package helps

import (
	"context"
	"sync"
)

// HTTPWebsocketPool owns bounded, exclusive leases. Construction only allocates
// local state; dialing happens outside the lock. Keys never contain raw secrets.
type HTTPWebsocketPool[T comparable] struct {
	mu           sync.Mutex
	epoch        uint64
	accountEpoch map[string]uint64
	entries      map[T]*httpWebsocketPoolEntry[T]
	changed      chan struct{}
	sequence     uint64
	maxTotal     int
	healthy      func(T) bool
	close        func(T, string)
}

type httpWebsocketPoolEntry[T comparable] struct {
	resource     T
	account, key string
	busy         bool
	used         uint64
}

type HTTPWebsocketLease[T comparable] struct {
	pool  *HTTPWebsocketPool[T]
	entry *httpWebsocketPoolEntry[T]
	once  sync.Once
}

func NewHTTPWebsocketPool[T comparable](maxTotal int, healthy func(T) bool, closeResource func(T, string)) *HTTPWebsocketPool[T] {
	if maxTotal < 1 {
		maxTotal = 256
	}
	return &HTTPWebsocketPool[T]{entries: make(map[T]*httpWebsocketPoolEntry[T]), accountEpoch: make(map[string]uint64), changed: make(chan struct{}), maxTotal: maxTotal, healthy: healthy, close: closeResource}
}

func (p *HTTPWebsocketPool[T]) signalLocked() { close(p.changed); p.changed = make(chan struct{}) }

// Acquire waits on the caller's context when all account/global slots are busy.
// It never steals an active connection or times out a running response.
func (p *HTTPWebsocketPool[T]) Acquire(ctx context.Context, account, key string, maxPerAccount int, create func() T) (*HTTPWebsocketLease[T], error) {
	if maxPerAccount < 1 {
		maxPerAccount = 8
	}
	p.mu.Lock()
	epoch, accountEpoch := p.epoch, p.accountEpoch[account]
	p.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.epoch != epoch || p.accountEpoch[account] != accountEpoch {
			p.mu.Unlock()
			return nil, context.Canceled
		}
		var stale []T
		var match, oldestAccount, oldestGlobal *httpWebsocketPoolEntry[T]
		count := 0
		for resource, entry := range p.entries {
			if !entry.busy && !p.healthy(resource) {
				delete(p.entries, resource)
				stale = append(stale, resource)
				continue
			}
			if entry.account == account {
				count++
			}
			if entry.busy {
				continue
			}
			if entry.account == account && entry.key == key && (match == nil || entry.used > match.used) {
				match = entry
			}
			if oldestGlobal == nil || entry.used < oldestGlobal.used {
				oldestGlobal = entry
			}
			if entry.account == account && (oldestAccount == nil || entry.used < oldestAccount.used) {
				oldestAccount = entry
			}
		}
		if len(stale) > 0 {
			p.signalLocked()
		}
		if match != nil {
			match.busy = true
			p.mu.Unlock()
			for _, resource := range stale {
				p.close(resource, "pool_unhealthy")
			}
			return &HTTPWebsocketLease[T]{pool: p, entry: match}, nil
		}
		evicted := false
		victim := oldestGlobal
		if count >= maxPerAccount {
			victim = oldestAccount
		}
		if (count >= maxPerAccount || len(p.entries) >= p.maxTotal) && victim != nil {
			evicted = true
			delete(p.entries, victim.resource)
			stale = append(stale, victim.resource)
			if victim.account == account {
				count--
			}
			p.signalLocked()
		}
		if count < maxPerAccount && len(p.entries) < p.maxTotal {
			resource := create()
			entry := &httpWebsocketPoolEntry[T]{resource: resource, account: account, key: key, busy: true}
			p.entries[resource] = entry
			p.mu.Unlock()
			for _, old := range stale {
				p.close(old, "pool_evicted")
			}
			return &HTTPWebsocketLease[T]{pool: p, entry: entry}, nil
		}
		changed := p.changed
		p.mu.Unlock()
		for _, resource := range stale {
			p.close(resource, "pool_unhealthy")
		}
		if evicted {
			// A hot reload may lower the cap by more than one idle socket.
			continue
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

func (l *HTTPWebsocketLease[T]) Resource() T { return l.entry.resource }

// Release returns only a fully consumed healthy response to the idle pool.
// Releasing twice or after removal cannot resurrect a retired socket.
func (l *HTTPWebsocketLease[T]) Release(reusable bool) {
	l.once.Do(func() {
		p := l.pool
		p.mu.Lock()
		entry, found := p.entries[l.entry.resource]
		keep := found && entry == l.entry && reusable && p.healthy(entry.resource)
		if keep {
			p.sequence++
			entry.used = p.sequence
			entry.busy = false
		} else if found && entry == l.entry {
			delete(p.entries, entry.resource)
		}
		p.signalLocked()
		p.mu.Unlock()
		if !keep {
			p.close(l.entry.resource, "pool_discarded")
		}
	})
}

// Forget releases capacity immediately after a reader observes disconnection.
func (p *HTTPWebsocketPool[T]) Forget(resource T) {
	p.mu.Lock()
	if _, ok := p.entries[resource]; ok {
		delete(p.entries, resource)
		p.signalLocked()
	}
	p.mu.Unlock()
}

// CloseAccount retires active resources, including pending dial state.
// An empty account closes all resources for executor shutdown.
func (p *HTTPWebsocketPool[T]) CloseAccount(account, reason string) {
	p.mu.Lock()
	if account == "" {
		p.epoch++
	} else {
		p.accountEpoch[account]++
	}
	var removed []T
	for resource, entry := range p.entries {
		if account == "" || entry.account == account {
			delete(p.entries, resource)
			removed = append(removed, resource)
		}
	}
	p.signalLocked()
	p.mu.Unlock()
	for _, resource := range removed {
		p.close(resource, reason)
	}
}
