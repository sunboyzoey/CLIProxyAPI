package helps

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
)

type poolTestResource struct{ dead atomic.Bool }

func testHTTPPool(t *testing.T, cap int) *HTTPWebsocketPool[*poolTestResource] {
	t.Helper()
	p := NewHTTPWebsocketPool(cap, func(r *poolTestResource) bool { return !r.dead.Load() }, func(r *poolTestResource, _ string) { r.dead.Store(true) })
	t.Cleanup(func() { p.CloseAccount("", "test_end") })
	return p
}
func testAcquire(t *testing.T, p *HTTPWebsocketPool[*poolTestResource], account, key string, max int) *HTTPWebsocketLease[*poolTestResource] {
	t.Helper()
	l, err := p.Acquire(t.Context(), account, key, max, func() *poolTestResource { return &poolTestResource{} })
	if err != nil {
		t.Fatal(err)
	}
	return l
}
func TestHTTPWebsocketPoolReuseAndIsolation(t *testing.T) {
	p := testHTTPPool(t, 3)
	a := testAcquire(t, p, "a", "key", 2)
	b := testAcquire(t, p, "a", "key", 2)
	if a.Resource() == b.Resource() {
		t.Fatal("concurrent callers shared a socket")
	}
	a.Release(true)
	again := testAcquire(t, p, "a", "key", 2)
	if again.Resource() != a.Resource() {
		t.Fatal("idle socket not reused")
	}
	again.Release(true)
	again.Release(false)
	if a.Resource().dead.Load() {
		t.Fatal("double release closed a live socket")
	}
	other := testAcquire(t, p, "b", "key", 2)
	if other.Resource() == a.Resource() {
		t.Fatal("accounts mixed")
	}
	b.Release(false)
	other.Release(true)
	replacement := testAcquire(t, p, "a", "new-token", 1)
	if replacement.Resource() == a.Resource() || !a.Resource().dead.Load() {
		t.Fatal("incompatible idle socket was not replaced at account capacity")
	}
	replacement.Release(true)
}
func TestHTTPWebsocketPoolCancellationAndRemoval(t *testing.T) {
	p := testHTTPPool(t, 1)
	active := testAcquire(t, p, "a", "key", 1)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.Acquire(ctx, "a", "key", 1, func() *poolTestResource { t.Fatal("cancelled caller allocated"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// CloseAccount also retires resources whose dial has not completed.
	p.CloseAccount("a", "removed")
	if !active.Resource().dead.Load() {
		t.Fatal("active resource not retired")
	}
	active.Release(true)
	next := testAcquire(t, p, "a", "key", 1)
	if next.Resource() == active.Resource() {
		t.Fatal("retired socket resurrected")
	}
	next.Release(true)
}
func TestHTTPWebsocketCompatibility(t *testing.T) {
	headers := http.Header{"Authorization": {"Bearer secret"}, "Session_id": {"generated-1"}, "Openai-Beta": {"responses=v2"}}
	key := HTTPWebsocketCompatibility("wss://example", "proxy", headers, "generated-1", true)
	next := headers.Clone()
	next.Set("Session_id", "generated-2")
	if key != HTTPWebsocketCompatibility("wss://example", "proxy", next, "generated-2", true) {
		t.Fatal("generated session prevents reuse")
	}
	for _, header := range []string{"Authorization", "Openai-Beta", "Session_id", "X-Codex-Turn-State", "X-Codex-Routing-Hint", "X-Client-Request-Id", "Chatgpt-Account-Id"} {
		next := headers.Clone()
		next.Set(header, "different")
		if key == HTTPWebsocketCompatibility("wss://example", "proxy", next, "generated-1", true) {
			t.Fatalf("%s did not isolate", header)
		}
	}
	if key == HTTPWebsocketCompatibility("wss://example", "proxy", headers, "generated-1", true, "other-caller") {
		t.Fatal("caller not isolated")
	}
	if key == HTTPWebsocketCompatibility("wss://example", "other-proxy", headers, "generated-1", true) {
		t.Fatal("proxy not isolated")
	}
	if key == HTTPWebsocketCompatibility("wss://other", "proxy", headers, "generated-1", true) {
		t.Fatal("endpoint not isolated")
	}
	if key == HTTPWebsocketCompatibility("wss://example", "proxy", headers, "generated-1", false) {
		t.Fatal("compression not isolated")
	}
}

// Done is evaluated only when Acquire reaches its capacity wait select.
type observedPoolWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *observedPoolWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestHTTPWebsocketPoolWaitReleaseAndRevocation(t *testing.T) {
	for _, action := range []string{"release", "cancel", "remove", "shutdown"} {
		t.Run(action, func(t *testing.T) {
			p := testHTTPPool(t, 1)
			active := testAcquire(t, p, "a", "key", 1)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			waiting := &observedPoolWaitContext{Context: ctx, waiting: make(chan struct{})}
			result := make(chan *HTTPWebsocketLease[*poolTestResource], 1)
			errs := make(chan error, 1)
			go func() {
				l, err := p.Acquire(waiting, "a", "key", 1, func() *poolTestResource { return &poolTestResource{} })
				result <- l
				errs <- err
			}()
			<-waiting.waiting
			switch action {
			case "release":
				active.Release(true)
			case "cancel":
				cancel()
			case "remove":
				p.CloseAccount("a", "removed")
			case "shutdown":
				p.CloseAccount("", "shutdown")
			}
			lease, err := <-result, <-errs
			if action == "release" {
				if err != nil || lease.Resource() != active.Resource() {
					t.Fatalf("waiter did not reuse released socket: %v", err)
				}
				lease.Release(true)
			} else if !errors.Is(err, context.Canceled) {
				t.Fatalf("revoked waiter acquired: %v", err)
			}
		})
	}
}

func TestHTTPWebsocketPoolLoweredCapacity(t *testing.T) {
	p := testHTTPPool(t, 4)
	first := testAcquire(t, p, "a", "old-1", 3)
	second := testAcquire(t, p, "a", "old-2", 3)
	third := testAcquire(t, p, "a", "old-3", 3)
	first.Release(true)
	second.Release(true)
	third.Release(true)
	next := testAcquire(t, p, "a", "new", 1)
	for _, retired := range []*poolTestResource{first.Resource(), second.Resource(), third.Resource()} {
		if !retired.dead.Load() {
			t.Fatal("lowered capacity left incompatible idle connections")
		}
	}
	next.Release(true)
}
