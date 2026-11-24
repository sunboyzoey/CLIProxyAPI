package helps

import (
	"context"
	"sync"
)

// ContextMutex serializes session turns while allowing canceled waiters to leave.
// Its zero value is ready to use. It must not be copied after first use.
type ContextMutex struct {
	once sync.Once
	held chan struct{}
}

// LockContext acquires the lock or returns the caller's cancellation error.
// A failed acquisition does not need Unlock.
func (m *ContextMutex) LockContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.once.Do(func() { m.held = make(chan struct{}, 1) })
	select {
	case m.held <- struct{}{}:
		// Cancellation and acquisition may become ready together.
		if err := ctx.Err(); err != nil {
			m.Unlock()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Lock acquires the lock without cancellation.
func (m *ContextMutex) Lock() {
	_ = m.LockContext(context.Background())
}

// Unlock releases a successfully acquired lock.
func (m *ContextMutex) Unlock() {
	<-m.held
}
