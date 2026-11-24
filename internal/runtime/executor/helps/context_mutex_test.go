package helps

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mutexWaitContext struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func (c *mutexWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestContextMutexCancellationWhileWaiting(t *testing.T) {
	var mutex ContextMutex
	mutex.Lock()
	defer mutex.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	observed := &mutexWaitContext{Context: ctx, waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- mutex.LockContext(observed) }()
	<-observed.waiting
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lock error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled waiter did not leave")
	}
}

func TestContextMutexConcurrentTurns(t *testing.T) {
	var mutex ContextMutex
	var active atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Go(func() {
			for j := 0; j < 32; j++ {
				if err := mutex.LockContext(t.Context()); err != nil {
					t.Error(err)
					return
				}
				if active.Add(1) != 1 {
					t.Error("concurrent owners")
				}
				active.Add(-1)
				mutex.Unlock()
			}
		})
	}
	wg.Wait()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := mutex.LockContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lock = %v", err)
	}
	// A failed acquisition must not consume the next turn's slot.
	if err := mutex.LockContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	mutex.Unlock()
}
