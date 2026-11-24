package executor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// Canceled turns must leave a busy session without waiting for the active turn
// or changing its connection. A long-running turn must not retain canceled callers.
func TestCodexWebsocketConcurrentCanceledWaiters(t *testing.T) {
	for _, stream := range []bool{false, true} {
		name := "execute"
		if stream {
			name = "stream"
		}
		t.Run(name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				http.Error(w, "unexpected upstream call", http.StatusBadGateway)
			}))
			defer server.Close()
			exec := NewCodexWebsocketsExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}})
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			auth := &cliproxyauth.Auth{ID: "concurrent-auth", Provider: "codex", Attributes: map[string]string{"api_key": "test", "base_url": server.URL}}
			req := cliproxyexecutor.Request{Model: "gpt-5-codex", Payload: []byte(`{"model":"gpt-5-codex","input":"hello"}`)}
			opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response"), Metadata: map[string]any{cliproxyexecutor.ExecutionSessionMetadataKey: "busy-session"}}
			sess := exec.getOrCreateSession("busy-session")
			sess.reqMu.Lock()
			locked := true
			defer func() {
				if locked {
					sess.reqMu.Unlock()
				}
			}()
			const callers = 8
			done := make(chan error, callers)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			for i := 0; i < callers; i++ {
				go func() {
					// The auth manager dispatches a separate credential snapshot per request.
					requestAuth := auth.Clone()
					if stream {
						_, err := exec.ExecuteStream(ctx, requestAuth, req, opts)
						done <- err
					} else {
						_, err := exec.Execute(ctx, requestAuth, req, opts)
						done <- err
					}
				}()
			}
			timer := time.NewTimer(time.Second)
			defer timer.Stop()
			for i := 0; i < callers; i++ {
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Errorf("waiter error = %v, want cancellation", err)
					}
				case <-timer.C:
					sess.reqMu.Unlock()
					locked = false
					for j := i; j < callers; j++ {
						<-done
					}
					t.Fatal("canceled requests remained blocked behind the active session")
				}
			}
			sess.connMu.Lock()
			changed := sess.turnContext != nil || sess.conn != nil
			sess.connMu.Unlock()
			if changed {
				t.Error("canceled waiter changed the active session")
			}
			if got := upstreamCalls.Load(); got != 0 {
				t.Errorf("upstream calls = %d, want 0", got)
			}
		})
	}
}
