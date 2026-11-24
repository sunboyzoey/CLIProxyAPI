package auth

import (
	"context"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type sentPoolError struct{ customStatusError }

func (sentPoolError) IsRequestStop() bool { return true }

type sentPoolExecutor struct {
	customStreamMockExecutor
	refreshes int
}

func (e *sentPoolExecutor) Refresh(_ context.Context, a *Auth) (*Auth, error) {
	e.refreshes++
	result := a.Clone()
	result.Metadata["access_token"] = "refreshed"
	return result, nil
}

func TestStreamModelPoolDoesNotReplaySentRequest(t *testing.T) {
	for _, bootstrap := range []bool{false, true} {
		for _, continueRule := range []bool{false, true} {
			name := "execute"
			if bootstrap {
				name = "bootstrap"
			}
			if continueRule {
				name += "/continue-rule"
			}
			t.Run(name, func(t *testing.T) {
				m := NewManager(nil, nil, nil)
				calls := 0
				sentErr := sentPoolError{customStatusError{code: 401, msg: "already sent"}}
				exec := &sentPoolExecutor{customStreamMockExecutor: customStreamMockExecutor{identifier: "codex", streamFn: func(context.Context, *Auth, core.Request, core.Options) (*core.StreamResult, error) {
					calls++
					if !bootstrap {
						return nil, sentErr
					}
					ch := make(chan core.StreamChunk, 1)
					ch <- core.StreamChunk{Err: sentErr}
					close(ch)
					return &core.StreamResult{Chunks: ch}, nil
				}}}
				m.RegisterExecutor(exec)
				a := &Auth{ID: t.Name(), Provider: "codex", Status: StatusActive, Metadata: map[string]any{"access_token": "original", "refresh_token": "synthetic"}}
				if continueRule {
					a.Metadata["request_scoped_errors"] = []internalconfig.RequestScopedErrorRule{{Status: 401, Match: []string{"already sent"}, Action: "continue"}}
				}
				registered, errRegister := m.Register(t.Context(), a)
				if errRegister != nil {
					t.Fatal(errRegister)
				}
				_, errStream := m.executeStreamWithModelPool(t.Context(), exec, registered, "codex", core.Request{Model: "alias"}, core.Options{}, "alias", "", []string{"model-a", "model-b"}, true, OAuthModelAliasResult{}, nil, true, false)
				if !IsRequestStopError(errStream) {
					t.Fatalf("stop marker lost: %v", errStream)
				}
				if calls != 1 || exec.refreshes != 0 {
					t.Fatalf("sent request replayed: calls=%d refreshes=%d", calls, exec.refreshes)
				}
			})
		}
	}
}
