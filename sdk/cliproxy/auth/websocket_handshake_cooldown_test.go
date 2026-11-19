package auth

import (
	"context"
	"testing"
	"time"
)

func TestWebsocketHandshakeCooldown(t *testing.T) {
	withQuotaCooldownEnabled(t)
	previous := transientErrorCooldownSeconds.Load()
	t.Cleanup(func() { transientErrorCooldownSeconds.Store(previous) })
	for _, model := range []string{"gpt-6.2-sol", ""} {
		for _, tc := range []struct {
			name   string
			config int64
			hint   time.Duration
			code   string
			want   time.Duration
		}{
			{name: "default", code: ErrorCodeWebsocketHandshakeRejected, want: time.Minute},
			{name: "configured", config: 5, code: ErrorCodeWebsocketHandshakeRejected, want: 5 * time.Second},
			{name: "retry hint", config: 5, hint: 2 * time.Minute, code: ErrorCodeWebsocketHandshakeRejected, want: 2 * time.Minute},
			{name: "disabled", config: -1, code: ErrorCodeWebsocketHandshakeRejected},
			{name: "ordinary forbidden", want: 30 * time.Minute},
		} {
			t.Run(model+"/"+tc.name, func(t *testing.T) {
				transientErrorCooldownSeconds.Store(tc.config)
				manager := NewManager(nil, nil, nil)
				a := &Auth{ID: "handshake-test", Provider: "codex", Status: StatusActive}
				if model != "" {
					a.ModelStates = map[string]*ModelState{model: {Status: StatusActive}, "gpt-6.1-sol": {Status: StatusActive}}
				}
				if _, errRegister := manager.Register(WithSkipPersist(context.Background()), a); errRegister != nil {
					t.Fatal(errRegister)
				}
				var hint *time.Duration
				if tc.hint > 0 {
					hint = &tc.hint
				}
				before := time.Now()
				manager.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: "codex", Model: model, RetryAfter: hint, Error: &Error{Code: tc.code, HTTPStatus: 403, Message: "upstream handshake refused"}})
				after := time.Now()
				got, ok := manager.GetByID(a.ID)
				if !ok {
					t.Fatal("missing auth")
				}
				deadline := got.NextRetryAfter
				if model != "" {
					state := got.ModelStates[model]
					if state == nil {
						t.Fatal("missing model")
					}
					deadline = state.NextRetryAfter
					if state.Quota.Exceeded || state.Quota.BackoffLevel != 0 {
						t.Fatalf("false quota: %+v", state.Quota)
					}
					sibling := got.ModelStates["gpt-6.1-sol"]
					if sibling.Unavailable || sibling.Quota.Exceeded {
						t.Fatalf("sibling affected: %+v", sibling)
					}
				}
				if got.Quota.Exceeded {
					t.Fatalf("false credential quota: %+v", got.Quota)
				}
				if tc.want == 0 {
					if !deadline.IsZero() {
						t.Fatalf("cooling disabled but deadline=%v", deadline)
					}
					return
				}
				if deadline.Before(before.Add(tc.want)) || deadline.After(after.Add(tc.want)) {
					t.Fatalf("deadline=%v want within [%v,%v]", deadline, before.Add(tc.want), after.Add(tc.want))
				}
				views := CooldownSnapshotForAuth(got, before)
				if len(views) != 1 {
					t.Fatalf("unexpected cooldown views: %+v", views)
				}
				reason := ErrorCodeWebsocketHandshakeRejected
				if tc.code == "" {
					reason = "payment_required"
				}
				if views[0].Reason != reason || views[0].HTTPStatus != 403 {
					t.Fatalf("incorrect view: %+v", views[0])
				}
			})
		}
	}
}

func TestWebsocketHandshakePreservesExistingQuotaAndForcedCooldown(t *testing.T) {
	withQuotaCooldownEnabled(t)
	previous := transientErrorCooldownSeconds.Load()
	transientErrorCooldownSeconds.Store(0)
	t.Cleanup(func() { transientErrorCooldownSeconds.Store(previous) })
	for _, model := range []string{"gpt-6.2-sol", ""} {
		for _, kind := range []string{"quota", "force"} {
			t.Run(model+"/"+kind, func(t *testing.T) {
				manager := NewManager(nil, nil, nil)
				a := &Auth{ID: "existing-cooldown", Provider: "codex", Status: StatusActive}
				if _, errRegister := manager.Register(WithSkipPersist(context.Background()), a); errRegister != nil {
					t.Fatal(errRegister)
				}
				prior := &Error{HTTPStatus: 429, Message: "quota exceeded"}
				if kind == "force" {
					prior = &Error{HTTPStatus: 503, Code: ErrorCodeForceCooldown, Message: "forced maintenance"}
				}
				hint := 10 * time.Minute
				manager.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: "codex", Model: model, RetryAfter: &hint, Error: prior})
				before, _ := manager.GetByID(a.ID)
				deadline := before.NextRetryAfter
				if model != "" {
					deadline = before.ModelStates[model].NextRetryAfter
				}
				if deadline.IsZero() {
					t.Fatal("fixture lacks existing deadline")
				}
				manager.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: "codex", Model: model, Error: &Error{Code: ErrorCodeWebsocketHandshakeRejected, HTTPStatus: 403, Message: "empty handshake refusal"}})
				after, _ := manager.GetByID(a.ID)
				next := after.NextRetryAfter
				quota := after.Quota
				if model != "" {
					next = after.ModelStates[model].NextRetryAfter
					quota = after.ModelStates[model].Quota
				}
				if next.Before(deadline) {
					t.Fatalf("existing cooldown shortened: %v -> %v", deadline, next)
				}
				if kind == "quota" && !quota.Exceeded {
					t.Fatal("existing quota cleared")
				}
			})
		}
	}
}
