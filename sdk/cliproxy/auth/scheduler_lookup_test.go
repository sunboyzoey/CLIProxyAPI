package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type lookupTestScheduler struct {
	fakePluginScheduler
	lookup bool
}

func TestSchedulerLookupRevalidatesSelectedAccountAfterCallback(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		for _, mode := range []string{"unchanged", "cooldown", "epoch", "provider", "disabled", "kind", "model", "tried"} {
			t.Run(mode+map[bool]string{true: "_mixed", false: "_single"}[mixed], func(t *testing.T) {
				m := NewManager(nil, &FillFirstSelector{}, nil)
				m.RegisterExecutor(schedulerTestExecutor{provider: "gemini"})
				id, model := "lookup-revalidate", "lookup-revalidate-model"
				reg := registry.GetGlobalRegistry()
				reg.RegisterClient(id, "gemini", []*registry.ModelInfo{{ID: model}})
				t.Cleanup(func() { reg.UnregisterClient(id) })
				if _, err := m.Register(context.Background(), &Auth{ID: id, Provider: "gemini", Attributes: map[string]string{"auth_kind": "oauth"}}); err != nil {
					t.Fatal(err)
				}
				tried := map[string]struct{}{}
				scheduler := &lookupTestScheduler{lookup: true}
				scheduler.pick = func(_ context.Context, req pluginapi.SchedulerPickRequest) (pluginapi.SchedulerPickResponse, bool, error) {
					if len(req.Candidates) != 1 || req.Candidates[0].ID != id {
						t.Fatal("wrong initial candidate")
					}
					m.mu.Lock()
					a := m.auths[id]
					switch mode {
					case "cooldown":
						a.Unavailable, a.NextRetryAfter = true, time.Now().Add(17*time.Second)
					case "epoch":
						a.RegistrationEpoch++
					case "provider":
						a.Provider = "codex"
					case "disabled":
						a.Disabled = true
					case "kind":
						a.Attributes["auth_kind"] = "apikey"
					case "tried":
						tried[id] = struct{}{}
					}
					m.mu.Unlock()
					if mode == "model" {
						reg.UnregisterClient(id)
					}
					return pluginapi.SchedulerPickResponse{Handled: true, AuthID: id}, true, nil
				}
				m.SetPluginScheduler(scheduler)
				opts := cliproxyexecutor.Options{Metadata: map[string]any{}}
				got, err := lookupTestPick(m, mixed, withRequiredAuthKind(context.Background(), "oauth"), model, opts, tried)
				if mode == "unchanged" {
					if err != nil || got == nil || got.ID != id || opts.Metadata[cliproxyexecutor.SelectionIDMetadataKey] == nil {
						t.Fatalf("unchanged selection failed: %v %v", got, err)
					}
					return
				}
				if got != nil || err == nil || !isRequestStopError(err) {
					t.Fatalf("changed selection dispatched: %v %v", got, err)
				}
				if _, present := opts.Metadata[cliproxyexecutor.SelectionIDMetadataKey]; present {
					t.Fatal("failed selection retained execution selection ID")
				}
				var status interface{ StatusCode() int }
				if !errors.As(err, &status) {
					t.Fatal("lost public status")
				}
				if mode == "cooldown" {
					var headers interface{ Headers() http.Header }
					if status.StatusCode() != 503 || !errors.As(err, &headers) || headers.Headers().Get("Retry-After") != "17" {
						t.Fatalf("lost cooldown status/hint: %v", err)
					}
				} else {
					var scoped interface{ IsRequestScoped() bool }
					if status.StatusCode() != 409 || !errors.As(err, &scoped) || !scoped.IsRequestScoped() {
						t.Fatalf("state replacement not request-scoped409: %v", err)
					}
				}
				if scheduler.calls != 1 {
					t.Fatal("selection automatically retried")
				}
			})
		}
	}
}

func (s *lookupTestScheduler) SchedulerWantsLookupCandidates() bool { return s.lookup }

func TestSchedulerLookupPreservesExcludedCandidateFallback(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		for _, delegate := range []string{"", pluginapi.SchedulerBuiltinFillFirst} {
			name := map[bool]string{false: "single", true: "mixed"}[mixed] + "/" + delegate
			t.Run(name, func(t *testing.T) {
				m := NewManager(nil, &FillFirstSelector{}, nil)
				m.RegisterExecutor(schedulerTestExecutor{provider: "gemini"})
				for _, candidate := range []*Auth{
					{ID: "lookup-excluded", Provider: "gemini", Attributes: map[string]string{"priority": "100"}},
					{ID: "lookup-fallback", Provider: "gemini", Attributes: map[string]string{"priority": "50"}},
				} {
					if _, errRegister := m.Register(t.Context(), candidate); errRegister != nil {
						t.Fatal(errRegister)
					}
				}
				scheduler := &lookupTestScheduler{lookup: true}
				scheduler.acrossPriorities = true
				scheduler.pick = func(_ context.Context, req pluginapi.SchedulerPickRequest) (pluginapi.SchedulerPickResponse, bool, error) {
					if !req.LookupCandidatesProvided || len(req.LookupCandidates) != 2 {
						t.Fatalf("lookup candidates were lost: %+v", req.LookupCandidates)
					}
					return pluginapi.SchedulerPickResponse{
						Handled: delegate != "", DelegateBuiltin: delegate,
						ExcludeCandidates: []string{"lookup-excluded"},
					}, delegate != "", nil
				}
				m.SetPluginScheduler(scheduler)
				tried := map[string]struct{}{"unrelated": {}}
				got, errPick := lookupTestPick(m, mixed, t.Context(), "", cliproxyexecutor.Options{}, tried)
				if errPick != nil || got == nil || got.ID != "lookup-fallback" {
					t.Fatalf("excluded candidate fallback = %v, %v", got, errPick)
				}
				if len(tried) != 1 || scheduler.calls != 1 {
					t.Fatalf("unexpected mutation or callback replay: tried=%v calls=%d", tried, scheduler.calls)
				}
			})
		}
	}
}

func lookupTestPick(m *Manager, mixed bool, ctx context.Context, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, error) {
	if mixed {
		a, _, _, err := m.pickNextMixed(ctx, []string{"gemini"}, model, opts, tried)
		return a, err
	}
	a, _, err := m.pickNext(ctx, "gemini", model, opts, tried)
	return a, err
}

func TestSchedulerLookupCandidatesPreserveRequestScope(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		for _, pinned := range []bool{false, true} {
			name := "single"
			if mixed {
				name = "mixed"
			}
			if pinned {
				name += "_pinned"
			}
			t.Run(name, func(t *testing.T) {
				m := NewManager(nil, &FillFirstSelector{}, nil)
				m.RegisterExecutor(schedulerTestExecutor{provider: "gemini"})
				next := time.Now().Add(60 * time.Second)
				reg := registry.GetGlobalRegistry()
				for _, id := range []string{"lookup-active", "lookup-cooling", "lookup-disabled", "lookup-provider", "lookup-model", "lookup-tried", "lookup-kind"} {
					a := &Auth{ID: id, Provider: "gemini", Attributes: map[string]string{"auth_kind": "oauth"}, Status: StatusActive}
					switch id {
					case "lookup-cooling":
						a.ModelStates = map[string]*ModelState{"lookup-model": {Unavailable: true, NextRetryAfter: next}}
					case "lookup-disabled":
						a.Disabled = true
					case "lookup-provider":
						a.Provider = "codex"
					case "lookup-kind":
						a.Attributes["auth_kind"] = "apikey"
					}
					if _, err := m.Register(context.Background(), a); err != nil {
						t.Fatal(err)
					}
					model := "lookup-model"
					if id == "lookup-model" {
						model = "other-model"
					}
					reg.RegisterClient(id, a.Provider, []*registry.ModelInfo{{ID: model}})
					t.Cleanup(func() { reg.UnregisterClient(id) })
				}
				stop := errors.New("lookup diagnosis stops before generation")
				scheduler := &lookupTestScheduler{lookup: true}
				scheduler.pick = func(_ context.Context, r pluginapi.SchedulerPickRequest) (pluginapi.SchedulerPickResponse, bool, error) {
					if !r.LookupCandidatesProvided {
						t.Fatal("lookup scope missing")
					}
					want := 2
					if pinned {
						want = 1
					}
					if len(r.LookupCandidates) != want {
						t.Fatalf("expanded lookup scope: %+v", r.LookupCandidates)
					}
					for _, c := range r.LookupCandidates {
						if c.ID == "lookup-cooling" {
							if c.UnavailableReason != "cooldown" || c.RetryAfterSeconds < 59 || c.RetryAfterSeconds > 60 {
								t.Fatalf("lost recovery deadline: %+v", c)
							}
						} else if c.ID != "lookup-active" || pinned {
							t.Fatalf("unauthorized lookup candidate: %s", c.ID)
						}
					}
					want--
					if len(r.Candidates) != want || (!pinned && r.Candidates[0].ID != "lookup-active") {
						t.Fatalf("availability bypass: %+v", r.Candidates)
					}
					return pluginapi.SchedulerPickResponse{}, true, stop
				}
				m.SetPluginScheduler(scheduler)
				opts := cliproxyexecutor.Options{Metadata: map[string]any{}}
				if pinned {
					opts.Metadata[cliproxyexecutor.PinnedAuthMetadataKey] = "lookup-cooling"
				}
				_, err := lookupTestPick(m, mixed, withRequiredAuthKind(context.Background(), "oauth"), "lookup-model", opts, map[string]struct{}{"lookup-tried": {}})
				if err != stop || scheduler.calls != 1 {
					t.Fatalf("lookup callback unavailable: %v calls=%d", err, scheduler.calls)
				}
			})
		}
	}
}

func TestSchedulerLookupAllUnavailableCannotSelectOrChangeFallback(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		for _, mode := range []string{"disabled", "unhandled", "select_lookup_only", "delegate"} {
			t.Run(mode+map[bool]string{true: "_mixed", false: "_single"}[mixed], func(t *testing.T) {
				m := NewManager(nil, &FillFirstSelector{}, nil)
				m.RegisterExecutor(schedulerTestExecutor{provider: "gemini"})
				a := &Auth{ID: "lookup-only", Provider: "gemini", Unavailable: true, NextRetryAfter: time.Now().Add(time.Minute)}
				if _, err := m.Register(context.Background(), a); err != nil {
					t.Fatal(err)
				}
				_, before := lookupTestPick(m, mixed, context.Background(), "", cliproxyexecutor.Options{}, nil)
				scheduler := &lookupTestScheduler{lookup: mode != "disabled"}
				scheduler.handled = mode != "unhandled"
				if mode == "select_lookup_only" {
					scheduler.resp = pluginapi.SchedulerPickResponse{Handled: true, AuthID: a.ID}
				}
				if mode == "delegate" {
					scheduler.resp = pluginapi.SchedulerPickResponse{Handled: true, DelegateBuiltin: pluginapi.SchedulerBuiltinRoundRobin}
				}
				m.SetPluginScheduler(scheduler)
				got, after := lookupTestPick(m, mixed, context.Background(), "", cliproxyexecutor.Options{}, nil)
				if got != nil || before == nil || after == nil || before.Error() != after.Error() {
					t.Fatalf("lookup changed unavailable fallback: %v, before=%v after=%v", got, before, after)
				}
				wantCalls := 1
				if mode == "disabled" {
					wantCalls = 0
				}
				if scheduler.calls != wantCalls {
					t.Fatalf("calls=%d want=%d", scheduler.calls, wantCalls)
				}
			})
		}
	}
}

func TestSchedulerLookupAvailabilityUsesEffectiveBlock(t *testing.T) {
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	m := NewManager(nil, nil, nil)
	auths := []*Auth{
		{ID: "quota", Quota: QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: now.Add(2500 * time.Millisecond)}},
		{ID: "blocked", Unavailable: true},
		{ID: "disabled_model", ModelStates: map[string]*ModelState{"model": {Status: StatusDisabled}}},
		{ID: "model", ModelStates: map[string]*ModelState{"model": {Unavailable: true, NextRetryAfter: now.Add(4100 * time.Millisecond)}}},
	}
	got := m.schedulerLookupCandidates(auths, "model", now)
	for i, want := range []int64{3, 0, 0, 5} {
		if got[i].RetryAfterSeconds != want {
			t.Fatalf("wrong deadline %+v", got[i])
		}
		if (want > 0 && got[i].UnavailableReason != "cooldown") || (want == 0 && got[i].UnavailableReason != "blocked") {
			t.Fatalf("wrong reason %+v", got[i])
		}
	}
}
