package auth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/base64"
)

type nativeProbeRefreshExecutor struct {
	countingRefreshExecutor
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
	err     error
}

func (e *nativeProbeRefreshExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	if e.calls.Add(1) == 1 && e.started != nil {
		close(e.started)
	}
	if e.release != nil {
		select {
		case <-e.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if e.err != nil {
		return nil, e.err
	}
	auth.Metadata["access_token"] = "native-probe-new-at"
	auth.Metadata["refresh_token"] = "native-probe-new-rt"
	auth.Metadata["expired"] = time.Now().Add(time.Hour).Format(time.RFC3339)
	return auth, nil
}

func TestNativeProbeAuthConcurrentRefreshPreservesDisabledAndQuota(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "enabled", true: "disabled"}[disabled], func(t *testing.T) {
			m := NewManager(nil, nil, nil)
			exec := &nativeProbeRefreshExecutor{countingRefreshExecutor: countingRefreshExecutor{id: "codex"}, started: make(chan struct{}), release: make(chan struct{})}
			m.RegisterExecutor(exec)
			future := time.Now().Add(time.Hour)
			a := &Auth{ID: "probe", Provider: "codex", Status: StatusActive, Disabled: disabled, Unavailable: true,
				Quota: QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: future}, NextRetryAfter: future,
				Metadata: map[string]any{"access_token": "old-at", "refresh_token": "old-rt", "expired": time.Now().Add(-time.Hour).Format(time.RFC3339)}}
			if disabled {
				a.Status = StatusDisabled
			}
			registered, err := m.Register(context.Background(), a)
			if err != nil {
				t.Fatal(err)
			}
			if !disabled && !registered.Quota.Exceeded {
				t.Fatal("test requires an active credential quota cooldown")
			}
			var wg sync.WaitGroup
			for range 12 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					got, err := m.NativeProbeAuth(context.Background(), a.ID, registered.RegistrationEpoch)
					if err != nil {
						t.Error(err)
						return
					}
					if got.Disabled != disabled || got.Quota.Exceeded != registered.Quota.Exceeded || got.Quota.Reason != registered.Quota.Reason || !got.Quota.NextRecoverAt.Equal(registered.Quota.NextRecoverAt) {
						t.Errorf("probe refresh changed scheduling state: disabled=%t quota=%t reason=%s deadline=%v", got.Disabled, got.Quota.Exceeded, got.Quota.Reason, got.Quota.NextRecoverAt)
					}
					if got.Metadata["access_token"] != "native-probe-new-at" {
						t.Error("stale access token")
					}
				}()
			}
			<-exec.started
			close(exec.release)
			wg.Wait()
			if exec.calls.Load() != 1 {
				t.Fatalf("refreshes=%d, want 1", exec.calls.Load())
			}
		})
	}
}

func TestNativeProbeSchedulerIdentityIsHostDerived(t *testing.T) {
	token := func(subject, account, suffix string) string {
		payload := `{"sub":"` + subject + `","https://api.openai.com/auth":{"chatgpt_account_id":"` + account + `"}}`
		return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + suffix
	}
	auth := &Auth{ID: "one", Provider: "codex", Metadata: map[string]any{"access_token": token("subject", "account", "one")}, Attributes: map[string]string{"native_probe_identity": "forged", "access_token": "must-not-leak"}}
	first := schedulerAuthCandidates([]*Auth{auth})[0]
	identity := first.Attributes["native_probe_identity"]
	if len(identity) != 64 || identity == "forged" || first.Attributes["access_token"] != "" || len(first.Metadata) != 0 {
		t.Fatal("unsafe scheduler projection")
	}
	auth.Metadata["access_token"] = token("subject", "account", "rotated")
	if schedulerAuthCandidates([]*Auth{auth})[0].Attributes["native_probe_identity"] != identity {
		t.Fatal("identity changed after token renewal")
	}
	auth.Metadata["access_token"] = token("subject", "other-account", "new")
	if schedulerAuthCandidates([]*Auth{auth})[0].Attributes["native_probe_identity"] == identity {
		t.Fatal("identity survived account replacement")
	}
	auth.Metadata["access_token"] = "opaque"
	if schedulerAuthCandidates([]*Auth{auth})[0].Attributes["native_probe_identity"] != "" {
		t.Fatal("accepted forged identity for opaque token")
	}
	auth.Provider = "bps"
	auth.Metadata["access_token"] = token("subject", "account", "one")
	if schedulerAuthCandidates([]*Auth{auth})[0].Attributes["native_probe_identity"] != "" {
		t.Fatal("exposed native identity for another provider")
	}
}

func TestNativeProbeAuthFencesReplacement(t *testing.T) {
	m := NewManager(nil, nil, nil)
	exec := &nativeProbeRefreshExecutor{countingRefreshExecutor: countingRefreshExecutor{id: "codex"}, started: make(chan struct{}), release: make(chan struct{})}
	m.RegisterExecutor(exec)
	a, err := m.Register(context.Background(), &Auth{ID: "probe", Provider: "codex", Metadata: map[string]any{"access_token": "old", "refresh_token": "old-rt", "expired": time.Now().Add(-time.Hour).Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := m.NativeProbeAuth(context.Background(), a.ID, a.RegistrationEpoch); done <- err }()
	<-exec.started
	_, err = m.Register(context.Background(), &Auth{ID: "probe", Provider: "codex", Metadata: map[string]any{"access_token": "replacement", "refresh_token": "replacement-rt", "expired": time.Now().Add(time.Hour).Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	close(exec.release)
	if <-done == nil {
		t.Fatal("accepted replaced credential")
	}
	got, _ := m.GetByID(a.ID)
	if got.Metadata["access_token"] != "replacement" {
		t.Fatal("refresh overwrote replacement")
	}
}

func TestNativeProbeAuthRedactsRefreshFailureAndKeepsValidTokenUnrejected(t *testing.T) {
	m := NewManager(nil, nil, nil)
	exec := &nativeProbeRefreshExecutor{countingRefreshExecutor: countingRefreshExecutor{id: "codex"}, err: errors.New("secret-refresh-token")}
	m.RegisterExecutor(exec)
	a, err := m.Register(context.Background(), &Auth{ID: "probe", Provider: "codex", Metadata: map[string]any{"access_token": "still-valid", "refresh_token": "secret-refresh-token", "expired": time.Now().Add(20 * time.Second).Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.NativeProbeAuth(context.Background(), a.ID, a.RegistrationEpoch)
	if err == nil || err.Error() != "native_probe_refresh_failed" {
		t.Fatal("refresh error was not sanitized")
	}
	got, _ := m.GetByID(a.ID)
	if got.RejectedAccessToken != "" {
		t.Fatal("proactive refresh marked access token rejected")
	}
}
