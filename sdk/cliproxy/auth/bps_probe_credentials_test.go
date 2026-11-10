package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/MoeForge/moego/base64"
)

func TestBPSProbeAuthFreshBearerUsesNormalRoute(t *testing.T) {
	for _, scenario := range []struct {
		name, accountProxy, fallbackProxy, wantError string
	}{
		{"default_route", "", "", ""},
		{"whitespace_default", " ", "\t", ""},
		{"inherited_proxy", "", "socks5://fallback:7890", ""},
		{"account_proxy", "https://account:8443", "http://fallback:7890", ""},
		{"invalid_account_does_not_fallback", "direct://", "http://fallback:7890", "bps_probe_proxy_invalid"},
		{"invalid_fallback", "", "bad-proxy", "bps_probe_proxy_invalid"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			m := NewManager(nil, nil, nil)
			a, err := m.Register(context.Background(), &Auth{ID: "fresh-bps", Provider: "bps", ProxyURL: scenario.accountProxy,
				Metadata: map[string]any{"access_token": "fresh-at", "expired": time.Now().Add(time.Hour).Format(time.RFC3339)}})
			if err != nil {
				t.Fatal(err)
			}
			got, err := m.BPSProbeAuth(context.Background(), a.ID, a.RegistrationEpoch, scenario.fallbackProxy)
			if scenario.wantError != "" {
				if err == nil || err.Error() != scenario.wantError || got != nil {
					t.Fatalf("route validation: got error %v, want %s", err, scenario.wantError)
				}
				return
			}
			if err != nil || got == nil || got.Metadata["access_token"] != "fresh-at" {
				t.Fatalf("fresh credential preparation failed: %v", err)
			}
			if got.ProxyURL != a.ProxyURL {
				t.Fatal("credential preparation changed stored route")
			}
		})
	}
}

func TestBPSProbeAuthSharesRefreshLockAndPreservesQuota(t *testing.T) {
	m := NewManager(nil, nil, nil)
	exec := &nativeProbeRefreshExecutor{countingRefreshExecutor: countingRefreshExecutor{id: "bps"}, started: make(chan struct{}), release: make(chan struct{})}
	m.RegisterExecutor(exec)
	future := time.Now().Add(time.Hour)
	a, err := m.Register(context.Background(), &Auth{ID: "bps-probe", Provider: "bps", Status: StatusActive, Unavailable: true,
		Quota: QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: future}, NextRetryAfter: future,
		Metadata: map[string]any{"access_token": "old-at", "refresh_token": "old-rt", "expired": time.Now().Add(-time.Hour).Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := m.BPSProbeAuth(context.Background(), a.ID, a.RegistrationEpoch, "http://proxy:7890")
			if err != nil {
				t.Error(err)
				return
			}
			if got.Metadata["access_token"] != "native-probe-new-at" || got.Metadata["refresh_token"] != "native-probe-new-rt" || got.RejectedAccessToken != "" || !got.Quota.Exceeded || got.Quota.Reason != a.Quota.Reason || !got.Quota.NextRecoverAt.Equal(future) {
				t.Error("BPS refresh lost current credentials or quota state")
			}
		}()
	}
	<-exec.started
	close(exec.release)
	wg.Wait()
	if exec.calls.Load() != 1 {
		t.Fatalf("refreshes=%d, want 1", exec.calls.Load())
	}
}

func TestBPSProbeAuthFencesReplacement(t *testing.T) {
	m := NewManager(nil, nil, nil)
	exec := &nativeProbeRefreshExecutor{countingRefreshExecutor: countingRefreshExecutor{id: "bps"}, started: make(chan struct{}), release: make(chan struct{})}
	m.RegisterExecutor(exec)
	a, err := m.Register(context.Background(), &Auth{ID: "bps-probe", Provider: "bps", Metadata: map[string]any{"access_token": "old", "refresh_token": "old-rt", "expired": time.Now().Add(-time.Hour).Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := m.BPSProbeAuth(context.Background(), a.ID, a.RegistrationEpoch, "http://proxy:7890")
		done <- err
	}()
	<-exec.started
	_, err = m.Register(context.Background(), &Auth{ID: a.ID, Provider: "bps", Metadata: map[string]any{"access_token": "replacement", "refresh_token": "replacement-rt", "expired": time.Now().Add(time.Hour).Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	close(exec.release)
	if <-done == nil {
		t.Fatal("accepted replacement")
	}
	got, _ := m.GetByID(a.ID)
	if got.Metadata["access_token"] != "replacement" {
		t.Fatal("overwrote replacement")
	}
}

func TestBPSProbeAuthRejectsDisabledAndNative(t *testing.T) {
	for _, a := range []*Auth{
		{ID: "disabled", Provider: "bps", Disabled: true},
		{ID: "native", Provider: "codex"},
	} {
		m := NewManager(nil, nil, nil)
		a.Metadata = map[string]any{"access_token": "expired", "refresh_token": "must-not-refresh", "expired": time.Now().Add(-time.Hour).Format(time.RFC3339)}
		got, err := m.Register(context.Background(), a)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = m.BPSProbeAuth(context.Background(), a.ID, got.RegistrationEpoch, "http://proxy:7890"); err == nil {
			t.Fatal("accepted disabled or native credential")
		}
	}
}

func TestBPSProbeSchedulerIdentityIsSeparateAndHostDerived(t *testing.T) {
	token := "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"subject","https://api.openai.com/auth":{"chatgpt_account_id":"account"}}`)) + ".signature"
	a := &Auth{ID: "bps", Provider: "bps", Metadata: map[string]any{"access_token": token}, Attributes: map[string]string{"bps_probe_identity": "forged", "native_probe_identity": "forged", "refresh_token": "must-not-leak"}}
	candidate := schedulerAuthCandidates([]*Auth{a})[0]
	identity := candidate.Attributes["bps_probe_identity"]
	if len(identity) != 64 || identity == "forged" || candidate.Attributes["native_probe_identity"] != "" || candidate.Attributes["refresh_token"] != "" || len(candidate.Metadata) != 0 {
		t.Fatal("unsafe BPS scheduler projection")
	}
	a.Provider = "codex"
	candidate = schedulerAuthCandidates([]*Auth{a})[0]
	if candidate.Attributes["bps_probe_identity"] != "" || candidate.Attributes["native_probe_identity"] != identity {
		t.Fatal("mixed probe provider identities")
	}
	a.Provider = "other"
	candidate = schedulerAuthCandidates([]*Auth{a})[0]
	if candidate.Attributes["bps_probe_identity"] != "" || candidate.Attributes["native_probe_identity"] != "" {
		t.Fatal("accepted foreign forged identities")
	}
}
