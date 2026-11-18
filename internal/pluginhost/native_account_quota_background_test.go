package pluginhost

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func backgroundQuotaRequest(a *coreauth.Auth) []byte {
	_, _, identity := nativeQuotaIdentity(a)
	doc := ojson.NewDocString("{}")
	_ = doc.Set("expected_auth_id", a.ID)
	_ = doc.Set("expected_identity", identity)
	return doc.Bytes()
}

func TestBackgroundNativeQuotaIdentityAndDisabledFences(t *testing.T) {
	for _, scenario := range []string{"success", "disabled", "replaced_before", "replaced_during", "disabled_during", "api_key", "deleted"} {
		t.Run(scenario, func(t *testing.T) {
			h, m, a, _ := nativeQuotaFixture(t)
			a.Disabled = false
			a.Status = coreauth.StatusActive
			var err error
			a, err = m.Register(context.Background(), a)
			if err != nil {
				t.Fatal(err)
			}
			request := backgroundQuotaRequest(a)
			replace := func(disabled bool) {
				replacement := a.Clone()
				if disabled {
					replacement.Disabled = true
				} else {
					replacement.Metadata["access_token"] = nativeQuotaToken("different-subject", "account", "replacement")
				}
				if _, errRegister := m.Register(context.Background(), replacement); errRegister != nil {
					t.Fatal(errRegister)
				}
			}
			switch scenario {
			case "disabled":
				replace(true)
			case "replaced_before":
				replace(false)
			case "api_key":
				a.Attributes = map[string]string{coreauth.AttributeAuthKind: coreauth.AuthKindAPIKey}
				if _, errRegister := m.Register(context.Background(), a); errRegister != nil {
					t.Fatal(errRegister)
				}
			case "deleted":
				doc := ojson.NewDoc(request)
				_ = doc.Set("expected_auth_id", "missing.json")
				request = doc.Bytes()
			}
			calls := 0
			ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", nativeQuotaTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("Authorization") != "Bearer "+a.Metadata["access_token"].(string) {
					t.Fatal("unexpected credential")
				}
				if scenario == "replaced_during" {
					replace(false)
				}
				if scenario == "disabled_during" {
					replace(true)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":10,"limit_window_seconds":18000}}}`))}, nil
			}))
			raw, errCall := h.nativeAccountQuota(ctx, request)
			if scenario == "success" {
				if errCall != nil || calls != 1 || ojson.GetBytes(raw, "result.quota.source").String() != "codex_wham" {
					t.Fatalf("background query failed: %v", errCall)
				}
				latest, _ := m.GetByID(a.ID)
				if latest.Disabled || latest.Status != coreauth.StatusActive {
					t.Fatal("quota changed routing status")
				}
			} else {
				expectedCalls := 0
				if strings.HasSuffix(scenario, "during") {
					expectedCalls = 1
				}
				if errCall == nil || calls != expectedCalls {
					t.Fatalf("identity fence failed: calls=%d error=%v", calls, errCall)
				}
			}
		})
	}
}

func TestBackgroundNativeQuotaExplicitOperationCancellation(t *testing.T) {
	h, m, a, _ := nativeQuotaFixture(t)
	a.Disabled = false
	a.Status = coreauth.StatusActive
	a, err := m.Register(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", nativeQuotaTransport(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	}))
	ctx = withHostCallbackPluginID(ctx, "bps")
	id, _, errOpen := h.createHostHTTPOperation("bps", nil, "", ctx, false)
	if errOpen != nil {
		t.Fatal(errOpen)
	}
	defer h.httpOperations.cancel("bps", nil, id)
	doc := ojson.NewDoc(backgroundQuotaRequest(a))
	_ = doc.Set("operation_id", id)
	done := make(chan error, 1)
	go func() { _, errCall := h.nativeAccountQuota(ctx, doc.Bytes()); done <- errCall }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("quota request not started")
	}
	h.httpOperations.cancel("bps", nil, id)
	select {
	case errCall := <-done:
		if errCall == nil || errCall.Error() != "codex_quota_cancelled" {
			t.Fatal("operation cancellation not observed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("operation did not cancel HTTP")
	}
}

func TestBackgroundNativeQuotaUsesManagerRefresh(t *testing.T) {
	h, m, a, _ := nativeQuotaFixture(t)
	a.Disabled = false
	a.Status = coreauth.StatusActive
	a.Metadata["expired"] = time.Now().Add(-time.Hour).Format(time.RFC3339)
	a, err := m.Register(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	executor := &nativeQuotaRefreshExecutor{fakeProviderExecutor: fakeProviderExecutor{provider: "codex"}, token: nativeQuotaToken("subject", "account", "rotated")}
	m.RegisterExecutor(executor)
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", nativeQuotaTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer "+executor.token {
			t.Fatal("background query used expired token")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"rate_limit":{"allowed":true}}`))}, nil
	}))
	if _, errCall := h.nativeAccountQuota(ctx, backgroundQuotaRequest(a)); errCall != nil || executor.calls != 1 {
		t.Fatalf("manager refresh not used: %v", errCall)
	}
	latest, _ := m.GetByID(a.ID)
	if latest.Disabled || latest.Metadata["access_token"] != executor.token {
		t.Fatal("refresh owner or enabled state changed")
	}
}
