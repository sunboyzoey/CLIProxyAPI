package pluginhost

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func bpsProbeTestMetadata() map[string]any {
	token := "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"subject-one","https://api.openai.com/auth":{"chatgpt_account_id":"account-one"}}`)) + ".signature"
	return map[string]any{"access_token": token, "refresh_token": "secret-rt", "id_token": "secret-id-token", "unknown_secret": "must-not-leak",
		"client_id": "app_fnr0pYvVwwFDocDumLG3H2Bp", "token_type": "Bearer", "expires_in": 3600,
		"obtained_at": time.Now().Format(time.RFC3339), "expired": time.Now().Add(time.Hour).Format(time.RFC3339),
		"headers": map[string]string{"X-Account-Setting": "preserved"}, "max_concurrent": 3}
}

func TestHostBPSProbeCredentialsProjectionAndProxy(t *testing.T) {
	for _, scenario := range []struct {
		name, account, global, fallback, want string
	}{
		{"account", "http://account-proxy:7890", "http://global-proxy:7890", "http://fallback-proxy:7890", "http://account-proxy:7890"},
		{"global", "", "http://global-proxy:7890", "http://fallback-proxy:7890", "http://global-proxy:7890"},
		{"fallback", "", "", "http://fallback-proxy:7890", "http://fallback-proxy:7890"},
		{"default_route", "", "", "", ""},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			h := New()
			h.runtimeConfig = &config.Config{}
			h.runtimeConfig.ProxyURL = scenario.global
			m := coreauth.NewManager(nil, nil, nil)
			h.SetAuthManager(m)
			a, err := m.Register(context.Background(), &coreauth.Auth{ID: "bps.json", Provider: "bps", ProxyURL: scenario.account, Metadata: bpsProbeTestMetadata()})
			if err != nil {
				t.Fatal(err)
			}
			doc := ojson.NewDocString(`{}`)
			_ = doc.Set("auth_index", a.Index)
			_ = doc.Set("expected_auth_id", a.ID)
			_ = doc.Set("expected_account_id", "account-one")
			_ = doc.Set("expected_subject", "subject-one")
			_ = doc.Set("fallback_proxy_url", scenario.fallback)
			raw, err := h.callFromPlugin(context.Background(), "host.auth.bps_probe_credentials", doc.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"refresh_token", "secret-rt", "id_token", "unknown_secret", "must-not-leak"} {
				if strings.Contains(string(raw), forbidden) {
					t.Fatal("BPS callback exposed non-generation material")
				}
			}
			result := ojson.GetBytes(raw, "result")
			wantProxy := scenario.want
			if result.Get("auth_id").String() != a.ID || result.Get("auth_index").String() != a.Index || result.Get("provider").String() != "bps" || result.Get("subject").String() != "subject-one" || result.Get("proxy_url").String() != wantProxy || result.Get("storage_json.proxy_url").String() != wantProxy || !result.Get("pause_supported").Bool() {
				t.Fatal("BPS credential identity or proxy projection mismatch")
			}
			if result.Get("storage_json.headers.X-Account-Setting").String() != "preserved" || result.Get("storage_json.max_concurrent").Int() != 3 || result.Get("storage_json.access_token").String() == "" {
				t.Fatal("lost generation settings")
			}
			m.SetConfig(&config.Config{Home: config.HomeConfig{Enabled: true}})
			raw, err = h.callHostBPSProbeCredentials(context.Background(), doc.Bytes())
			if err != nil || ojson.GetBytes(raw, "result.pause_supported").Bool() {
				t.Fatal("Home claimed pause support")
			}
			_ = doc.Set("expected_subject", "different-subject")
			if _, err = h.callHostBPSProbeCredentials(context.Background(), doc.Bytes()); err == nil {
				t.Fatal("accepted subject mismatch")
			}
		})
	}
}

func TestHostBPSProbeCredentialsRejectsUnsafeIdentity(t *testing.T) {
	for _, scenario := range []string{"disabled", "native", "metadata_mismatch", "account_changed", "id_changed", "api_key"} {
		t.Run(scenario, func(t *testing.T) {
			h := New()
			m := coreauth.NewManager(nil, nil, nil)
			h.SetAuthManager(m)
			a := &coreauth.Auth{ID: "bps.json", Provider: "bps", Metadata: bpsProbeTestMetadata()}
			switch scenario {
			case "disabled":
				a.Disabled = true
			case "native":
				a.Provider = "codex"
			case "metadata_mismatch":
				a.Metadata["subject"] = "wrong"
			case "api_key":
				a.Metadata["api_key"] = "wrong"
			}
			a, err := m.Register(context.Background(), a)
			if err != nil {
				t.Fatal(err)
			}
			doc := ojson.NewDocString(`{"prepare":false,"expected_account_id":"account-one","expected_subject":"subject-one"}`)
			_ = doc.Set("auth_index", a.Index)
			_ = doc.Set("expected_auth_id", a.ID)
			if scenario == "account_changed" {
				_ = doc.Set("expected_account_id", "wrong")
			}
			if scenario == "id_changed" {
				_ = doc.Set("expected_auth_id", "wrong")
			}
			if _, err = h.callHostBPSProbeCredentials(context.Background(), doc.Bytes()); err == nil {
				t.Fatal("accepted unsafe credential")
			}
		})
	}
}

func TestHostBPSProbeCredentialsReadOnlyDoesNotRefresh(t *testing.T) {
	h := New()
	m := coreauth.NewManager(nil, nil, nil)
	h.SetAuthManager(m)
	metadata := bpsProbeTestMetadata()
	metadata["expired"] = time.Now().Add(-time.Hour).Format(time.RFC3339)
	a, err := m.Register(context.Background(), &coreauth.Auth{ID: "bps.json", Provider: "bps", Metadata: metadata})
	if err != nil {
		t.Fatal(err)
	}
	doc := ojson.NewDocString(`{"prepare":false}`)
	_ = doc.Set("auth_index", a.Index)
	_ = doc.Set("expected_auth_id", a.ID)
	if _, err = h.callHostBPSProbeCredentials(context.Background(), doc.Bytes()); err != nil {
		t.Fatal("read-only bridge attempted renewal")
	}
	_ = doc.Set("prepare", true)
	if _, err = h.callHostBPSProbeCredentials(context.Background(), doc.Bytes()); err == nil {
		t.Fatal("used expired bearer without renewal")
	}
}

type bpsProbeCancelExecutor struct {
	fakeProviderExecutor
	started, finished chan struct{}
}

func (e *bpsProbeCancelExecutor) Refresh(ctx context.Context, _ *coreauth.Auth) (*coreauth.Auth, error) {
	close(e.started)
	<-ctx.Done()
	close(e.finished)
	return nil, ctx.Err()
}

func TestHostBPSProbeCredentialsOperationCancellation(t *testing.T) {
	h := New()
	m := coreauth.NewManager(nil, nil, nil)
	h.SetAuthManager(m)
	exec := &bpsProbeCancelExecutor{fakeProviderExecutor: fakeProviderExecutor{provider: "bps"}, started: make(chan struct{}), finished: make(chan struct{})}
	m.RegisterExecutor(exec)
	metadata := bpsProbeTestMetadata()
	metadata["expired"] = time.Now().Add(-time.Hour).Format(time.RFC3339)
	a, err := m.Register(context.Background(), &coreauth.Auth{ID: "bps.json", Provider: "bps", Metadata: metadata})
	if err != nil {
		t.Fatal(err)
	}
	ctx := withHostCallbackPluginID(context.Background(), "bps")
	operationID := openHostHTTPOperation(t, h, ctx, "")
	doc := ojson.NewDocString(`{"fallback_proxy_url":"http://fallback-proxy:7890"}`)
	_ = doc.Set("auth_index", a.Index)
	_ = doc.Set("expected_auth_id", a.ID)
	_ = doc.Set("operation_id", operationID)
	done := make(chan error, 1)
	go func() { _, err := h.callHostBPSProbeCredentials(ctx, doc.Bytes()); done <- err }()
	<-exec.started
	cancelDoc := ojson.NewDocString(`{}`)
	_ = cancelDoc.Set("operation_id", operationID)
	if _, err = h.callHostHTTPCancel(ctx, cancelDoc.Bytes()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("prepared credentials after cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("BPS credential callback did not cancel")
	}
	select {
	case <-exec.finished:
	case <-time.After(2 * time.Second):
		t.Fatal("manager refresh did not receive cancellation")
	}
	if _, exists := h.httpOperations.claim("bps", nil, operationID, ""); exists {
		t.Fatal("credential operation leaked")
	}
}
