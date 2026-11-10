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
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestHostNativeProbeCredentialsIdentityAndProxy(t *testing.T) {
	for _, proxy := range []string{"", "http://account-proxy:7890"} {
		h := New()
		h.runtimeConfig = &config.Config{}
		h.runtimeConfig.ProxyURL = "http://global-proxy:7890"
		m := coreauth.NewManager(nil, nil, nil)
		h.SetAuthManager(m)
		a, err := m.Register(context.Background(), &coreauth.Auth{ID: "native.json", Provider: "codex", ProxyURL: proxy, Disabled: true, Status: coreauth.StatusDisabled, Metadata: map[string]any{"access_token": "current-at", "refresh_token": "never-return-this-rt", "account_id": "account-one", "expired": time.Now().Add(time.Hour).Format(time.RFC3339)}})
		if err != nil {
			t.Fatal(err)
		}
		doc := ojson.NewDocString(`{}`)
		_ = doc.Set("auth_index", a.Index)
		_ = doc.Set("expected_auth_id", a.ID)
		_ = doc.Set("expected_account_id", "account-one")
		raw, err := h.callFromPlugin(context.Background(), "host.auth.probe_credentials", doc.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "never-return-this-rt") || strings.Contains(string(raw), "refresh_token") {
			t.Fatal("callback exposed RT")
		}
		result := ojson.GetBytes(raw, "result")
		wantProxy := proxy
		if wantProxy == "" {
			wantProxy = "http://global-proxy:7890"
		}
		if result.Get("access_token").String() != "current-at" || result.Get("account_id").String() != "account-one" || result.Get("proxy_url").String() != wantProxy || !result.Get("disabled").Bool() {
			t.Fatal("credential projection mismatch")
		}
		if !result.Get("pause_supported").Bool() {
			t.Fatal("local scheduling should support probe pause")
		}
		m.SetConfig(&config.Config{Home: config.HomeConfig{Enabled: true}})
		raw, err = h.callHostNativeProbeCredentials(context.Background(), doc.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if ojson.GetBytes(raw, "result.pause_supported").Bool() {
			t.Fatal("Home scheduler bypasses plugin pause")
		}
		_ = doc.Set("expected_account_id", "other-account")
		if _, err = h.callHostNativeProbeCredentials(context.Background(), doc.Bytes()); err == nil {
			t.Fatal("accepted wrong account")
		}
		_ = doc.Set("expected_account_id", "account-one")
		_ = doc.Set("expected_auth_id", "replacement.json")
		if _, err = h.callHostNativeProbeCredentials(context.Background(), doc.Bytes()); err == nil {
			t.Fatal("accepted wrong credential")
		}
	}
}

func TestHostNativeProbePauseRequiresSelectedScheduler(t *testing.T) {
	scheduler := schedulerFunc(func(context.Context, pluginapi.SchedulerPickRequest) (pluginapi.SchedulerPickResponse, error) {
		return pluginapi.SchedulerPickResponse{}, nil
	})
	h := newHostWithRecords(
		capabilityRecord{id: "bps", priority: 1, plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{Scheduler: scheduler}}},
		capabilityRecord{id: "other", priority: 2, plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{Scheduler: scheduler}}},
	)
	h.SetAuthManager(coreauth.NewManager(nil, nil, nil))
	if h.nativeProbePauseSupported(withHostCallbackPluginID(context.Background(), "bps")) {
		t.Fatal("non-selected scheduler claimed pause support")
	}
	if !h.nativeProbePauseSupported(withHostCallbackPluginID(context.Background(), "other")) {
		t.Fatal("selected local scheduler should support pause")
	}
	h = New()
	h.SetAuthManager(coreauth.NewManager(nil, nil, nil))
	if h.nativeProbePauseSupported(withHostCallbackPluginID(context.Background(), "bps")) {
		t.Fatal("missing scheduler claimed pause support")
	}
}

func TestHostNativeProbeCredentialsReadOnlyPreparation(t *testing.T) {
	h := New()
	m := coreauth.NewManager(nil, nil, nil)
	h.SetAuthManager(m)
	a, err := m.Register(context.Background(), &coreauth.Auth{ID: "native.json", Provider: "codex", Metadata: map[string]any{"access_token": "expired-at", "refresh_token": "secret", "account_id": "account-one", "expired": time.Now().Add(-time.Hour).Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	doc := ojson.NewDocString(`{"prepare":false}`)
	_ = doc.Set("auth_index", a.Index)
	_ = doc.Set("expected_auth_id", a.ID)
	if _, err = h.callHostNativeProbeCredentials(context.Background(), doc.Bytes()); err != nil {
		t.Fatal("read-only preparation tried to refresh without an executor")
	}
	_ = doc.Set("prepare", true)
	if _, err = h.callHostNativeProbeCredentials(context.Background(), doc.Bytes()); err == nil {
		t.Fatal("preparation silently used expired token")
	}
}

func TestHostNativeProbeCredentialsRejectsUnsupportedProviders(t *testing.T) {
	for _, provider := range []string{"bps", "openai", "codex"} {
		h := New()
		m := coreauth.NewManager(nil, nil, nil)
		h.SetAuthManager(m)
		a, err := m.Register(context.Background(), &coreauth.Auth{ID: "unsupported", Provider: provider, Metadata: map[string]any{"access_token": "api-secret", "api_key": "api-secret", "account_id": "account-one"}})
		if err != nil {
			t.Fatal(err)
		}
		doc := ojson.NewDocString(`{}`)
		_ = doc.Set("auth_index", a.Index)
		_ = doc.Set("expected_auth_id", a.ID)
		if _, err = h.callHostNativeProbeCredentials(context.Background(), doc.Bytes()); err == nil {
			t.Fatalf("accepted unsupported %s", provider)
		}
	}
}

func TestNativeProbeAccountIDFromOfficialClaim(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"https://api.openai.com/auth":{"chatgpt_account_id":"claim-account"}}`))
	a := &coreauth.Auth{Metadata: map[string]any{"access_token": "e30." + payload + ".signature"}}
	if nativeProbeAccountID(a) != "claim-account" {
		t.Fatal("missing official account claim")
	}
}
