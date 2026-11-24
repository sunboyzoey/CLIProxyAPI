package pluginhost

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type nativeQuotaTransport func(*http.Request) (*http.Response, error)

func (f nativeQuotaTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func nativeQuotaToken(subject, account, suffix string) string {
	doc := ojson.NewDocString(`{}`)
	_ = doc.Set("sub", subject)
	_ = doc.Set("https://api\\.openai\\.com/auth", map[string]string{"chatgpt_account_id": account})
	return "e30." + base64.RawURLEncoding.EncodeToString(doc.Bytes()) + "." + suffix
}

func nativeQuotaFixture(t *testing.T) (*Host, *coreauth.Manager, *coreauth.Auth, []byte) {
	t.Helper()
	h := New()
	m := coreauth.NewManager(nil, nil, nil)
	h.SetAuthManager(m)
	a, errRegister := m.Register(context.Background(), &coreauth.Auth{ID: "native.json", Provider: "codex", Disabled: true, Status: coreauth.StatusDisabled,
		Metadata: map[string]any{"access_token": nativeQuotaToken("subject", "account", "original"), "refresh_token": "private-refresh-token", "expired": time.Now().Add(time.Hour).Format(time.RFC3339)}})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	doc := ojson.NewDocString(`{"expected_account_id":"account","expected_subject":"subject"}`)
	_ = doc.Set("auth_index", a.Index)
	_ = doc.Set("expected_auth_id", a.ID)
	return h, m, a, doc.Bytes()
}

func TestNativeAccountQuotaUsesCPAIdentityAndRedacts(t *testing.T) {
	h, m, a, request := nativeQuotaFixture(t)
	queries := 0
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", nativeQuotaTransport(func(r *http.Request) (*http.Response, error) {
		queries++
		if r.URL.String() != nativeQuotaURL || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+a.Metadata["access_token"].(string) || r.Header.Get("ChatGPT-Account-Id") != "account" || r.Body != nil {
			t.Fatal("quota did not use the selected native OAuth credential")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"plan_type":"pro","access_token":"private-upstream-secret","rate_limit":{"allowed":false,"limit_reached":true,"primary_window":{"used_percent":100,"limit_window_seconds":18000,"reset_at":1800000000}},"code_review_rate_limit":{"primary_window":{"used_percent":10}},"additional_rate_limits":[{"limit_name":"extra","rate_limit":{"primary_window":{"used_percent":30}}}],"model_usage":{"test":{"available":false,"secret":"private-upstream-secret"}}}`))}, nil
	}))
	// Per-request overrides must never replace this physical credential's proxy.
	ctx = cliproxyexecutor.WithRequestProxyURL(ctx, "http://unused-override.invalid:1")
	raw, errCall := h.callFromPlugin(ctx, "host.auth.native_quota", request)
	if errCall != nil {
		t.Fatal(errCall)
	}
	result := ojson.GetBytes(raw, "result")
	quota := result.Get("quota")
	_, _, identity := nativeQuotaIdentity(a)
	if queries != 1 || result.Get("auth_id").String() != a.ID || result.Get("identity").String() != identity || result.Get("provider").String() != "codex" {
		t.Fatal("quota response lost physical identity")
	}
	if quota.Get("subscription.plan").String() != "pro" || len(quota.Get("groups").Array()) != 3 || quota.Get("groups.0.displayName").String() != "Codex 账号额度" || quota.Get("availability").String() != "exhausted" || quota.Get("source").String() != "codex_wham" || quota.Get("cached").Bool() {
		t.Fatal("native quota lost typed display fields")
	}
	if _, errParse := time.Parse(time.RFC3339Nano, quota.Get("fetched_at").String()); errParse != nil {
		t.Fatal("quota timestamp missing")
	}
	for _, secret := range []string{"private", "access_token", "refresh_token", "proxy_url", a.Metadata["access_token"].(string)} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("quota projection leaked unrelated credential/upstream data")
		}
	}
	latest, _ := m.GetByID(a.ID)
	if !latest.Disabled || latest.Status != coreauth.StatusDisabled {
		t.Fatal("quota query changed account availability")
	}
}

func TestNativeAccountQuotaFencesReplacedCredentials(t *testing.T) {
	for _, during := range []bool{false, true} {
		h, m, a, request := nativeQuotaFixture(t)
		queries := 0
		replace := func() {
			replacement := a.Clone()
			replacement.Metadata["access_token"] = nativeQuotaToken("other-subject", "account", "replacement")
			if _, errRegister := m.Register(context.Background(), replacement); errRegister != nil {
				t.Fatal(errRegister)
			}
		}
		if !during {
			replace()
		}
		ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", nativeQuotaTransport(func(*http.Request) (*http.Response, error) {
			queries++
			replace()
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"plan_type":"plus"}`))}, nil
		}))
		if _, errCall := h.nativeAccountQuota(ctx, request); errCall == nil || errCall.Error() != "codex_quota_identity_changed" {
			t.Fatal("replacement was accepted")
		}
		if !during && queries != 0 || during && queries != 1 {
			t.Fatal("identity fence ran at the wrong boundary")
		}
	}
}

func TestNativeAccountQuotaExcludesExplicitAPIKeyAndVirtualKinds(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*coreauth.Auth)
	}{
		{"attribute-api-key-kind", func(a *coreauth.Auth) {
			a.Attributes = map[string]string{coreauth.AttributeAuthKind: coreauth.AuthKindAPIKey}
		}},
		{"metadata-api-key-kind", func(a *coreauth.Auth) { a.Metadata[coreauth.AttributeAuthKind] = coreauth.AuthKindAPIKey }},
		{"plugin-virtual", func(a *coreauth.Auth) { a.Attributes = map[string]string{coreauth.AttributePluginVirtual: "true"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, m, a, request := nativeQuotaFixture(t)
			tc.edit(a)
			if _, errRegister := m.Register(context.Background(), a); errRegister != nil {
				t.Fatal(errRegister)
			}
			ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", nativeQuotaTransport(func(*http.Request) (*http.Response, error) {
				t.Fatal("unsupported credential reached native WHAM")
				return nil, nil
			}))
			if account, subject, identity := nativeQuotaIdentity(a); account != "" || subject != "" || identity != "" {
				t.Fatal("quota identity disagreed with native OAuth classification")
			}
			if _, errCall := h.nativeAccountQuota(ctx, request); errCall == nil || errCall.Error() != "codex_quota_oauth_required" {
				t.Fatal("non-OAuth credential accepted for native quota")
			}
		})
	}
}

type nativeQuotaRefreshExecutor struct {
	fakeProviderExecutor
	calls int
	token string
}

func (e *nativeQuotaRefreshExecutor) Refresh(_ context.Context, a *coreauth.Auth) (*coreauth.Auth, error) {
	e.calls++
	a.Metadata["access_token"] = e.token
	a.Metadata["expired"] = time.Now().Add(time.Hour).Format(time.RFC3339)
	return a, nil
}

func TestNativeAccountQuotaPreparesThroughManagerRefresh(t *testing.T) {
	h, m, a, request := nativeQuotaFixture(t)
	executor := &nativeQuotaRefreshExecutor{fakeProviderExecutor: fakeProviderExecutor{provider: "codex"}, token: nativeQuotaToken("subject", "account", "rotated")}
	m.RegisterExecutor(executor)
	a.Metadata["expired"] = time.Now().Add(-time.Hour).Format(time.RFC3339)
	if _, errRegister := m.Register(context.Background(), a); errRegister != nil {
		t.Fatal(errRegister)
	}
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", nativeQuotaTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer "+executor.token {
			t.Fatal("native quota used stale OAuth token")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"rate_limit":{"allowed":true}}`))}, nil
	}))
	if _, errCall := h.nativeAccountQuota(ctx, request); errCall != nil || executor.calls != 1 {
		t.Fatalf("manager refresh not used: calls=%d error=%v", executor.calls, errCall)
	}
	latest, _ := m.GetByID(a.ID)
	if latest.Metadata["access_token"] != executor.token || !latest.Disabled {
		t.Fatal("refresh ownership or disabled state lost")
	}
}

func TestNativeAccountQuotaCancellationReachesRefreshAndHTTP(t *testing.T) {
	t.Run("refresh", func(t *testing.T) {
		h, m, a, request := nativeQuotaFixture(t)
		executor := &bpsProbeCancelExecutor{fakeProviderExecutor: fakeProviderExecutor{provider: "codex"}, started: make(chan struct{}), finished: make(chan struct{})}
		m.RegisterExecutor(executor)
		a.Metadata["expired"] = time.Now().Add(-time.Hour).Format(time.RFC3339)
		if _, errRegister := m.Register(context.Background(), a); errRegister != nil {
			t.Fatal(errRegister)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { _, errCall := h.nativeAccountQuota(ctx, request); done <- errCall }()
		<-executor.started
		cancel()
		select {
		case errCall := <-done:
			if errCall == nil || !strings.HasPrefix(errCall.Error(), "codex_quota_credentials_") {
				t.Fatal("cancelled refresh published a quota")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("cancelled quota remained blocked on refresh")
		}
		select {
		case <-executor.finished:
		case <-time.After(2 * time.Second):
			t.Fatal("refresh did not receive quota cancellation")
		}
	})
	t.Run("http", func(t *testing.T) {
		h, _, _, request := nativeQuotaFixture(t)
		started := make(chan struct{})
		ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", nativeQuotaTransport(func(r *http.Request) (*http.Response, error) {
			close(started)
			<-r.Context().Done()
			return nil, r.Context().Err()
		}))
		callback, closeCallback := h.openCallbackContextForPlugin(ctx, "bps")
		doc := ojson.NewDoc(request)
		_ = doc.Set("host_callback_id", callback)
		done := make(chan error, 1)
		go func() {
			_, errCall := h.nativeAccountQuota(withHostCallbackPluginID(context.Background(), "bps"), doc.Bytes())
			done <- errCall
		}()
		<-started
		closeCallback()
		select {
		case errCall := <-done:
			if errCall == nil || errCall.Error() != "codex_quota_cancelled" {
				t.Fatal("closed callback did not cancel native HTTP")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("native HTTP outlived callback")
		}
	})
}

func TestNativeAccountQuotaUsesAccountProxyAndRejectsInvalidProxy(t *testing.T) {
	h, _, a, _ := nativeQuotaFixture(t)
	var accountCalls, globalCalls atomic.Int32
	proxy := func(counter *atomic.Int32) *httptest.Server {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			counter.Add(1)
			if r.Method != http.MethodConnect || r.Host != "chatgpt.com:443" {
				t.Error("unexpected proxy destination")
			}
			w.WriteHeader(http.StatusForbidden)
		}))
		t.Cleanup(server.Close)
		return server
	}
	a.ProxyURL = proxy(&accountCalls).URL
	h.runtimeConfig = &config.Config{}
	h.runtimeConfig.ProxyURL = proxy(&globalCalls).URL
	if _, errFetch := h.fetchNativeAccountQuota(context.Background(), a); errFetch == nil || errFetch.Error() != "codex_quota_unavailable" || accountCalls.Load() != 1 || globalCalls.Load() != 0 {
		t.Fatal("quota ignored physical account proxy")
	}
	a.ProxyURL = "http://private:secret@example.invalid:99999"
	if _, errFetch := h.fetchNativeAccountQuota(context.Background(), a); errFetch == nil || errFetch.Error() != "codex_quota_invalid_proxy" {
		t.Fatal("invalid account proxy silently fell back")
	}
}

func TestNativeAccountQuotaErrorsAreBoundedAndSafe(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   string
	}{
		{401, "private-upstream-secret", "codex_quota_unauthorized"},
		{403, "private-upstream-secret", "codex_quota_forbidden"},
		{429, "private-upstream-secret", "codex_quota_rate_limited"},
		{302, "private-upstream-secret", "codex_quota_upstream_error"},
		{200, strings.Repeat("x", (1<<20)+1), "codex_quota_invalid_response"},
	} {
		h, _, a, _ := nativeQuotaFixture(t)
		ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", nativeQuotaTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		}))
		if _, errFetch := h.fetchNativeAccountQuota(ctx, a); errFetch == nil || errFetch.Error() != tc.want {
			t.Fatal("unsafe or incorrect quota error")
		}
	}
	h, _, a, _ := nativeQuotaFixture(t)
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", nativeQuotaTransport(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("private-proxy-token")
	}))
	if _, errFetch := h.fetchNativeAccountQuota(ctx, a); errFetch == nil || errFetch.Error() != "codex_quota_unavailable" {
		t.Fatal("transport error escaped quota boundary")
	}
}

func TestNormalizeNativeQuotaNeverInventsMissingCounters(t *testing.T) {
	for _, tc := range []struct {
		raw          string
		groups       int
		availability string
		valid        bool
	}{
		{`{}`, 0, "unknown", false},
		{`{"plan_type":"plus"}`, 0, "unknown", true},
		{`{"rate_limit":{"allowed":false}}`, 0, "exhausted", true},
		{`{"rate_limit":{"allowed":"false","primary_window":{}}}`, 0, "unknown", false},
		{`{"rate_limit":{"primary_window":{"used_percent":"50"},"secondary_window":{"used_percent":0}}}`, 1, "unknown", true},
		{`{"rate_limit":{"primary_window":{"used_percent":-1},"secondary_window":{"used_percent":101}}}`, 0, "unknown", false},
		{`{"rate_limit":{"allowed":true,"limit_reached":true}}`, 0, "unknown", true},
	} {
		out, errNormalize := normalizeNativeQuota([]byte(tc.raw), time.Now().UTC())
		if (errNormalize == nil) != tc.valid || len(out.Groups) != tc.groups || out.Availability != tc.availability {
			t.Fatalf("incorrect quota projection for %s", tc.raw)
		}
	}
}
