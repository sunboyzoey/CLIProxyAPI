package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestAlphaSearchPayloadFinalBarrier(t *testing.T) {
	original := []byte(`{"model":"bps/alias","id":"search-session","commands":{"search_query":[{"q":"golang"}],"open":[{"ref_id":"opaque-ref"}]},"prompt_cache_key":"original","prompt_cache_retention":"24h","store":false,"future":{"opaque":"keep"}}`)
	match := []config.PayloadModelRule{{Name: "bps/alias", Protocol: "codex-alpha-search", Headers: map[string]string{"X-Test": "yes"}}}
	cfg := &config.Config{Payload: config.PayloadConfig{
		Override: []config.PayloadRule{
			{Models: []config.PayloadModelRule{{Name: "*", Protocol: "codex"}}, Params: map[string]any{"reasoning.effort": "high"}},
			{Models: match, Params: map[string]any{"model": "configured", "prompt_cache_key": "explicit-config"}},
		},
		Filter: []config.PayloadFilterRule{{Models: match, Params: []string{"id", "commands.open"}}},
	}}
	before := helps.PayloadConfigEvaluationCount()
	out := prepareCodexAlphaSearchBody(cfg, original, "resolved", "bps/alias", "/v1/alpha/search", http.Header{"X-Test": {"yes"}})
	if diff := helps.PayloadConfigEvaluationCount() - before; diff != 1 {
		t.Fatalf("payload evaluations=%d, want 1", diff)
	}
	doc := ojson.NewDoc(out)
	if doc.Get("model").String() != "configured" || doc.Get("prompt_cache_key").String() != "explicit-config" {
		t.Fatalf("override lost: %s", out)
	}
	for _, field := range []string{"id", "commands.open", "prompt_cache_retention", "store", "reasoning"} {
		if doc.Get(field).Exists() {
			t.Fatalf("unexpected %s: %s", field, out)
		}
	}
	if doc.Get("commands.search_query.0.q").String() != "golang" || doc.Get("future.opaque").String() != "keep" {
		t.Fatalf("unknown/protocol fields lost: %s", out)
	}
	if ojson.GetBytes(original, "model").String() != "bps/alias" {
		t.Fatal("modified original request")
	}
	cfg.Payload.Filter = append(cfg.Payload.Filter, config.PayloadFilterRule{Models: match, Params: []string{"model"}})
	out = prepareCodexAlphaSearchBody(cfg, original, "resolved", "bps/alias", "/v1/alpha/search", http.Header{"X-Test": {"yes"}})
	if ojson.GetBytes(out, "model").Exists() {
		t.Fatal("filtered model restored")
	}
}

func TestAlphaSearchOAuthRoutesAndRewritesFinalModel(t *testing.T) {
	server := newTestServer(t)
	executor := &codexSearchCaptureExecutor{}
	server.handlers.AuthManager.RegisterExecutor(executor)
	selected := &auth.Auth{ID: "native-search", Provider: "codex", Prefix: "native", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "native-token"}}
	if _, err := server.handlers.AuthManager.Register(context.Background(), selected); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(selected.ID, "codex", []*registry.ModelInfo{{ID: "native/gpt-6.2-sol"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(selected.ID) })
	router := &codexSearchModelRouter{handled: true, response: pluginapi.ModelRouteResponse{Handled: true, TargetKind: "provider", Target: "codex", TargetModel: "native/gpt-6.2-sol"}}
	server.handlers.SetModelRouterHost(router)
	for _, path := range []string{"/v1/alpha/search", "/backend-api/codex/alpha/search"} {
		for _, model := range []string{"account-bps/gpt-6.1-sol", "gpt-6.2-sol"} {
			payload := `{"id":"s1","model":"` + model + `","commands":{"search_query":[{"q":"golang"}]},"future":{"opaque":"state"},"store":false}`
			response := `{"output":[{"type":"encrypted_content","encrypted_content":"opaque-search-state"}],"future":true}`
			executor.responseBody = io.NopCloser(strings.NewReader(response))
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
			request.Header.Set("Authorization", "Bearer test-key")
			result := httptest.NewRecorder()
			server.engine.ServeHTTP(result, request)
			if result.Code != http.StatusOK {
				t.Fatalf("status=%d: %s", result.Code, result.Body.String())
			}
			if result.Body.String() != response {
				t.Fatalf("response not opaque: %s", result.Body.String())
			}
			if got := ojson.GetBytes(executor.body, "model").String(); got != "gpt-6.2-sol" {
				t.Fatalf("upstream model=%q", got)
			}
			if got := ojson.GetBytes(executor.body, "future.opaque").String(); got != "state" {
				t.Fatalf("unknown field=%q", got)
			}
			if ojson.GetBytes(executor.body, "store").Exists() {
				t.Fatal("responses-only store reached search")
			}
			if executor.authIDs[len(executor.authIDs)-1] != "native-search" {
				t.Fatal("wrong search account")
			}
		}
	}
}

func TestAlphaSearchNoModelDoesNotInventOne(t *testing.T) {
	original := []byte(`{"id":"session","commands":{}}`)
	out := prepareCodexAlphaSearchBody(nil, original, "resolved", "", "/v1/alpha/search", nil)
	if string(out) != string(original) {
		t.Fatalf("missing model changed: %s", out)
	}
}

func TestAlphaSearchErrorsAreNotReplayed(t *testing.T) {
	for _, status := range []int{401, 403, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := newTestServer(t)
			upstream := `{"error":{"code":"search_fixture_failure"}}`
			executor := &alphaSearchRetryExecutor{&codexSearchCaptureExecutor{statuses: []int{status}, responseBody: io.NopCloser(strings.NewReader(upstream))}}
			server.handlers.AuthManager.RegisterExecutor(executor)
			credential := &auth.Auth{ID: "native-errors", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "fixture"}}
			if _, err := server.handlers.AuthManager.Register(context.Background(), credential); err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/alpha/search", strings.NewReader(`{"id":"fixture"}`))
			request.Header.Set("Authorization", "Bearer test-key")
			result := httptest.NewRecorder()
			server.engine.ServeHTTP(result, request)
			if result.Code != status || result.Body.String() != upstream {
				t.Fatalf("lost upstream error: %d %s", result.Code, result.Body.String())
			}
			if result.Header().Get("Retry-After") != "7" {
				t.Fatal("upstream retry guidance lost")
			}
			if executor.httpCalls != 1 || executor.refreshCalls != 0 {
				t.Fatalf("unexpected replay/refresh: %d/%d", executor.httpCalls, executor.refreshCalls)
			}
		})
	}
}

type alphaSearchRetryExecutor struct{ *codexSearchCaptureExecutor }

func (e *alphaSearchRetryExecutor) HttpRequest(ctx context.Context, selected *auth.Auth, request *http.Request) (*http.Response, error) {
	response, err := e.codexSearchCaptureExecutor.HttpRequest(ctx, selected, request)
	if response != nil {
		response.Header.Set("Retry-After", "7")
	}
	return response, err
}
