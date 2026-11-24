package handlers

import (
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/gin-gonic/gin"
	claudemodels "github.com/router-for-me/CLIProxyAPI/v8/internal/client/claude/models"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestOAuthDirectoryModelScopeAndAvailability(t *testing.T) {
	reg := registry.GetGlobalRegistry()
	manager := coreauth.NewManager(nil, nil, nil)
	on := true
	cfg := &config.Config{Plugins: config.PluginsConfig{Enabled: true, Configs: map[string]config.PluginInstanceConfig{"cpa-oauth": {Enabled: &on}}}}
	manager.SetConfig(cfg)
	h := NewBaseAPIHandlers(&cfg.SDKConfig, manager)
	register := func(name, group string, models ...*registry.ModelInfo) string {
		a := &coreauth.Auth{ID: t.Name() + name, Provider: "codex", Metadata: map[string]any{"oauth_group": group, "access_token": "fixture"}}
		if _, err := manager.Register(t.Context(), a); err != nil {
			t.Fatal(err)
		}
		reg.RegisterClient(a.ID, a.Provider, models)
		t.Cleanup(func() { reg.UnregisterClient(a.ID) })
		return a.ID
	}
	const bare = "directory-model"
	const prefixed = "branch/" + bare
	const private = "directory-other"
	aliasOwner := register("one", "alpha", &registry.ModelInfo{ID: bare}, &registry.ModelInfo{ID: prefixed, OptionalOAuthPrefix: true})
	register("two", "beta", &registry.ModelInfo{ID: prefixed}, &registry.ModelInfo{ID: private})
	models := []map[string]any{{"id": prefixed, "slug": prefixed, "display_name": "compat"}, {"id": bare, "slug": bare, "display_name": "regular"}, {"id": private, "slug": private, "display_name": "private"}}
	call := func(group, format, detail string, body any) (int, ojson.Result) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		if group != "" {
			c.Set("accessMetadata", map[string]string{"oauth_group": group})
		}
		if detail != "" {
			c.Set(ModelDetailIDContextKey, detail)
		}
		h.WriteModelListResponse(c, format, body)
		return w.Code, ojson.ParseBytes(w.Body.Bytes())
	}
	check := func(field string, body ojson.Result, want ...string) {
		t.Helper()
		var got []string
		for _, row := range body.Get(field).Array() {
			id := row.Get("id").String()
			if id == "" {
				id = row.Get("slug").String()
			}
			got = append(got, id)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("%s got %v want %v", field, got, want)
		}
	}
	openai := map[string]any{"data": models}
	_, data := call("alpha", "openai", "", openai)
	check("data", data, bare)
	_, data = call("beta", "openai", "", openai)
	check("data", data, prefixed, private)
	_, data = call("alpha", "openai", "", map[string]any{"models": []map[string]string{{"slug": prefixed}, {"slug": bare}}})
	check("models", data, bare)
	_, data = call("alpha", "openai", "", map[string]any{"data": models[:1]})
	check("data", data)
	if code, _ := call("alpha", "openai", prefixed, openai); code != 200 {
		t.Fatal("authorized compatibility detail", code)
	}
	if code, _ := call("beta", "openai", bare, openai); code != 404 {
		t.Fatal("out-of-scope detail", code)
	}
	claude := claudemodels.BuildResponse(models, false)
	wire := claudemodels.EnsureClaudeModelIDPrefix(bare)
	_, data = call("alpha", "claude", "", claude)
	check("data", data, wire)
	if data.Get("first_id").String() != wire || data.Get("last_id").String() != wire {
		t.Fatal("stale cursors")
	}
	if code, _ := call("alpha", "claude", wire, claude); code != 200 {
		t.Fatal("authorized Claude detail", code)
	}
	if code, _ := call("beta", "claude", wire, claude); code != 404 {
		t.Fatal("out-of-scope Claude detail", code)
	}
	reg.SuspendClientModel(aliasOwner, bare, "auth_unavailable")
	_, data = call("alpha", "openai", "", openai)
	check("data", data, bare)
	_, data = call("alpha", "openai", "", map[string]any{"data": models[:1]})
	check("data", data)
	reg.ResumeClientModel(aliasOwner, bare)
	_, data = call("", "openai", "", openai)
	check("data", data, prefixed, bare, private)
	reg.UnregisterClient(t.Name() + "two")
	_, data = call("", "openai", "", openai)
	check("data", data, bare, private)
	manager.SetConfig(&config.Config{})
	_, data = call("", "openai", "", openai)
	check("data", data, prefixed, bare, private)
}
