package cliproxy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type codexCatalogTestTransport func(*http.Request) (*http.Response, error)

func (f codexCatalogTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCPAOAuthAccountManifestRegistration(t *testing.T) {
	ctx := context.Background()
	enabled := true
	cfg := &config.Config{
		Plugins:         config.PluginsConfig{Enabled: true, Configs: map[string]config.PluginInstanceConfig{"cpa-oauth": {Enabled: &enabled}}},
		OAuthModelAlias: map[string][]config.OAuthModelAlias{"codex": {{Name: "account-specific", Alias: "public-alias"}}},
	}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	s := &Service{cfg: cfg, coreManager: manager, codexCatalogWake: make(chan struct{}, 1)}
	reg := GlobalModelRegistry()
	id := t.Name()
	reg.UnregisterClient(id)
	t.Cleanup(func() { reg.UnregisterClient(id) })

	a, err := manager.Register(ctx, &coreauth.Auth{
		ID: id, Provider: "codex", Prefix: "acct", Status: coreauth.StatusActive,
		Attributes: map[string]string{"plan_type": "pro", "excluded_models": "suppressed"},
		Metadata:   map[string]any{"access_token": "fixture-first", "account_id": "one"},
		ModelStates: map[string]*coreauth.ModelState{
			"protected": {Status: coreauth.StatusError, Unavailable: true, NextRetryAfter: time.Now().Add(time.Hour)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	status := http.StatusOK
	manifest := `{"models":[{"slug":"account-specific"},{"slug":"suppressed"},{"slug":"protected"}]}`
	calls := 0
	original := http.DefaultTransport
	http.DefaultTransport = codexCatalogTestTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Host != "chatgpt.com" || req.Header.Get("ChatGPT-Account-ID") == "" {
			t.Errorf("unexpected manifest destination or missing account binding")
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(manifest)), Header: make(http.Header)}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = original })

	s.completeModelRegistrationForAuth(ctx, a)
	if calls != 0 || len(reg.GetModelsForClient(id)) != 0 || len(s.codexCatalogWake) != 1 {
		t.Fatal("cold registration must remain empty and wake discovery without starting network I/O")
	}
	checkProtected := func(want bool) {
		t.Helper()
		current, _ := manager.GetByID(id)
		if (current.ModelStates["protected"] != nil) != want {
			t.Fatalf("protected cooldown present = %v, want %v", !want, want)
		}
	}
	checkProtected(true)
	first := s.refreshCodexAccountCatalog(ctx, codexCatalogJob{id: id})
	if first.IsZero() || calls != 1 {
		t.Fatal("account manifest was not discovered")
	}
	if !reg.ClientSupportsModel(id, "public-alias") || !reg.ClientSupportsModel(id, "acct/public-alias") || !reg.ClientSupportsModel(id, "protected") ||
		reg.ClientSupportsModel(id, "account-specific") || reg.ClientSupportsModel(id, "suppressed") || reg.ClientSupportsModel(id, "gpt-6-astra") {
		t.Fatal("published models did not honor the account's upstream catalog, aliases, and exclusions")
	}
	checkProtected(true)
	// A force refresh may invalidate the cache while the credential stays the same.
	status = http.StatusBadGateway
	if _, err = helps.DiscoverCodexAccountTiers(ctx, cfg, a, true); err == nil {
		t.Fatal("expected fixture discovery failure")
	}
	if current := s.refreshCodexAccountCatalog(ctx, codexCatalogJob{id, first, true}); !current.IsZero() || len(reg.GetModelsForClient(id)) != 0 || calls != 2 {
		t.Fatal("negative cache must retract routes without probing on every scan")
	}
	checkProtected(true)
	status = http.StatusOK
	manifest = `{"models":[]}`
	empty, err := helps.DiscoverCodexAccountTiers(ctx, cfg, a, true)
	if err != nil {
		t.Fatal(err)
	}
	s.refreshCodexAccountCatalog(ctx, codexCatalogJob{id: id, known: true})
	if len(reg.GetModelsForClient(id)) != 0 {
		t.Fatal("confirmed empty catalog published a fallback model")
	}
	checkProtected(false)

	// Even a stale publication that captured the current registry epoch must
	// not overwrite a different credential reusing the same filename and prefix.
	before := newModelRegistrationFence(a, cfg)
	before.codexCheckedAt = empty.CheckedAt
	replacement, _ := manager.GetByID(id)
	replacement.Metadata["account_id"] = "two"
	replacement.Metadata["access_token"] = "fixture-second"
	replacement, err = manager.Update(ctx, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if before.publishModels(s, id, "codex", []*ModelInfo{{ID: "old-account-only"}}) {
		t.Fatal("stale account grant published after credential replacement")
	}
	s.completeModelRegistrationForAuth(ctx, replacement)
	if len(reg.GetModelsForClient(id)) != 0 {
		t.Fatal("new identity inherited old registration")
	}
	manifest = `{"models":[{"slug":"replacement-only"}]}`
	checked := s.refreshCodexAccountCatalog(ctx, codexCatalogJob{id, empty.CheckedAt, true})
	if checked.IsZero() || !reg.ClientSupportsModel(id, "replacement-only") || reg.ClientSupportsModel(id, "public-alias") {
		t.Fatal("new account catalog was not isolated")
	}
}
