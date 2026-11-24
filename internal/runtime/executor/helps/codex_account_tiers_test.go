package helps

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestOAuthAccountTierEntitlementsAndPayloadFilter(t *testing.T) {
	tiers, err := parseCodexAccountTiers([]byte(`{"models":[{"slug":"sol","service_tiers":[{"id":"priority"},{"id":"ultrafast"}]},{"slug":"astra","service_tiers":[{"id":"fast"}]},{"slug":"plain"}]}`), time.Now(), "plus")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parseCodexAccountTiers([]byte(`{"error":{}}`), time.Now(), "plus"); err == nil {
		t.Fatal("invalid manifest accepted")
	}
	a := &auth.Auth{ID: t.Name(), Provider: "codex", Metadata: map[string]any{"access_token": "test", "account_id": "a", "service_tier": "ultrafast"}}
	key := tierCacheKey(nil, a)
	tierCache.Lock()
	tierCache.entries[key] = tierCacheEntry{tiers: tiers, expires: time.Now().Add(time.Hour)}
	tierCache.Unlock()
	t.Cleanup(func() { tierCache.Lock(); delete(tierCache.entries, key); tierCache.Unlock() })
	for _, tt := range []struct {
		mode, model, want string
		filter            bool
	}{
		{"ultrafast", "sol", "ultrafast", false}, {"ultrafast", "astra", "priority", false}, {"ultrafast", "plain", "", false}, {"ultrafast", "absent", "", false}, {"fast", "sol", "priority", false}, {"fast", "astra", "priority", false}, {"fast", "plain", "", false}, {"fast", "absent", "", false}, {"inherit", "sol", "default", false}, {"ultrafast", "sol", "", true},
	} {
		a.Metadata["service_tier"] = tt.mode
		cfg := &config.Config{}
		if tt.filter {
			cfg.Payload.Filter = []config.PayloadFilterRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: []string{"service_tier"}}}
		}
		doc := ojson.NewDocString(`{"service_tier":"default"}`)
		_ = doc.Set("model", tt.model)
		f := NewCodexPayloadFinalizer(context.Background(), cfg, "codex", "alias", "codex", "", nil, ex.Request{Model: "alias"}, ex.Options{}, a)
		f.FinalizeDoc(doc)
		if got := doc.Get("service_tier").String(); got != tt.want {
			t.Errorf("%+v got %q", tt, got)
		}
	}
	a.Metadata["account_id"] = "b"
	if _, ok := CachedCodexAccountTiers(a); ok {
		t.Fatal("cross-account entitlement")
	}
}

func TestOAuthAccountDiagnosticModelsFromManifest(t *testing.T) {
	data := []byte(`{"models":[
	  {"slug":"plus-only","available_in_plans":["plus"],"input_modalities":["image","text"]},
	  {"slug":"basic","supported_in_api":false},
	  {"slug":"free-only","available_in_plans":["free"]},
	  {"slug":"hidden","visibility":"hide","service_tiers":[{"id":"ultrafast"}]},
	  {"slug":"image-only","output_modalities":["image"]},
	  {"slug":"audio-only","input_modalities":["audio"]},
	  {"slug":"cloud-only","allow_only_codex_cloud_agent_orchestrator":true},
	  {"slug":"gpt-image-1.5"},{"slug":"bad id"},{"slug":"basic"}
	]}`)
	for plan, want := range map[string][]string{"plus": {"plus-only", "basic"}, "free": {"basic", "free-only"}} {
		got, err := parseCodexAccountTiers(data, time.Now(), plan)
		if err != nil || !slices.Equal(got.Models, want) || !slices.Equal(got.UltrafastModels, []string{"hidden"}) {
			t.Fatalf("plan %s: got %+v, err %v", plan, got, err)
		}
	}
}

func TestOAuthAccountPublishedCatalog(t *testing.T) {
	data := []byte(`{"models":[
	  {"slug":"standard","supported_in_api":false},
	  {"slug":"audio","input_modalities":["audio"]},
	  {"slug":"gpt-image-1.5","output_modalities":["image"]},
	  {"slug":"standard"},
	  {"slug":"limited","available_in_plans":["pro"]},
	  {"slug":"empty-plans","available_in_plans":[]},
	  {"slug":"hidden","visibility":"hide"},
	  {"slug":"workspace","allow_only_chatgpt_workspace_executor":true},
	  {"slug":"cloud","allow_only_codex_cloud_agent_orchestrator":true},
	  {"slug":"disabled","disabled":true},
	  {"slug":"off","enabled":false},
	  {"slug":"invalid id"}
	]}`)
	got, err := parseCodexAccountTiers(data, time.Now(), "free")
	if err != nil || !slices.Equal(got.CatalogModels, []string{"standard", "audio", "gpt-image-1.5"}) {
		t.Fatalf("published catalog = %q, error = %v", got.CatalogModels, err)
	}
	empty, err := parseCodexAccountTiers([]byte(`{"models":[]}`), time.Now(), "free")
	if err != nil || empty.CatalogModels == nil || len(empty.CatalogModels) != 0 {
		t.Fatalf("empty catalog = %#v, error = %v", empty.CatalogModels, err)
	}
	invalid, err := parseCodexAccountTiers([]byte(`{"models":{}}`), time.Now(), "free")
	if err == nil || invalid.CatalogModels != nil {
		t.Fatalf("invalid catalog = %#v, error = %v", invalid.CatalogModels, err)
	}
}

func TestOAuthAccountManifestCacheScope(t *testing.T) {
	a := &auth.Auth{ID: t.Name(), Provider: "codex", Metadata: map[string]any{"access_token": "test", "account_id": "a"}}
	cfg := &config.Config{}
	cfg.ProxyURL = "http://one.invalid"
	key := tierCacheKey(cfg, a)
	tierCache.Lock()
	tierCache.entries[key] = tierCacheEntry{tiers: CodexAccountTiers{CatalogModels: []string{}}, expires: time.Now().Add(time.Hour)}
	tierCache.Unlock()
	t.Cleanup(func() { tierCache.Lock(); delete(tierCache.entries, key); tierCache.Unlock() })
	if tiers, ok := CachedCodexAccountTiersForConfig(cfg, a); !ok || tiers.CatalogModels == nil {
		t.Fatal("lost a confirmed empty catalog")
	}
	cfg.ProxyURL = "http://two.invalid"
	if _, ok := CachedCodexAccountTiersForConfig(cfg, a); ok {
		t.Fatal("cached manifest crossed egress routes")
	}
	a.ProxyURL = "http://one.invalid"
	if _, ok := CachedCodexAccountTiersForConfig(cfg, a); !ok {
		t.Fatal("account egress should take precedence over the instance egress")
	}
	a.Metadata["plan_type"] = "free"
	if _, ok := CachedCodexAccountTiersForConfig(cfg, a); ok {
		t.Fatal("cached manifest survived a plan change")
	}
}

func TestOAuthInstanceDefaultTier(t *testing.T) {
	a := &auth.Auth{ID: t.Name(), Provider: "codex", Metadata: map[string]any{"access_token": "fixture", "account_id": "a"}}
	for _, tc := range []struct {
		setting, request, model, want string
		override                      bool
	}{
		{"fast", "", "m1", "", false},
		{"fast", "", "m2", "priority", false},
		{"ultrafast", "", "m1", "ultrafast", false},
		{"ultrafast", "", "m2", "priority", false},
		{"ultrafast", "", "m3", "", false},
		{"fast", "default", "m1", "default", false},
		{"inherit", "fast", "m1", "", false},
		{"inherit", "fast", "m2", "priority", false},
		{"inherit", "ultrafast", "m2", "priority", false},
		{"inherit", "ultrafast", "m1", "ultrafast", false},
		{"inherit", "", "m1", "", false},
		{"ultrafast", "priority", "m1", "", false},
		{"ultrafast", "fast", "m2", "priority", false},
		{"fast", "", "m1", "default", true},
	} {
		cfg := &config.Config{}
		enabled := true
		var item config.PluginInstanceConfig
		if err := yaml.Unmarshal([]byte("enabled: true\ndefault_tier: "+tc.setting), &item); err != nil {
			t.Fatal(err)
		}
		cfg.Plugins.Enabled = enabled
		cfg.Plugins.Configs = map[string]config.PluginInstanceConfig{"cpa-oauth": item}
		if tc.override {
			cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"service_tier": "default"}}}
		}
		key := tierCacheKey(cfg, a)
		tierCache.Lock()
		tierCache.entries[key] = tierCacheEntry{tiers: CodexAccountTiers{FastModels: []string{"m2"}, UltrafastModels: []string{"m1"}}, expires: time.Now().Add(time.Hour)}
		tierCache.Unlock()
		t.Cleanup(func() { tierCache.Lock(); delete(tierCache.entries, key); tierCache.Unlock() })
		doc := ojson.NewDocString("{}")
		_ = doc.Set("model", tc.model)
		if tc.request != "" {
			_ = doc.Set("service_tier", tc.request)
		}
		req := ex.Request{Model: tc.model, Payload: doc.Bytes()}
		f := NewCodexPayloadFinalizer(context.Background(), cfg, "codex", tc.model, "codex", "", doc.Bytes(), req, ex.Options{}, a)
		f.FinalizeDoc(doc)
		if tc.request == "default" {
			translated := ojson.NewDocString(`{}`)
			_ = translated.Set("model", tc.model)
			finalize := NewCodexPayloadFinalizer(context.Background(), cfg, "codex", tc.model, "codex", "", translated.Bytes(), req, ex.Options{}, a)
			finalize.FinalizeDoc(translated)
			if translated.Get("service_tier").Exists() {
				t.Fatal("explicit standard tier was upgraded after translation")
			}
		}
		if got := doc.Get("service_tier").String(); got != tc.want {
			t.Errorf("%+v got %q", tc, got)
		}
	}
}

func TestOAuthAccountTierLazyDiscoveryAndTranslation(t *testing.T) {
	cfg := &config.Config{}
	var item config.PluginInstanceConfig
	if err := yaml.Unmarshal([]byte("enabled: true\ndefault_tier: ultrafast"), &item); err != nil {
		t.Fatal(err)
	}
	cfg.Plugins.Enabled = true
	cfg.Plugins.Configs = map[string]config.PluginInstanceConfig{"cpa-oauth": item}
	a := &auth.Auth{ID: t.Name(), Provider: "codex", Metadata: map[string]any{"access_token": "test", "account_id": "a"}}
	for _, tc := range []struct {
		name, raw, original, body, want string
		fail, discover                  bool
	}{
		{"ordinary tier translated away", `{"service_tier":"default"}`, `{}`, `{}`, "", false, false},
		{"prepared body has its own standard tier", `{}`, `{}`, `{"service_tier":"default"}`, "default", false, false},
		{"removed translated tier stays removed", `{}`, `{"service_tier":"priority"}`, `{}`, "", false, false},
		{"translated request precedes default", `{"speed":"fast"}`, `{}`, `{"service_tier":"priority"}`, "priority", false, true},
		{"default applies to omitted tier", `{}`, `{}`, `{}`, "ultrafast", false, true},
		{"failure for requested tier", `{}`, `{}`, `{"service_tier":"priority"}`, "", true, true},
		{"failure for instance default", `{}`, `{}`, `{}`, "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := accountTierRule(context.Background(), cfg, a)
			calls := 0
			policy.discover = func() (CodexAccountTiers, error) {
				calls++
				if tc.fail {
					return CodexAccountTiers{}, errors.New("test manifest unavailable")
				}
				return CodexAccountTiers{FastModels: []string{"m"}, UltrafastModels: []string{"m"}}, nil
			}
			key := tierCacheKey(cfg, a)
			if _, ok := cachedTiers(key); ok {
				t.Fatal("unexpected manifest lookup during policy construction")
			}
			doc := ojson.NewDocString(tc.body)
			policy.captureClientTier([]byte(tc.raw), nil)
			policy.apply(doc, []byte(tc.original), "m")
			if got := doc.Get("service_tier").String(); got != tc.want || (calls > 0) != tc.discover {
				t.Errorf("tier = %q, manifest calls = %d", got, calls)
			}
		})
	}
}

func TestOAuthAccountTierExcludedPlans(t *testing.T) {
	data := []byte(`{"models":[
	  {"slug":"paid","available_in_plans":["pro"],"service_tiers":[{"id":"priority"},{"id":"ultrafast"}]},
	  {"slug":"shared","service_tiers":[{"id":"priority"},{"id":"ultrafast","available_in_plans":["pro"]}]},
	  {"slug":"inactive","available_in_plans":[],"service_tiers":[{"id":"fast"}]}
	]}`)
	got, err := parseCodexAccountTiers(data, time.Now(), "free")
	if err != nil || !slices.Equal(got.FastModels, []string{"shared"}) || len(got.UltrafastModels) != 0 {
		t.Fatalf("unexpected free tiers: %+v, err %v", got, err)
	}
	got, err = parseCodexAccountTiers(data, time.Now(), "pro")
	if err != nil || !slices.Equal(got.FastModels, []string{"paid", "shared"}) || !slices.Equal(got.UltrafastModels, []string{"paid", "shared"}) {
		t.Fatalf("unexpected pro tiers: %+v, err %v", got, err)
	}
}
