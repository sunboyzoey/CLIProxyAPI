package helps

import (
	"context"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestOAuthAccountTierEntitlementsAndPayloadFilter(t *testing.T) {
	tiers, err := parseCodexAccountTiers([]byte(`{"models":[{"slug":"sol","service_tiers":[{"id":"priority"},{"id":"ultrafast"}]},{"slug":"astra","service_tiers":[{"id":"fast"}]},{"slug":"plain"}]}`), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parseCodexAccountTiers([]byte(`{"error":{}}`), time.Now()); err == nil {
		t.Fatal("invalid manifest accepted")
	}
	a := &auth.Auth{ID: t.Name(), Provider: "codex", Metadata: map[string]any{"access_token": "test", "account_id": "a", "service_tier": "ultrafast"}}
	key := tierCacheKey(a)
	tierCache.Lock()
	tierCache.entries[key] = tierCacheEntry{tiers: tiers, expires: time.Now().Add(time.Hour)}
	tierCache.Unlock()
	t.Cleanup(func() { tierCache.Lock(); delete(tierCache.entries, key); tierCache.Unlock() })
	for _, tt := range []struct {
		mode, model, want string
		filter            bool
	}{
		{"ultrafast", "sol", "ultrafast", false}, {"ultrafast", "astra", "priority", false}, {"ultrafast", "plain", "", false}, {"ultrafast", "absent", "", false}, {"fast", "sol", "priority", false}, {"inherit", "sol", "default", false}, {"ultrafast", "sol", "", true},
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
