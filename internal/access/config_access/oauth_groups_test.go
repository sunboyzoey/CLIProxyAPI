package configaccess

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestConfiguredKeyGroupsUseAuthenticatedKey(t *testing.T) {
	cfg := &config.SDKConfig{
		APIKeys:        []string{"first", "second"},
		OAuthKeyGroups: map[string]string{config.OAuthKeyFingerprint("first"): "alpha"},
	}
	if err := cfg.ValidateOAuthKeyGroups(); err != nil {
		t.Fatal(err)
	}
	Register(cfg)
	t.Cleanup(func() { Register(nil) })
	manager := access.NewManager()
	manager.SetProviders(access.RegisteredProviders())
	for key, want := range map[string]string{"first": "alpha", "second": "default", "unknown": ""} {
		req := httptest.NewRequest("GET", "/v1/models", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("X-OAuth-Group", "beta")
		got, err := manager.Authenticate(context.Background(), req)
		if want == "" {
			if err == nil || got != nil {
				t.Fatal("unknown key accepted")
			}
			continue
		}
		if err != nil || got == nil || got.Metadata[access.OAuthAccountGroup] != want {
			t.Fatalf("group = %v, err = %v", got, err)
		}
	}
	cfg.APIKeys = []string{"second"}
	if g := cfg.OAuthGroupForKey("first"); g != "" {
		t.Fatalf("revoked issuer retained group %q", g)
	}
}

func TestNamedKeyAccountAssignments(t *testing.T) {
	const alice, bob = "key-a", "key-b"
	cfg := &config.SDKConfig{APIKeys: []string{alice, bob}, OAuthKeySelection: true,
		OAuthKeyGroups: map[string]string{config.OAuthKeyFingerprint(bob): "legacy"}}
	a := &auth.Auth{Provider: "codex", Metadata: map[string]any{"type": "codex", "access_token": "fixture"}}
	for _, tc := range []struct {
		group        any
		wantA, wantB bool
	}{
		{nil, true, true}, {"default", true, true}, {"key:" + config.OAuthKeyFingerprint(alice), true, false},
		{"key:" + config.OAuthKeyFingerprint(bob), false, true}, {"legacy", false, true},
	} {
		a.Metadata["oauth_group"] = tc.group
		if a.InOAuthGroup(cfg.OAuthRoutingGroup(alice)) != tc.wantA || a.InOAuthGroup(cfg.OAuthRoutingGroup(bob)) != tc.wantB {
			t.Fatalf("unexpected eligibility for group %v", tc.group)
		}
	}
	if cfg.OAuthRoutingGroup("removed") != "" {
		t.Fatal("removed key received a routing scope")
	}
	if err := auth.ValidateCodexAccountField("oauth_group", "key:invalid"); err == nil {
		t.Fatal("accepted malformed key assignment")
	}
	if (&auth.Auth{Provider: "claude"}).InOAuthGroup(cfg.OAuthRoutingGroup(alice)) {
		t.Fatal("non-Codex credential matched")
	}
}
