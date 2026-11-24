package cliproxy

import (
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestOAuthDirectoryPrefixProvenance(t *testing.T) {
	a := &coreauth.Auth{Provider: "codex", Prefix: "one", Metadata: map[string]any{"access_token": "fixture"}}
	models := []*ModelInfo{{ID: "base"}, {ID: "one/base", DisplayName: "explicit"}, {ID: "brand/custom"}}
	for _, tc := range []struct {
		provider string
		force    bool
		want     map[string]bool
	}{
		{"codex", false, map[string]bool{"base": false, "one/base": false, "one/one/base": true, "brand/custom": false, "one/brand/custom": true}},
		{"codex", true, map[string]bool{"one/base": false, "one/one/base": false, "one/brand/custom": false}},
		{"gemini", false, map[string]bool{"base": false, "one/base": false, "one/one/base": false, "brand/custom": false, "one/brand/custom": false}},
	} {
		a.Provider = tc.provider
		result := applyAuthModelPrefixes(models, a, tc.force)
		if len(result) != len(tc.want) {
			t.Fatalf("%s force=%t: got %d routes", tc.provider, tc.force, len(result))
		}
		for _, model := range result {
			optional, ok := tc.want[model.ID]
			if !ok || model.OptionalOAuthPrefix != optional {
				t.Errorf("%s force=%t: %q optional %t", tc.provider, tc.force, model.ID, model.OptionalOAuthPrefix)
			}
			if tc.provider == "codex" && !tc.force && model.ID == "one/base" && model.DisplayName != "explicit" {
				t.Fatal("generated route displaced an explicit published ID")
			}
		}
	}
}
