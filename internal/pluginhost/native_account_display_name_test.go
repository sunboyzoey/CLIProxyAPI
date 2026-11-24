package pluginhost

import (
	"context"
	"strings"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestNativeOAuthInventoryDisplayName(t *testing.T) {
	const access = `{"sub":"subject","https://api.openai.com/auth":{"chatgpt_account_id":"account"}}`
	const profile = `{"sub":"subject","https://api.openai.com/auth":{"chatgpt_account_id":"account"},"https://api.openai.com/profile":{"name":"  Profile name  ","unrelated":"internal-profile-value"}}`
	const id = `{"sub":"subject","https://api.openai.com/auth":{"chatgpt_account_id":"account"},"name":"Identity name"}`
	const email = "person@example.test"
	const filename = "account-file.json"

	token := func(payload string) string {
		return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
	}
	for _, tc := range []struct {
		label, access, id, email, expected string
	}{
		{"profile", profile, id, email, "Profile name"},
		{"id name", access, id, email, "Identity name"},
		{"subject-only id token", access, `{"sub":"subject","name":"World Name"}`, email, "World Name"},
		{"different subject", access, `{"sub":"other","name":"Wrong"}`, email, email},
		{"different account", access, `{"sub":"subject","https://api.openai.com/auth":{"chatgpt_account_id":"other"},"name":"Wrong"}`, email, email},
		{"unusable claims", access, `{"sub":"subject","name":{"private":"internal-profile-value"}}`, email, email},
		{"profile email", `{"sub":"subject","https://api.openai.com/profile":{"email":"profile@example.test"}}`, "{}", "", "profile@example.test"},
		{"id email", access, `{"sub":"subject","email":"id@example.test"}`, "", "id@example.test"},
		{"no usable token", "invalid", id, email, email},
		{"missing names", access, "{}", "", filename},
	} {
		t.Run(tc.label, func(t *testing.T) {
			host := New()
			manager := coreauth.NewManager(nil, nil, nil)
			host.SetAuthManager(manager)
			accessToken, idToken := token(tc.access), token(tc.id)
			a, err := manager.Register(context.Background(), &coreauth.Auth{
				ID: "directory/" + filename, FileName: filename, Provider: "codex",
				Metadata: map[string]any{"access_token": accessToken, "id_token": idToken, "email": tc.email},
			})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := host.nativeOAuthInventory()
			if err != nil {
				t.Fatal(err)
			}
			row := ojson.GetBytes(raw, "result.accounts.0")
			if got := row.Get("display_name").Str; got != tc.expected {
				t.Errorf("display name = %q, want %q", got, tc.expected)
			}
			identity, _, _ := coreauth.NativeCodexIdentity(a)
			if row.Get("name").Str != filename || row.Get("auth_id").Str != a.ID || row.Get("identity").Str != identity {
				t.Error("inventory lost the source filename or credential identifiers")
			}
			for _, secret := range []string{accessToken, idToken, "internal-profile-value"} {
				if strings.Contains(string(raw), secret) {
					t.Fatal("inventory contains unrelated grant data")
				}
			}
		})
	}
}
