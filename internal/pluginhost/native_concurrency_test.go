package pluginhost

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func nativeConcurrencyHostFixture(t *testing.T) (*Host, *coreauth.Manager, *ojson.Doc, *bpsDisableTestStore, string) {
	t.Helper()
	dir := t.TempDir()
	store := &bpsDisableTestStore{FileTokenStore: sdkauth.NewFileTokenStore()}
	store.SetBaseDir(dir)
	manager := coreauth.NewManager(store, nil, nil)
	host := New()
	host.SetAuthManager(manager)
	token := "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"subject","https://api.openai.com/auth":{"chatgpt_account_id":"account"}}`)) + ".fixture"
	auth, err := manager.Register(t.Context(), &coreauth.Auth{ID: "native.json", FileName: "native.json", Provider: "codex", Metadata: map[string]any{"type": "codex", "access_token": token, "refresh_token": "synthetic-private-refresh", "account_id": "account", "max_concurrent": 1}})
	if err != nil {
		t.Fatal(err)
	}
	doc := ojson.NewDocString(`{"expected_account_id":"account","expected_subject":"subject","max_concurrent":3}`)
	_ = doc.Set("auth_index", auth.Index)
	_ = doc.Set("expected_auth_id", auth.ID)
	return host, manager, doc, store, filepath.Join(dir, "native.json")
}

func TestHostNativeConcurrencyDurableSettingsAndIdentity(t *testing.T) {
	host, manager, doc, _, path := nativeConcurrencyHostFixture(t)
	ctx := withHostCallbackPluginID(t.Context(), "bps")
	raw, err := host.callFromPlugin(ctx, "host.auth.native_concurrency_set", doc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if ojson.GetBytes(raw, "result.max_concurrent").Int() != 3 || !ojson.GetBytes(raw, "result.supported").Bool() {
		t.Fatal("missing committed concurrency setting")
	}
	if strings.Contains(string(raw), "access_token") || strings.Contains(string(raw), "refresh_token") || strings.Contains(string(raw), "synthetic-private-refresh") {
		t.Fatal("callback leaked credentials")
	}
	stored, err := os.ReadFile(path)
	if err != nil || ojson.GetBytes(stored, "max_concurrent").Int() != 3 {
		t.Fatal("concurrency setting not persisted")
	}
	reloadedStore := sdkauth.NewFileTokenStore()
	reloadedStore.SetBaseDir(filepath.Dir(path))
	reloaded := coreauth.NewManager(reloadedStore, nil, nil)
	if errLoad := reloaded.Load(t.Context()); errLoad != nil {
		t.Fatal(errLoad)
	}
	if reloaded.NativeConcurrency("native.json").MaxConcurrent != 3 {
		t.Fatal("concurrency setting did not survive reload")
	}
	auth, _ := manager.GetByID("native.json")
	before := auth.Metadata["refresh_token"]
	_ = doc.Set("expected_subject", "replacement-subject")
	if _, err = host.callFromPlugin(ctx, "host.auth.native_concurrency_set", doc.Bytes()); err == nil {
		t.Fatal("accepted wrong subject")
	}
	auth, _ = manager.GetByID("native.json")
	if auth.Metadata["refresh_token"] != before || manager.NativeConcurrency(auth.ID).MaxConcurrent != 3 {
		t.Fatal("identity mismatch mutated credential")
	}
}

func TestHostNativeConcurrencyPersistenceFailureAndValidation(t *testing.T) {
	host, manager, doc, store, _ := nativeConcurrencyHostFixture(t)
	ctx := withHostCallbackPluginID(t.Context(), "bps")
	if _, err := host.callFromPlugin(withHostCallbackPluginID(t.Context(), "other"), "host.auth.native_concurrency_set", doc.Bytes()); err == nil {
		t.Fatal("accepted another plugin's setting mutation")
	}
	store.fail.Store(true)
	if _, err := host.callFromPlugin(ctx, "host.auth.native_concurrency_set", doc.Bytes()); err == nil || strings.Contains(err.Error(), "secret persistence") {
		t.Fatal("persistence failure was accepted or leaked")
	}
	if manager.NativeConcurrency("native.json").MaxConcurrent != 1 {
		t.Fatal("failed write changed runtime limit")
	}
	store.fail.Store(false)
	for _, value := range []any{-1, 1.5, "3", 10001, nil} {
		_ = doc.Set("max_concurrent", value)
		if _, err := host.callFromPlugin(ctx, "host.auth.native_concurrency_set", doc.Bytes()); err == nil {
			t.Fatalf("accepted invalid limit %v", value)
		}
	}
	_ = doc.Set("max_concurrent", 0)
	if _, err := host.callFromPlugin(ctx, "host.auth.native_concurrency_set", doc.Bytes()); err != nil {
		t.Fatal(err)
	}
	if manager.NativeConcurrency("native.json").MaxConcurrent != 0 {
		t.Fatal("zero did not disable limiting")
	}
}

func TestHostNativeConcurrencyListIsolatesAccountErrors(t *testing.T) {
	host, _, doc, _, _ := nativeConcurrencyHostFixture(t)
	list := ojson.NewDocString(`{"accounts":[]}`)
	_ = list.SetRaw("accounts.0", doc.String())
	_ = doc.Set("expected_subject", "changed")
	_ = list.SetRaw("accounts.1", doc.String())
	raw, err := host.callFromPlugin(context.Background(), "host.auth.native_concurrency_list", list.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !ojson.GetBytes(raw, "result.supported").Bool() || !ojson.GetBytes(raw, "result.accounts.0.supported").Bool() || ojson.GetBytes(raw, "result.accounts.1.error").String() == "" {
		t.Fatal("batch did not isolate wrong identity")
	}
}

func TestHostNativeSettingsCommitAllFieldsAtomically(t *testing.T) {
	host, manager, doc, store, path := nativeConcurrencyHostFixture(t)
	ctx := withHostCallbackPluginID(t.Context(), "bps")
	_ = doc.Set("proxy_url", " socks5h://127.0.0.1:1080 ")
	_ = doc.Set("priority", 7)
	store.saves.Store(0)
	if _, err := host.callFromPlugin(ctx, "host.auth.native_concurrency_set", doc.Bytes()); err != nil {
		t.Fatal(err)
	}
	current, _ := manager.GetByID("native.json")
	if current.ProxyURL != "socks5h://127.0.0.1:1080" || current.Attributes["priority"] != "7" || manager.NativeConcurrency(current.ID).MaxConcurrent != 3 {
		t.Fatal("settings did not publish together")
	}
	if store.saves.Load() != 1 {
		t.Fatalf("atomic settings performed %d saves", store.saves.Load())
	}
	raw, err := os.ReadFile(path)
	if err != nil || ojson.GetBytes(raw, "proxy_url").String() != current.ProxyURL || ojson.GetBytes(raw, "priority").Int() != 7 || ojson.GetBytes(raw, "max_concurrent").Int() != 3 {
		t.Fatal("settings did not persist together")
	}
	_ = doc.Set("max_concurrent", 9)
	_ = doc.Set("proxy_url", "direct")
	_ = doc.Set("priority", 2)
	store.fail.Store(true)
	if _, err = host.callFromPlugin(ctx, "host.auth.native_concurrency_set", doc.Bytes()); err == nil {
		t.Fatal("failed atomic write was accepted")
	}
	current, _ = manager.GetByID("native.json")
	if current.ProxyURL != "socks5h://127.0.0.1:1080" || current.Attributes["priority"] != "7" || manager.NativeConcurrency(current.ID).MaxConcurrent != 3 {
		t.Fatal("failed write partially changed settings")
	}
	store.fail.Store(false)
	_ = doc.Set("proxy_url", "invalid://proxy")
	store.saves.Store(0)
	if _, err = host.callFromPlugin(ctx, "host.auth.native_concurrency_set", doc.Bytes()); err == nil || store.saves.Load() != 0 {
		t.Fatal("invalid proxy partially committed settings")
	}
	_ = doc.Set("proxy_url", "none")
	_ = doc.Set("priority", 1.5)
	if _, err = host.callFromPlugin(ctx, "host.auth.native_concurrency_set", doc.Bytes()); err == nil || store.saves.Load() != 0 {
		t.Fatal("invalid priority partially committed settings")
	}
	_ = doc.Delete("max_concurrent")
	_ = doc.Delete("priority")
	for _, proxy := range []string{"none", "direct", ""} {
		_ = doc.Set("proxy_url", proxy)
		if _, err = host.callFromPlugin(ctx, "host.auth.native_concurrency_set", doc.Bytes()); err != nil {
			t.Fatal(err)
		}
		current, _ = manager.GetByID("native.json")
		if current.ProxyURL != proxy || manager.NativeConcurrency(current.ID).MaxConcurrent != 3 || current.Attributes["priority"] != "7" {
			t.Fatal("proxy-only update changed omitted settings")
		}
	}
	_ = doc.Delete("proxy_url")
	_ = doc.Set("priority", -3)
	if _, err = host.callFromPlugin(ctx, "host.auth.native_concurrency_set", doc.Bytes()); err != nil {
		t.Fatal(err)
	}
	current, _ = manager.GetByID("native.json")
	if current.Attributes["priority"] != "-3" {
		t.Fatal("priority-only update missing")
	}
}
