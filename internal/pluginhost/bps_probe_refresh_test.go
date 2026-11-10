package pluginhost

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestBPSProbeRefreshUsesEffectiveProxyWithoutPersistingFallback(t *testing.T) {
	for _, scenario := range []struct {
		name, account, global, fallback, want string
		stored                                bool
		invalid                               bool
	}{
		{"account", "http://account:7890", "http://global:7890", "http://fallback:7890", "http://account:7890", true, false},
		{"global", "", "http://global:7890", "http://fallback:7890", "http://global:7890", false, false},
		{"fallback", "", "", "socks5h://fallback:7890", "socks5h://fallback:7890", false, false},
		{"empty_stored", "", "http://global:7890", "", "http://global:7890", true, false},
		{"default_route", "", "", "", "", false, false},
		{"empty_stored_default_route", "", "", "", "", true, false},
		{"bad_account", "direct://", "http://global:7890", "", "", true, true},
		{"bad_global", "", "direct://", "http://fallback:7890", "", false, true},
		{"bad_fallback", "", "", "invalid-proxy", "", false, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			provider := fakeAuthProvider{identifier: "bps", refreshAuth: func(_ context.Context, request pluginapi.AuthRefreshRequest) (pluginapi.AuthRefreshResponse, error) {
				calls++
				if scenario.invalid || !ojson.GetBytes(request.StorageJSON, "proxy_url").Exists() || ojson.GetBytes(request.StorageJSON, "proxy_url").String() != scenario.want || request.Metadata["proxy_url"] != scenario.want || request.HTTPClient == nil {
					t.Error("refresh ignored the effective probe proxy")
				}
				metadata := cloneAnyMap(request.Metadata)
				metadata["access_token"] = strings.Replace(metadata["access_token"].(string), ".signature", ".rotated", 1)
				metadata["refresh_token"] = "rotated-rt"
				metadata["expired"] = time.Now().Add(time.Hour).Format(time.RFC3339)
				doc := ojson.NewDoc(request.StorageJSON)
				for _, key := range []string{"access_token", "refresh_token", "expired"} {
					if err := doc.Set(key, metadata[key]); err != nil {
						t.Fatal(err)
					}
				}
				return pluginapi.AuthRefreshResponse{Auth: pluginapi.AuthData{Provider: "bps", ProxyURL: scenario.want, StorageJSON: doc.Bytes(), Metadata: metadata}}, nil
			}}
			executorRecord := normalizeTestCapabilityRecord(capabilityRecord{id: "bps-executor"})
			h := newHostWithRecords(capabilityRecord{id: "bps-auth", plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{AuthProvider: provider}}}, executorRecord)
			h.runtimeConfig = &config.Config{}
			h.runtimeConfig.ProxyURL = scenario.global
			adapter := newExecutorAdapterForRecordForTest(h, executorRecord, &fakeExecutor{}, nil, nil)
			adapter.provider = "bps"
			manager := coreauth.NewManager(nil, nil, nil)
			manager.RegisterExecutor(adapter)
			h.SetAuthManager(manager)
			metadata := bpsProbeTestMetadata()
			metadata["expired"] = time.Now().Add(-time.Hour).Format(time.RFC3339)
			if scenario.stored {
				metadata["proxy_url"] = scenario.account
			}
			auth, err := manager.Register(context.Background(), &coreauth.Auth{ID: "probe.json", Provider: "bps", ProxyURL: scenario.account, Metadata: metadata})
			if err != nil {
				t.Fatal(err)
			}
			doc := ojson.NewDocString(`{}`)
			_ = doc.Set("auth_index", auth.Index)
			_ = doc.Set("expected_auth_id", auth.ID)
			_ = doc.Set("fallback_proxy_url", scenario.fallback)
			raw, err := h.callHostBPSProbeCredentials(context.Background(), doc.Bytes())
			if scenario.invalid {
				if err == nil || err.Error() != "bps_probe_proxy_invalid" || calls != 0 {
					t.Fatalf("invalid proxy reached refresh: %v, calls=%d", err, calls)
				}
				return
			}
			if err != nil || calls != 1 || ojson.GetBytes(raw, "result.proxy_url").String() != scenario.want {
				t.Fatalf("probe preparation failed: %v, calls=%d", err, calls)
			}
			current, _ := manager.GetByID(auth.ID)
			value, exists := current.Metadata["proxy_url"]
			stored := ojson.GetBytes(storageJSONFromAuth(current), "proxy_url")
			// CPA's standard metadata merger omits an empty proxy value; the
			// original storage representation must still survive the refresh.
			wantMetadata := scenario.stored && scenario.account != ""
			if current.ProxyURL != scenario.account || exists != wantMetadata || stored.Exists() != scenario.stored || (wantMetadata && value != scenario.account) || (scenario.stored && stored.String() != scenario.account) {
				t.Fatalf("temporary proxy changed stored settings: account=%q metadata=%v/%v storage=%q/%v", current.ProxyURL, value, exists, stored.String(), stored.Exists())
			}
			if current.Metadata["refresh_token"] != "rotated-rt" || !strings.HasSuffix(current.Metadata["access_token"].(string), ".rotated") {
				t.Fatal("restoring proxy lost token rotation")
			}
			originalValue, originalExists := metadata["proxy_url"]
			if metadata["refresh_token"] != "secret-rt" || originalExists != scenario.stored || (scenario.stored && originalValue != scenario.account) {
				t.Fatal("refresh mutated the original credential map")
			}
		})
	}
}

func TestBPSProbeProxyDoesNotChangeOrdinaryRefresh(t *testing.T) {
	provider := fakeAuthProvider{identifier: "bps", refreshAuth: func(_ context.Context, request pluginapi.AuthRefreshRequest) (pluginapi.AuthRefreshResponse, error) {
		if _, exists := request.Metadata["proxy_url"]; exists || ojson.GetBytes(request.StorageJSON, "proxy_url").Exists() {
			t.Fatal("ordinary refresh received a probe proxy")
		}
		return pluginapi.AuthRefreshResponse{Auth: pluginapi.AuthData{Provider: "bps", ProxyURL: "http://new:7890", Metadata: map[string]any{"access_token": "new", "proxy_url": "http://new:7890"}, StorageJSON: []byte(`{"access_token":"new","proxy_url":"http://new:7890"}`)}}, nil
	}}
	record := normalizeTestCapabilityRecord(capabilityRecord{id: "bps-executor"})
	h := newHostWithRecords(capabilityRecord{id: "bps-auth", plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{AuthProvider: provider}}}, record)
	h.runtimeConfig = &config.Config{}
	h.runtimeConfig.ProxyURL = "http://global:7890"
	adapter := newExecutorAdapterForRecordForTest(h, record, &fakeExecutor{}, nil, nil)
	auth, err := adapter.Refresh(context.Background(), &coreauth.Auth{ID: "ordinary", Provider: "bps", Metadata: bpsProbeTestMetadata()})
	if err != nil || auth.ProxyURL != "http://new:7890" || ojson.GetBytes(storageJSONFromAuth(auth), "proxy_url").String() != "http://new:7890" {
		t.Fatalf("ordinary refresh behavior changed: %v", err)
	}
}
