package pluginhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type bpsDisableTestStore struct {
	*sdkauth.FileTokenStore
	saves atomic.Int64
	fail  atomic.Bool
}

func (s *bpsDisableTestStore) Save(ctx context.Context, a *coreauth.Auth) (string, error) {
	s.saves.Add(1)
	if s.fail.Load() {
		return "", errors.New("secret persistence detail")
	}
	return s.FileTokenStore.Save(ctx, a)
}

func bpsDisableFixture(t *testing.T) (*Host, *coreauth.Manager, *coreauth.Auth, *bpsDisableTestStore, string) {
	t.Helper()
	dir := t.TempDir()
	store := &bpsDisableTestStore{FileTokenStore: sdkauth.NewFileTokenStore()}
	store.SetBaseDir(dir)
	manager := coreauth.NewManager(store, nil, nil)
	host := New()
	host.SetAuthManager(manager)
	a, errRegister := manager.Register(context.Background(), &coreauth.Auth{
		ID: "bps.json", FileName: "bps.json", Provider: "bps", Status: coreauth.StatusActive,
		ProxyURL: "socks5://account-proxy:1080", Metadata: bpsProbeTestMetadata(),
	})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	store.saves.Store(0)
	return host, manager, a, store, filepath.Join(dir, "bps.json")
}

func bpsDisableRequest() *ojson.Doc {
	doc := ojson.NewDocString(`{"auth_id":"bps.json","expected_account_id":"account-one","expected_subject":"subject-one","reason_code":"request_rejected","detected_at":"2026-11-06T10:17:47.618316Z","request_id":"request-123"}`)
	return doc
}

func TestHostBPSDisablePreservesCurrentCredentialsAndPersistsReason(t *testing.T) {
	h, m, base, store, path := bpsDisableFixture(t)
	fresh := base.Clone()
	fresh.Metadata["refresh_token"] = "fresh-rt"
	fresh.Metadata["access_token"] = strings.Replace(base.Metadata["access_token"].(string), ".signature", ".fresh-signature", 1)
	fresh.Metadata["max_concurrent"] = 40
	if _, errRefresh := m.UpdateRefreshedAuth(context.Background(), base, fresh); errRefresh != nil {
		t.Fatal(errRefresh)
	}
	store.saves.Store(0)
	raw, errCall := h.callFromPlugin(withHostCallbackPluginID(context.Background(), "bps"), "host.auth.bps_disable", bpsDisableRequest().Bytes())
	if errCall != nil || !ojson.GetBytes(raw, "result.disabled").Bool() {
		t.Fatalf("disable callback failed: %v", errCall)
	}
	current, _ := m.GetByID(base.ID)
	if !current.Disabled || current.Status != coreauth.StatusDisabled || current.Metadata["refresh_token"] != "fresh-rt" || current.Metadata["access_token"] != fresh.Metadata["access_token"] || current.Metadata["max_concurrent"] != 40 || current.ProxyURL != base.ProxyURL {
		t.Fatal("disable changed credential material or account settings")
	}
	if current.StatusMessage != bpsPolicyDisableReason || current.Metadata["bps_auto_disable_code"] != "request_rejected" || current.Metadata["bps_auto_disable_request_id"] != "request-123" {
		t.Fatal("safe disable reason was not recorded")
	}
	disk, errRead := os.ReadFile(path)
	if errRead != nil || !ojson.GetBytes(disk, "disabled").Bool() || ojson.GetBytes(disk, "refresh_token").String() != "fresh-rt" || ojson.GetBytes(disk, "bps_auto_disable_code").String() != "request_rejected" {
		t.Fatal("disabled state and fresh credential were not persisted")
	}
	if strings.Contains(string(raw), "fresh-rt") || strings.Contains(string(raw), "access_token") || store.saves.Load() != 1 {
		t.Fatal("callback leaked credentials or wrote more than once")
	}
}

func TestHostBPSDisableKeepsConcurrentRefreshAndFirstReason(t *testing.T) {
	h, m, base, store, _ := bpsDisableFixture(t)
	ctx := withHostCallbackPluginID(context.Background(), "bps")
	start := make(chan struct{})
	var group sync.WaitGroup
	errs := make(chan error, 25)
	for i := 0; i < 25; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, errCall := h.callFromPlugin(ctx, "host.auth.bps_disable", bpsDisableRequest().Bytes())
			errs <- errCall
		}()
	}
	close(start)
	group.Wait()
	close(errs)
	for errCall := range errs {
		if errCall != nil {
			t.Fatal(errCall)
		}
	}
	if store.saves.Load() != 1 {
		t.Fatalf("concurrent duplicates persisted %d times", store.saves.Load())
	}
	// This refresh began before the rejection. Its commit must retain the
	// concurrent disabled state while still adopting the new credentials.
	fresh := base.Clone()
	fresh.Metadata["refresh_token"] = "rotated-rt"
	fresh.Metadata["access_token"] = strings.Replace(base.Metadata["access_token"].(string), ".signature", ".rotated-signature", 1)
	fresh.LastRefreshedAt = time.Now()
	if _, errRefresh := m.UpdateRefreshedAuth(context.Background(), base, fresh); errRefresh != nil {
		t.Fatal(errRefresh)
	}
	current, _ := m.GetByID(base.ID)
	if !current.Disabled || current.Status != coreauth.StatusDisabled || current.Metadata["refresh_token"] != "rotated-rt" || current.Metadata["bps_auto_disable_request_id"] != "request-123" {
		t.Fatal("late refresh cleared disable or lost refreshed credentials")
	}
	doc := bpsDisableRequest()
	_ = doc.Set("detected_at", "2026-11-06T11:00:00Z")
	_ = doc.Set("request_id", "later-request")
	if _, errCall := h.callFromPlugin(ctx, "host.auth.bps_disable", doc.Bytes()); errCall != nil {
		t.Fatal(errCall)
	}
	current, _ = m.GetByID(base.ID)
	if current.Metadata["bps_auto_disable_request_id"] != "request-123" || current.Metadata["bps_auto_disabled_at"] != "2026-11-06T10:17:47.618316Z" {
		t.Fatal("duplicate rejection overwrote first evidence")
	}
}

func TestHostBPSDisableRejectsUnsafeRequests(t *testing.T) {
	for _, scenario := range []string{"missing_caller", "other_plugin", "wrong_account", "wrong_subject", "wrong_auth", "native", "bad_reason", "invalid_time", "unsafe_request_id", "malformed", "missing_subject", "api_key"} {
		t.Run(scenario, func(t *testing.T) {
			h, m, a, store, _ := bpsDisableFixture(t)
			doc := bpsDisableRequest()
			ctx := withHostCallbackPluginID(context.Background(), "bps")
			switch scenario {
			case "missing_caller":
				ctx = context.Background()
			case "other_plugin":
				ctx = withHostCallbackPluginID(context.Background(), "other")
			case "wrong_account":
				_ = doc.Set("expected_account_id", "other")
			case "wrong_subject":
				_ = doc.Set("expected_subject", "other")
			case "missing_subject":
				_ = doc.Delete("expected_subject")
			case "wrong_auth":
				_ = doc.Set("auth_id", "missing.json")
			case "native", "api_key":
				_, _, errModify := m.Modify(context.Background(), a.ID, a.RegistrationEpoch, func(current *coreauth.Auth) error {
					if scenario == "native" {
						current.Provider = "codex"
					} else {
						current.Metadata["api_key"] = "not-oauth"
					}
					return nil
				})
				if errModify != nil {
					t.Fatal(errModify)
				}
			case "bad_reason":
				_ = doc.Set("reason_code", "server_error")
			case "invalid_time":
				_ = doc.Set("detected_at", "invalid")
			case "unsafe_request_id":
				_ = doc.Set("request_id", "secret\nvalue")
			}
			store.saves.Store(0)
			request := doc.Bytes()
			if scenario == "malformed" {
				request = []byte(`{`)
			}
			if _, errCall := h.callFromPlugin(ctx, "host.auth.bps_disable", request); errCall == nil {
				t.Fatal("unsafe request accepted")
			}
			current, _ := m.GetByID(a.ID)
			if current.Disabled || store.saves.Load() != 0 {
				t.Fatal("unsafe request mutated credential")
			}
		})
	}
}

func TestHostBPSDisableReturnsSafePersistenceError(t *testing.T) {
	h, m, a, store, _ := bpsDisableFixture(t)
	store.fail.Store(true)
	_, errCall := h.callFromPlugin(withHostCallbackPluginID(context.Background(), "bps"), "host.auth.bps_disable", bpsDisableRequest().Bytes())
	if errCall == nil || strings.Contains(errCall.Error(), "secret") {
		t.Fatalf("expected safe persistence error, got %v", errCall)
	}
	current, _ := m.GetByID(a.ID)
	if current.Disabled {
		t.Fatal("failed persistence was published as a committed disable")
	}
	store.fail.Store(false)
	if _, errRetry := h.callFromPlugin(withHostCallbackPluginID(context.Background(), "bps"), "host.auth.bps_disable", bpsDisableRequest().Bytes()); errRetry != nil {
		t.Fatal("retry after persistence recovery failed", errRetry)
	}
}
