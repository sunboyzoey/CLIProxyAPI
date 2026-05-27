package management

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestRemoveFaultyAuthFilesChecksAllOAuthAuthsAndRemoves401(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := &memoryAuthStore{items: make(map[string]*coreauth.Auth)}
	manager := coreauth.NewManager(store, nil, nil)
	validAuth := &coreauth.Auth{
		ID:       "codex-valid",
		Provider: "codex",
		Metadata: map[string]any{
			"email":        "valid@example.com",
			"access_token": "valid-token",
		},
	}
	expiredAuth := &coreauth.Auth{
		ID:       "codex-expired",
		Provider: "codex",
		Metadata: map[string]any{
			"email":        "expired@example.com",
			"access_token": "expired-token",
		},
	}
	apiKeyAuth := &coreauth.Auth{
		ID:       "codex-api-key",
		Provider: "codex",
		Metadata: map[string]any{
			"type": "codex",
		},
		Attributes: map[string]string{
			"api_key": "sk-test",
		},
	}
	for _, auth := range []*coreauth.Auth{validAuth, expiredAuth, apiKeyAuth} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("register %s: %v", auth.ID, errRegister)
		}
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer valid-token":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"plan_type":"plus","rate_limit":{}}`))
		case "Bearer expired-token":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"message":"token invalidated"}}`))
		default:
			t.Fatalf("unexpected authorization header %q", r.Header.Get("Authorization"))
		}
	}))
	defer upstream.Close()
	prevCodexUsageURL := faultSweepCodexUsageURL
	faultSweepCodexUsageURL = upstream.URL
	t.Cleanup(func() { faultSweepCodexUsageURL = prevCodexUsageURL })

	reloadMemory := true
	body, errMarshal := json.Marshal(removeFaultyAuthFilesRequest{ReloadMemory: &reloadMemory})
	if errMarshal != nil {
		t.Fatalf("marshal request: %v", errMarshal)
	}

	h := &Handler{authManager: manager}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/remove-faulty", bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.RemoveFaultyAuthFiles(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var resp removeFaultyAuthFilesResponse
	if errUnmarshal := json.Unmarshal(recorder.Body.Bytes(), &resp); errUnmarshal != nil {
		t.Fatalf("unmarshal response: %v", errUnmarshal)
	}
	if resp.Checked != 2 || resp.OK != 1 || resp.Removed401 != 1 || resp.Skipped != 1 || !resp.MemoryReloaded {
		t.Fatalf("unexpected response: %+v", resp)
	}

	if _, ok := manager.GetByID("codex-expired"); ok {
		t.Fatal("expired auth still present in manager")
	}
	if _, ok := manager.GetByID("codex-valid"); !ok {
		t.Fatal("valid auth missing from manager")
	}
	if _, ok := manager.GetByID("codex-api-key"); !ok {
		t.Fatal("api key auth should be skipped and retained")
	}

	storedAuths, errList := store.List(context.Background())
	if errList != nil {
		t.Fatalf("list store: %v", errList)
	}
	if len(storedAuths) != 2 {
		t.Fatalf("store auth count = %d, want 2", len(storedAuths))
	}
}
