package pluginhost

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type nativeProbeCredentials struct {
	AuthID         string    `json:"auth_id"`
	AuthIndex      string    `json:"auth_index"`
	Provider       string    `json:"provider"`
	AccessToken    string    `json:"access_token"`
	AccountID      string    `json:"account_id"`
	ProxyURL       string    `json:"proxy_url"`
	Disabled       bool      `json:"disabled"`
	PauseSupported bool      `json:"pause_supported"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
}

func nativeProbeAccountID(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if accountID, _ := auth.Metadata["account_id"].(string); strings.TrimSpace(accountID) != "" {
		return strings.TrimSpace(accountID)
	}
	for _, name := range []string{"id_token", "access_token"} {
		token, _ := auth.Metadata[name].(string)
		if claims, err := codex.ParseJWTToken(token); err == nil && strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID) != "" {
			return strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID)
		}
	}
	return ""
}

func (h *Host) nativeProbePauseSupported(ctx context.Context) bool {
	manager := h.currentAuthManager()
	if manager == nil || manager.HomeEnabled() {
		return false
	}
	if caller := hostCallbackPluginIDFromContext(ctx); caller != "" {
		selected := h.schedulerRecord()
		return selected != nil && selected.id == caller
	}
	return true
}

// callHostNativeProbeCredentials returns only the short-lived material needed
// for a native probe. Refresh and persistence remain owned by the auth manager.
func (h *Host) callHostNativeProbeCredentials(ctx context.Context, request []byte) ([]byte, error) {
	if !ojson.ValidBytes(request) {
		return nil, errors.New("native_probe_invalid_request")
	}
	doc := ojson.ParseBytes(request)
	index := strings.TrimSpace(doc.Get("auth_index").String())
	expectedID := strings.TrimSpace(doc.Get("expected_auth_id").String())
	expectedAccount := strings.TrimSpace(doc.Get("expected_account_id").String())
	if index == "" || expectedID == "" {
		return nil, errors.New("native_probe_identity_required")
	}
	auth, err := h.authByIndex(index)
	if err != nil || auth == nil || auth.ID != expectedID {
		return nil, errors.New("native_probe_identity_changed")
	}
	accountID := nativeProbeAccountID(auth)
	apiKey, _ := auth.Metadata["api_key"].(string)
	if strings.TrimSpace(auth.Provider) != "codex" || coreauth.IsCodexUseSIWC(auth) || accountID == "" || strings.TrimSpace(apiKey) != "" || strings.TrimSpace(auth.Attributes["api_key"]) != "" {
		return nil, errors.New("native_probe_oauth_required")
	}
	if expectedAccount != "" && accountID != expectedAccount {
		return nil, errors.New("native_probe_identity_changed")
	}
	manager := h.currentAuthManager()
	if manager == nil {
		return nil, errors.New("native_probe_auth_unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	type prepared struct {
		auth *coreauth.Auth
		err  error
	}
	done := make(chan prepared, 1)
	// A pre-existing manager refresh lock can outlive this caller's deadline.
	// Return promptly while its cancellable preparation unwinds independently.
	if doc.Get("prepare").Exists() && !doc.Get("prepare").Bool() {
		done <- prepared{auth: auth}
	} else {
		go func() {
			ready, refreshErr := manager.NativeProbeAuth(ctx, auth.ID, auth.RegistrationEpoch)
			done <- prepared{ready, refreshErr}
		}()
	}
	var ready *coreauth.Auth
	select {
	case <-ctx.Done():
		return nil, errors.New("native_probe_credentials_timeout")
	case result := <-done:
		if result.err != nil {
			return nil, result.err
		}
		ready = result.auth
	}
	latest, exists := manager.GetByID(auth.ID)
	if !exists || ready == nil || latest == nil || latest.RegistrationEpoch != auth.RegistrationEpoch || ready.Index != index || latest.Index != index || nativeProbeAccountID(ready) != accountID || nativeProbeAccountID(latest) != accountID {
		return nil, errors.New("native_probe_identity_changed")
	}
	accessToken, _ := latest.Metadata["access_token"].(string)
	if strings.TrimSpace(accessToken) == "" {
		return nil, errors.New("native_probe_access_token_missing")
	}
	proxyURL := strings.TrimSpace(latest.ProxyURL)
	if proxyURL == "" {
		proxyURL = h.hostConfigSummary().ProxyURL
	}
	expiresAt, _ := latest.AccessTokenExpirationTime()
	return marshalRPCResult(nativeProbeCredentials{
		AuthID: latest.ID, AuthIndex: latest.Index, Provider: "codex",
		AccessToken: accessToken, AccountID: accountID, ProxyURL: proxyURL,
		Disabled: latest.Disabled, ExpiresAt: expiresAt, PauseSupported: h.nativeProbePauseSupported(ctx),
	})
}
