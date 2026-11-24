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

// bpsProbeIdentity derives identity from the actual bearer, never supplied
// metadata. Metadata identity, when present, must agree with the bearer.
func bpsProbeIdentity(auth *coreauth.Auth) (account, subject string) {
	if auth == nil || auth.Provider != "bps" {
		return "", ""
	}
	token, _ := auth.Metadata["access_token"].(string)
	claims, err := codex.ParseJWTToken(token)
	if err != nil || claims.Sub == "" || claims.CodexAuthInfo.ChatgptAccountID == "" {
		return "", ""
	}
	account, subject = claims.CodexAuthInfo.ChatgptAccountID, claims.Sub
	for key, expected := range map[string]string{"account_id": account, "subject": subject} {
		if value, _ := auth.Metadata[key].(string); value != "" && value != expected {
			return "", ""
		}
	}
	return account, subject
}

// callHostBPSProbeCredentials returns a generation-only snapshot. Refresh and
// persistence stay in CPA; neither refresh_token nor id_token is projected.
func (h *Host) callHostBPSProbeCredentials(ctx context.Context, request []byte) ([]byte, error) {
	if !ojson.ValidBytes(request) {
		return nil, errors.New("bps_probe_invalid_request")
	}
	doc := ojson.ParseBytes(request)
	pauseSupported := h.nativeProbePauseSupported(ctx)
	if operationID := strings.TrimSpace(doc.Get("operation_id").String()); operationID != "" {
		operation, errAcquire := h.acquireHostHTTPOperation(ctx, doc.Get("host_callback_id").String(), operationID)
		if errAcquire != nil {
			return nil, errors.New("bps_probe_operation_unavailable")
		}
		defer operation.finish()
		ctx = operation.ctx
	}
	index := strings.TrimSpace(doc.Get("auth_index").String())
	expectedID := strings.TrimSpace(doc.Get("expected_auth_id").String())
	expectedAccount := strings.TrimSpace(doc.Get("expected_account_id").String())
	expectedSubject := strings.TrimSpace(doc.Get("expected_subject").String())
	if index == "" || expectedID == "" {
		return nil, errors.New("bps_probe_identity_required")
	}
	auth, err := h.authByIndex(index)
	if err != nil || auth == nil || auth.ID != expectedID {
		return nil, errors.New("bps_probe_identity_changed")
	}
	account, subject := bpsProbeIdentity(auth)
	apiKey, _ := auth.Metadata["api_key"].(string)
	if account == "" || subject == "" || apiKey != "" || auth.Attributes["api_key"] != "" {
		return nil, errors.New("bps_probe_oauth_required")
	}
	if (expectedAccount != "" && account != expectedAccount) || (expectedSubject != "" && subject != expectedSubject) {
		return nil, errors.New("bps_probe_identity_changed")
	}
	if auth.Disabled {
		return nil, errors.New("bps_probe_account_disabled")
	}
	manager := h.currentAuthManager()
	if manager == nil {
		return nil, errors.New("bps_probe_auth_unavailable")
	}
	prepare := !doc.Get("prepare").Exists() || doc.Get("prepare").Bool()
	resolveProxy := func(a *coreauth.Auth) string {
		proxyURL := strings.TrimSpace(a.ProxyURL)
		if proxyURL == "" {
			proxyURL = strings.TrimSpace(h.hostConfigSummary().ProxyURL)
		}
		if proxyURL == "" {
			proxyURL = strings.TrimSpace(doc.Get("fallback_proxy_url").String())
		}
		return proxyURL
	}
	proxyURL := resolveProxy(auth)
	if prepare && !coreauth.ValidBPSProbeProxyURL(proxyURL) {
		return nil, errors.New("bps_probe_proxy_invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	type prepared struct {
		auth *coreauth.Auth
		err  error
	}
	done := make(chan prepared, 1)
	if !prepare {
		done <- prepared{auth: auth}
	} else {
		go func() {
			ready, refreshErr := manager.BPSProbeAuth(ctx, auth.ID, auth.RegistrationEpoch, proxyURL)
			done <- prepared{ready, refreshErr}
		}()
	}
	var ready *coreauth.Auth
	select {
	case <-ctx.Done():
		return nil, errors.New("bps_probe_credentials_timeout")
	case result := <-done:
		if result.err != nil {
			return nil, result.err
		}
		ready = result.auth
	}
	latest, exists := manager.GetByID(auth.ID)
	readyAccount, readySubject := bpsProbeIdentity(ready)
	latestAccount, latestSubject := bpsProbeIdentity(latest)
	if !exists || ready == nil || latest == nil || latest.RegistrationEpoch != auth.RegistrationEpoch || ready.RegistrationEpoch != auth.RegistrationEpoch || ready.Index != index || latest.Index != index || readyAccount != account || latestAccount != account || readySubject != subject || latestSubject != subject {
		return nil, errors.New("bps_probe_identity_changed")
	}
	if latest.Disabled || ready.Disabled {
		return nil, errors.New("bps_probe_account_disabled")
	}
	proxyURL = resolveProxy(latest)
	if prepare && !coreauth.ValidBPSProbeProxyURL(proxyURL) {
		return nil, errors.New("bps_probe_proxy_invalid")
	}
	// Only generation settings are exported. Unknown metadata can contain secrets.
	storage := map[string]any{}
	for _, key := range []string{"access_token", "token_type", "expires_in", "scope", "obtained_at", "client_id", "expired", "last_refresh", "prefix", "label", "headers", "max_concurrent"} {
		if value, ok := latest.Metadata[key]; ok {
			storage[key] = value
		}
	}
	storage["type"], storage["account_id"], storage["subject"] = "bps", account, subject
	storage["disabled"], storage["proxy_url"] = false, proxyURL
	return marshalRPCResult(map[string]any{
		"auth_id": latest.ID, "auth_index": latest.Index, "provider": "bps",
		"account_id": account, "subject": subject, "proxy_url": proxyURL,
		"disabled": false, "pause_supported": pauseSupported, "storage_json": storage,
	})
}
