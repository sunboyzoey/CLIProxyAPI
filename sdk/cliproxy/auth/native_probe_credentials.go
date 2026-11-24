package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

type nativeProbeRefreshContextKey struct{}

func isNativeProbeRefresh(ctx context.Context) bool {
	marked, _ := ctx.Value(nativeProbeRefreshContextKey{}).(bool)
	return marked
}

// nativeProbeSchedulerAttributes binds probe blocks to credential identity while
// exposing neither JWT claims nor tokens to the scheduler plugin.
func nativeProbeSchedulerAttributes(auth *Auth) map[string]string {
	attributes := schedulerSafeAttributes(auth.Attributes)
	delete(attributes, "native_probe_identity")
	delete(attributes, "bps_probe_identity")
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	if provider != "codex" && provider != "bps" {
		return attributes
	}
	token, _ := auth.Metadata["access_token"].(string)
	claims, err := codex.ParseJWTToken(token)
	if err != nil || claims.Sub == "" || claims.CodexAuthInfo.ChatgptAccountID == "" {
		return attributes
	}
	if attributes == nil {
		attributes = make(map[string]string)
	}
	sum := sha256.Sum256([]byte(claims.Sub + "\x00" + claims.CodexAuthInfo.ChatgptAccountID))
	key := "native_probe_identity"
	if provider == "bps" {
		key = "bps_probe_identity"
	}
	attributes[key] = hex.EncodeToString(sum[:])
	return attributes
}

// NativeProbeAuth prepares an existing native Codex OAuth credential without
// transferring refresh-token ownership to a plugin. The observed access token
// and registration epoch retain the normal refresh de-duplication and fencing.
func (m *Manager) NativeProbeAuth(ctx context.Context, id string, epoch uint64) (*Auth, error) {
	if m == nil {
		return nil, errors.New("native_probe_auth_unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, exists := m.GetByID(id)
	if !exists || current == nil || current.RegistrationEpoch != epoch {
		return nil, errors.New("native_probe_identity_changed")
	}
	if !strings.EqualFold(strings.TrimSpace(current.Provider), "codex") || IsCodexUseSIWC(current) || authMetadataString(current, "api_key") != "" || strings.TrimSpace(current.Attributes["api_key"]) != "" {
		return nil, errors.New("native_probe_oauth_required")
	}
	token := authAccessToken(current)
	if token == "" {
		return nil, errors.New("native_probe_access_token_missing")
	}
	expires, known := current.AccessTokenExpirationTime()
	if !known || expires.After(time.Now().Add(30*time.Second)) {
		return current, nil
	}
	if authMetadataString(current, "refresh_token") == "" {
		if expires.After(time.Now()) {
			return current, nil
		}
		return nil, errors.New("native_probe_access_token_expired")
	}
	// This is proactive renewal, not evidence that the access token was rejected.
	ctx = context.WithValue(ctx, nativeProbeRefreshContextKey{}, true)
	refreshed, err := m.refreshAuthForRequestAtEpoch(ctx, id, token, epoch)
	if err != nil {
		return nil, errors.New("native_probe_refresh_failed")
	}
	if refreshed == nil || refreshed.RegistrationEpoch != epoch || !refreshed.HasValidAccessToken(time.Now()) {
		return nil, errors.New("native_probe_refresh_incomplete")
	}
	return refreshed, nil
}
