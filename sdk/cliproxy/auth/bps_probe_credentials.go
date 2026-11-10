package auth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

// BPSProbeAuth renews a BPS grant through its registered executor and the same
// per-credential refresh lock used by ordinary requests. No RT leaves Manager.
func (m *Manager) BPSProbeAuth(ctx context.Context, id string, epoch uint64, proxyURL string) (*Auth, error) {
	if m == nil {
		return nil, errors.New("bps_probe_auth_unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	current, exists := m.GetByID(id)
	if !exists || current == nil || current.RegistrationEpoch != epoch {
		return nil, errors.New("bps_probe_identity_changed")
	}
	if !strings.EqualFold(strings.TrimSpace(current.Provider), "bps") || authMetadataString(current, "api_key") != "" || strings.TrimSpace(current.Attributes["api_key"]) != "" {
		return nil, errors.New("bps_probe_oauth_required")
	}
	if current.Disabled {
		return nil, errors.New("bps_probe_account_disabled")
	}
	if strings.TrimSpace(current.ProxyURL) != "" {
		proxyURL = current.ProxyURL
	}
	proxyURL = strings.TrimSpace(proxyURL)
	if !ValidBPSProbeProxyURL(proxyURL) {
		return nil, errors.New("bps_probe_proxy_invalid")
	}
	token := authAccessToken(current)
	if token == "" {
		return nil, errors.New("bps_probe_access_token_missing")
	}
	expires, known := current.AccessTokenExpirationTime()
	if !known || expires.After(time.Now().Add(30*time.Second)) {
		return current, nil
	}
	if authMetadataString(current, "refresh_token") == "" {
		if expires.After(time.Now()) {
			return current, nil
		}
		return nil, errors.New("bps_probe_access_token_expired")
	}
	// Share the proactive-refresh marker; expiry is not an upstream 401.
	ctx = context.WithValue(ctx, nativeProbeRefreshContextKey{}, true)
	ctx = context.WithValue(ctx, bpsProbeProxyContextKey{}, proxyURL)
	refreshed, err := m.refreshAuthForRequestAtEpoch(ctx, id, token, epoch)
	if err != nil {
		return nil, errors.New("bps_probe_refresh_failed")
	}
	if refreshed == nil || refreshed.RegistrationEpoch != epoch || refreshed.Disabled || !strings.EqualFold(refreshed.Provider, "bps") || !refreshed.HasValidAccessToken(time.Now()) {
		return nil, errors.New("bps_probe_refresh_incomplete")
	}
	return refreshed, nil
}

type bpsProbeProxyContextKey struct{}

// BPSProbeProxyURL is set only by BPSProbeAuth for its one credential renewal.
// The plugin adapter applies it to the outgoing snapshot, never persisted auth.
func BPSProbeProxyURL(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	proxyURL, ok := ctx.Value(bpsProbeProxyContextKey{}).(string)
	return proxyURL, ok
}

// ValidBPSProbeProxyURL accepts the normal BPS route: an empty value inherits
// deployment defaults, while a configured proxy must be a supported URL.
func ValidBPSProbeProxyURL(proxyURL string) bool {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		return true
	}
	u, err := url.Parse(proxyURL)
	return err == nil && u.Hostname() != "" && (u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "socks5" || u.Scheme == "socks5h")
}
