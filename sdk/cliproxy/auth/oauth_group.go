package auth

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
)

var keyAssignment = regexp.MustCompile(`^key:[0-9a-f]{64}$`)

type oauthGroupContextKey struct{}

func WithOAuthGroup(ctx context.Context, group string) context.Context {
	if group == "" {
		return ctx
	}
	return context.WithValue(ctx, oauthGroupContextKey{}, group)
}

func OAuthGroupFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	group, _ := ctx.Value(oauthGroupContextKey{}).(string)
	return group
}

// AuthenticatedOAuthGroup reads the access provider result, never a client header.
func AuthenticatedOAuthGroup(values interface{ Get(string) (any, bool) }) string {
	raw, _ := values.Get("accessMetadata")
	meta, _ := raw.(map[string]string)
	return meta[access.OAuthAccountGroup]
}

func (a *Auth) OAuthAccountGroup() string {
	if a == nil || a.Provider != "codex" || a.AuthKind() != AuthKindOAuth || IsPluginVirtualAuth(a) {
		return ""
	}
	group, exists := a.Metadata[access.OAuthAccountGroup]
	if !exists || group == nil {
		return "default"
	}
	name, _ := group.(string)
	return name
}

func (a *Auth) InOAuthGroup(group string) bool {
	account := a.OAuthAccountGroup()
	if group == "" || account == "" {
		return false
	}
	if key, legacy, named := strings.Cut(group, "/"); named {
		return keyAssignment.MatchString(key) && (account == "default" || account == key || account == legacy)
	}
	return account == group
}

func ValidateCodexAccountField(key string, value any) error {
	if value == nil {
		return nil
	}
	v, ok := value.(string)
	switch key {
	case "oauth_group":
		if !ok || (!config.ValidOAuthGroup(v) && !keyAssignment.MatchString(v)) {
			return errors.New("invalid OAuth group name")
		}
	case "service_tier":
		if !ok || (v != "inherit" && v != "fast" && v != "priority" && v != "ultrafast") {
			return errors.New("service_tier must be inherit, fast, priority, ultrafast or null")
		}
	}
	return nil
}

// OAuthModelDirectoryEnabled reports whether this instance publishes the CPA OAuth directory.
func (m *Manager) OAuthModelDirectoryEnabled() bool {
	if m == nil {
		return false
	}
	cfg, _ := m.runtimeConfig.Load().(*config.Config)
	return OAuthModelDirectoryEnabledForConfig(cfg)
}

// OAuthModelDirectoryEnabledForConfig checks the host-owned plugin enablement flags.
func OAuthModelDirectoryEnabledForConfig(cfg *config.Config) bool {
	if cfg == nil || !cfg.Plugins.Enabled {
		return false
	}
	enabled := cfg.Plugins.Configs["cpa-oauth"].Enabled
	return enabled != nil && *enabled
}

// OAuthGroupClientIDs selects authorized registrations without copying grant secrets or runtime state.
func (m *Manager) OAuthGroupClientIDs(group string) map[string]bool {
	clients := make(map[string]bool)
	if m == nil {
		return clients
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for id, a := range m.auths {
		if !a.Disabled && a.InOAuthGroup(group) {
			clients[id] = true
		}
	}
	return clients
}
