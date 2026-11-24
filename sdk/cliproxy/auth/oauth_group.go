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
