package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

var groupName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func ValidOAuthGroup(group string) bool { return groupName.MatchString(group) }

func OAuthKeyFingerprint(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:])
}

func (c *SDKConfig) OAuthGroupingEnabled() bool {
	return c != nil && (c.OAuthKeySelection || len(c.OAuthKeyGroups) != 0)
}

// OAuthRoutingGroup includes the authenticated key identity when per-key selection is enabled.
// Slash is reserved for this in-memory scope and cannot occur in a persisted group.
func (c *SDKConfig) OAuthRoutingGroup(key string) string {
	group := c.OAuthGroupForKey(key)
	if group != "" && c.OAuthKeySelection {
		return "key:" + OAuthKeyFingerprint(key) + "/" + group
	}
	return group
}

// OAuthGroupForKey also checks membership so a revoked issuer cannot reuse a realtime secret.
func (c *SDKConfig) OAuthGroupForKey(key string) string {
	if !c.OAuthGroupingEnabled() || key == "" {
		return ""
	}
	for _, active := range c.APIKeys {
		if strings.TrimSpace(active) == key {
			if group, exists := c.OAuthKeyGroups[OAuthKeyFingerprint(key)]; exists {
				return group
			}
			return "default"
		}
	}
	return ""
}

func (c *SDKConfig) ValidateOAuthKeyGroups() error {
	for fp, group := range c.OAuthKeyGroups {
		digest, err := hex.DecodeString(fp)
		if err != nil || len(digest) != sha256.Size || strings.ToLower(fp) != fp || !ValidOAuthGroup(group) {
			return errors.New("invalid OAuth key fingerprint or group")
		}
	}
	return nil
}
