package management

import (
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/MoeForge/moego/ojson"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

var oauthKeyDigest = regexp.MustCompile("^[0-9a-f]{64}$")

// CopyOAuthGroupKey resolves a displayed fingerprint against the current client keys.
func (h *Handler) CopyOAuthGroupKey(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	raw, errRead := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, 4096))
	var fingerprint string
	if errRead == nil && c.ContentType() == "application/json" && ojson.ValidBytes(raw) {
		ojson.ParseBytes(raw).ForEach(func(field, value ojson.Result) bool {
			if fingerprint != "" || field.String() != "sha256" || value.Type != ojson.String || !oauthKeyDigest.MatchString(value.String()) {
				fingerprint = ""
				return false
			}
			fingerprint = value.String()
			return true
		})
	}
	if fingerprint == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide a lowercase SHA-256 fingerprint"})
		return
	}
	cfg := h.configSnapshot()
	if cfg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "configuration unavailable"})
		return
	}
	for _, key := range cfg.APIKeys {
		key = strings.TrimSpace(key)
		if key != "" && config.OAuthKeyFingerprint(key) == fingerprint {
			c.JSON(http.StatusOK, gin.H{"key": key})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "API key fingerprint not found"})
}

func (h *Handler) ListOAuthAccountGroups(c *gin.Context) {
	cfg := h.configSnapshot()
	if cfg == nil || h.authManager == nil {
		c.JSON(503, gin.H{"error": "configuration unavailable"})
		return
	}
	keys := make([]gin.H, 0, len(cfg.APIKeys))
	for i, key := range cfg.APIKeys {
		fp := config.OAuthKeyFingerprint(key)
		keys = append(keys, gin.H{"index": i + 1, "sha256": fp, "group": cfg.OAuthGroupForKey(key)})
	}
	groups := make(map[string][]string)
	for _, a := range h.authManager.List() {
		if g := a.OAuthAccountGroup(); g != "" {
			groups[g] = append(groups[g], a.ID)
		}
	}
	c.JSON(http.StatusOK, gin.H{"enabled": cfg.OAuthGroupingEnabled(), "by_key": cfg.OAuthKeySelection, "keys": keys, "groups": groups})
}

func (h *Handler) ProbeCodexAccountTiers(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(503, gin.H{"error": "credential manager unavailable"})
		return
	}
	name, index := strings.TrimSpace(c.Query("name")), strings.TrimSpace(c.Query("auth_index"))
	expected := c.GetHeader("If-Match-OAuth-Identity")
	matches := func(a *coreauth.Auth) bool {
		identity, _, _ := coreauth.NativeCodexIdentity(a)
		return a != nil && name == a.ID && (index == "" || index == a.EnsureIndex()) && identity == expected
	}
	conflict := func() { c.JSON(http.StatusConflict, gin.H{"error": "OAuth account identity changed"}) }
	a, ok := h.lookupAuthFile(name, index)
	if expected != "" && !matches(a) {
		conflict()
		return
	}
	if !ok || a == nil {
		c.JSON(404, gin.H{"error": "credential not found"})
		return
	}
	if a.OAuthAccountGroup() == "" {
		c.JSON(400, gin.H{"error": "native Codex OAuth credential required"})
		return
	}
	if expected != "" {
		prepared, errPrepare := h.authManager.NativeProbeAuth(c.Request.Context(), a.ID, a.RegistrationEpoch)
		if errPrepare != nil {
			current, _ := h.authManager.GetByID(a.ID)
			if !matches(current) {
				conflict()
			} else {
				c.JSON(http.StatusBadGateway, gin.H{"error": "OAuth credential could not be prepared"})
			}
			return
		}
		if !matches(prepared) {
			conflict()
			return
		}
		a = prepared
	}
	tiers, err := helps.DiscoverCodexAccountTiers(c.Request.Context(), h.configSnapshot(), a, true)
	if expected != "" {
		current, _ := h.authManager.GetByID(a.ID)
		if !matches(current) {
			conflict()
			return
		}
	}
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tiers)
}

// SetOAuthKeyGroup changes one binding without trusting key material supplied by the caller.
func (h *Handler) SetOAuthKeyGroup(c *gin.Context) {
	var body struct {
		Fingerprint string `json:"sha256"`
		Group       string `json:"group"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || !config.ValidOAuthGroup(body.Group) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide a key sha256 fingerprint and a valid group"})
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "configuration unavailable"})
		return
	}
	bindings := make(map[string]string, len(h.cfg.APIKeys))
	for _, key := range h.cfg.APIKeys {
		fp := config.OAuthKeyFingerprint(key)
		group := h.cfg.OAuthKeyGroups[fp]
		if group == "" {
			group = "default"
		}
		bindings[fp] = group
	}
	if _, ok := bindings[body.Fingerprint]; !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "API key fingerprint not found"})
		return
	}
	bindings[body.Fingerprint] = body.Group
	old := h.cfg.OAuthKeyGroups
	h.cfg.OAuthKeyGroups = bindings
	snapshot, ok := h.saveConfigAndSnapshotLocked(c)
	if !ok {
		h.cfg.OAuthKeyGroups = old
		return
	}
	h.reloadConfigAfterManagementSaveAsync(c.Request.Context(), snapshot)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "group": body.Group})
}
