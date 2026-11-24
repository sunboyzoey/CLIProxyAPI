package helps

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
	"golang.org/x/sync/singleflight"
)

const codexManifestURL = "https://chatgpt.com/backend-api/codex/models?client_version=0.170.0"

type CodexAccountTiers struct {
	CheckedAt       time.Time `json:"checked_at"`
	Models          []string  `json:"models"`
	CatalogModels   []string  `json:"catalog_models"`
	FastModels      []string  `json:"fast_models"`
	UltrafastModels []string  `json:"ultrafast_models"`
}

type tierCacheEntry struct {
	tiers   CodexAccountTiers
	err     error
	expires time.Time
}

var tierCache = struct {
	sync.Mutex
	entries map[[32]byte]tierCacheEntry
	calls   singleflight.Group
}{entries: make(map[[32]byte]tierCacheEntry)}

func codexManifestProxy(cfg *config.Config, a *auth.Auth) string {
	if a.ProxyURL == "" && cfg != nil {
		return cfg.ProxyURL
	}
	return a.ProxyURL
}

func tierCacheKey(cfg *config.Config, a *auth.Auth) [32]byte {
	token, _ := a.Metadata["access_token"].(string)
	id, _ := a.Metadata["account_id"].(string)
	plan, _ := a.Metadata["plan_type"].(string)
	return sha256.Sum256([]byte(strings.Join([]string{a.ID, id, token, plan, a.Attributes["plan_type"], codexManifestProxy(cfg, a)}, "\x00")))
}

func cachedTiers(key [32]byte) (tierCacheEntry, bool) {
	tierCache.Lock()
	defer tierCache.Unlock()
	v, ok := tierCache.entries[key]
	return v, ok && time.Now().Before(v.expires)
}

// CachedCodexAccountTiers is read-only and never performs a network request.
func CachedCodexAccountTiers(a *auth.Auth) (CodexAccountTiers, bool) {
	return CachedCodexAccountTiersForConfig(nil, a)
}

// CachedCodexAccountTiersForConfig reads only the current credential and egress cache entry.
func CachedCodexAccountTiersForConfig(cfg *config.Config, a *auth.Auth) (CodexAccountTiers, bool) {
	if a.OAuthAccountGroup() == "" {
		return CodexAccountTiers{}, false
	}
	entry, ok := cachedTiers(tierCacheKey(cfg, a))
	if !ok || entry.err != nil {
		return CodexAccountTiers{}, false
	}
	return entry.tiers, true
}

// DiscoverCodexAccountTiers obtains model-specific entitlements using the account's own credentials and proxy.
func DiscoverCodexAccountTiers(ctx context.Context, cfg *config.Config, a *auth.Auth, refresh bool) (CodexAccountTiers, error) {
	if a.OAuthAccountGroup() == "" {
		return CodexAccountTiers{}, errors.New("native Codex OAuth credential required")
	}
	key := tierCacheKey(cfg, a)
	if !refresh {
		if entry, ok := cachedTiers(key); ok {
			return entry.tiers, entry.err
		}
	}
	ch := tierCache.calls.DoChan(string(key[:]), func() (any, error) {
		if !refresh {
			if entry, ok := cachedTiers(key); ok {
				return entry.tiers, entry.err
			}
		}
		tiers, err := fetchCodexAccountTiers(ctx, cfg, a)
		if ctx.Err() != nil {
			return tiers, ctx.Err()
		}
		now := time.Now()
		ttl := time.Hour
		if err != nil {
			ttl = time.Minute
		}
		tierCache.Lock()
		for k, v := range tierCache.entries {
			if !now.Before(v.expires) {
				delete(tierCache.entries, k)
			}
		}
		tierCache.entries[key] = tierCacheEntry{tiers, err, now.Add(ttl)}
		tierCache.Unlock()
		return tiers, err
	})
	select {
	case <-ctx.Done():
		return CodexAccountTiers{}, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return CodexAccountTiers{}, res.Err
		}
		return res.Val.(CodexAccountTiers), nil
	}
}

func fetchCodexAccountTiers(ctx context.Context, cfg *config.Config, a *auth.Auth) (CodexAccountTiers, error) {
	var empty CodexAccountTiers
	token, _ := a.Metadata["access_token"].(string)
	id, _ := a.Metadata["account_id"].(string)
	if token == "" || id == "" {
		return empty, errors.New("OAuth access token and account ID are required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, codexManifestURL, nil)
	if err != nil {
		return empty, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("ChatGPT-Account-ID", id)
	req.Header.Set("Accept", "application/json")
	// Only the configured account egress may receive this discovery request.
	transport, _, errProxy := proxyutil.BuildHTTPTransport(codexManifestProxy(cfg, a))
	if errProxy != nil {
		return empty, errors.New("invalid OAuth account proxy")
	}
	client := &http.Client{}
	if transport != nil {
		client.Transport = transport
		defer transport.CloseIdleConnections()
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return empty, errors.New("Codex model manifest unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return empty, fmt.Errorf("Codex model manifest returned HTTP %d", resp.StatusCode)
	}
	const limit = 8 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || len(data) > limit {
		return empty, errors.New("invalid Codex model manifest")
	}
	plan := strings.TrimSpace(a.Attributes["plan_type"])
	if value, _ := a.Metadata["plan_type"].(string); strings.TrimSpace(value) != "" {
		plan = strings.TrimSpace(value)
	}
	if claims, errParse := codex.ParseJWTToken(token); errParse == nil && strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType) != "" {
		plan = claims.GetPlanType()
	}
	if plan == "" {
		plan = codex.DefaultPlanType
	}
	return parseCodexAccountTiers(data, time.Now().UTC(), plan)
}

// A missing capability list is unspecified in older manifests. An explicit list
// is authoritative for the selected account, including an empty list.
func manifestIncludes(list ojson.Result, value string) bool {
	if !list.Exists() {
		return true
	}
	for _, item := range list.Array() {
		if item.Type == ojson.String && strings.EqualFold(item.String(), value) {
			return true
		}
	}
	return false
}

func listedCodexModel(m ojson.Result, plan string) bool {
	if visibility := m.Get("visibility"); visibility.Exists() && visibility.String() != "list" {
		return false
	}
	// supported_in_api describes API-key access. This manifest uses ChatGPT OAuth.
	return !m.Get("allow_only_chatgpt_workspace_executor").Bool() && !m.Get("allow_only_codex_cloud_agent_orchestrator").Bool() &&
		manifestIncludes(m.Get("available_in_plans"), plan)
}

func parseCodexAccountTiers(data []byte, checked time.Time, plan string) (CodexAccountTiers, error) {
	var empty CodexAccountTiers
	if !ojson.ValidBytes(data) {
		return empty, errors.New("invalid Codex model manifest")
	}
	models := ojson.GetBytes(data, "models")
	if !models.IsArray() {
		return empty, errors.New("Codex model manifest has no models array")
	}
	result := CodexAccountTiers{CheckedAt: checked, Models: []string{}, CatalogModels: []string{}, FastModels: []string{}, UltrafastModels: []string{}}
	seen := make(map[string]bool)
	catalog := make(map[string]bool)
	for _, m := range models.Array() {
		s := m.Get("slug")
		slug := s.String()
		if s.Type != ojson.String || slug == "" || len(slug) > 100 || strings.IndexFunc(slug, unicode.IsSpace) >= 0 || strings.IndexFunc(slug, unicode.IsControl) >= 0 {
			continue
		}
		// Keep short IDs in the cache without retaining the entire upstream manifest.
		slug = strings.Clone(slug)
		if listedCodexModel(m, plan) {
			enabled := m.Get("enabled")
			if !catalog[slug] && !m.Get("disabled").Bool() && (!enabled.Exists() || enabled.Bool()) {
				catalog[slug] = true
				result.CatalogModels = append(result.CatalogModels, slug)
			}
			if !seen[slug] && !strings.HasPrefix(slug, "gpt-image-") && manifestIncludes(m.Get("input_modalities"), "text") && manifestIncludes(m.Get("output_modalities"), "text") {
				seen[slug] = true
				result.Models = append(result.Models, slug)
			}
		}
		if !manifestIncludes(m.Get("available_in_plans"), plan) {
			continue
		}
		for _, tier := range m.Get("service_tiers").Array() {
			if !manifestIncludes(tier.Get("available_in_plans"), plan) {
				continue
			}
			switch tier.Get("id").String() {
			case "fast", "priority":
				result.FastModels = append(result.FastModels, slug)
			case "ultrafast":
				result.UltrafastModels = append(result.UltrafastModels, slug)
			}
		}
	}
	sort.Strings(result.FastModels)
	sort.Strings(result.UltrafastModels)
	return result, nil
}

type codexTierRule struct {
	mode            string
	inherit         bool
	clientSpecified bool
	discover        func() (CodexAccountTiers, error)
}

func acceleratedCodexTier(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "fast", "priority":
		return "priority"
	case "ultrafast":
		return "ultrafast"
	default:
		return ""
	}
}

func accountTierRule(ctx context.Context, cfg *config.Config, a *auth.Auth) (r codexTierRule) {
	if a.OAuthAccountGroup() == "" {
		return r
	}
	raw, _ := a.Metadata["service_tier"].(string)
	r.mode = acceleratedCodexTier(raw)
	if r.mode == "" {
		if cfg == nil || !cfg.Plugins.Enabled {
			return r
		}
		item := cfg.Plugins.Configs["cpa-oauth"]
		if item.Enabled == nil || !*item.Enabled {
			return r
		}
		var settings struct {
			DefaultTier string `yaml:"default_tier"`
		}
		if item.Raw.Decode(&settings) == nil {
			r.mode = acceleratedCodexTier(settings.DefaultTier)
		}
		r.inherit = true
	}
	r.discover = func() (CodexAccountTiers, error) { return DiscoverCodexAccountTiers(ctx, cfg, a, false) }
	return r
}

// Translators can omit explicit standard tiers that Codex does not accept.
func (r *codexTierRule) captureClientTier(req, original []byte) {
	if !r.inherit || r.mode == "" {
		return
	}
	for _, input := range [][]byte{req, original} {
		if ojson.GetBytesNoCopy(input, "service_tier").Exists() || ojson.GetBytesNoCopy(input, "serviceTier").Exists() {
			r.clientSpecified = true
			return
		}
	}
}

func hasTierModel(models []string, model string) bool {
	i := sort.SearchStrings(models, model)
	return i < len(models) && models[i] == model
}

func (r codexTierRule) apply(doc *ojson.Doc, original []byte, fallback string) bool {
	if r.discover == nil {
		return false
	}
	current := doc.Get("service_tier")
	requested := r.mode
	if r.inherit {
		if current.Exists() {
			requested = acceleratedCodexTier(current.String())
		} else if r.clientSpecified || (requested != "" && ojson.GetBytesNoCopy(original, "service_tier").Exists()) {
			return false
		}
	}
	if requested == "" {
		return false
	}
	model := doc.Get("model").String()
	if model == "" {
		model = fallback
	}
	tiers, err := r.discover()
	resolved := ""
	if err == nil {
		switch {
		case requested == "ultrafast" && hasTierModel(tiers.UltrafastModels, model):
			resolved = "ultrafast"
		case hasTierModel(tiers.FastModels, model):
			resolved = "priority"
		}
	}
	if resolved == "" {
		return current.Exists() && doc.Delete("service_tier") == nil
	}
	return current.String() != resolved && doc.Set("service_tier", resolved) == nil
}
