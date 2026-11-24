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

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
	"golang.org/x/sync/singleflight"
)

const codexManifestURL = "https://chatgpt.com/backend-api/codex/models?client_version=0.170.0"

type CodexAccountTiers struct {
	CheckedAt       time.Time `json:"checked_at"`
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

func tierCacheKey(a *auth.Auth) [32]byte {
	token, _ := a.Metadata["access_token"].(string)
	id, _ := a.Metadata["account_id"].(string)
	return sha256.Sum256([]byte(a.ID + "\x00" + id + "\x00" + token))
}

func cachedTiers(key [32]byte) (tierCacheEntry, bool) {
	tierCache.Lock()
	defer tierCache.Unlock()
	v, ok := tierCache.entries[key]
	return v, ok && time.Now().Before(v.expires)
}

// CachedCodexAccountTiers is read-only and never performs a network request.
func CachedCodexAccountTiers(a *auth.Auth) (CodexAccountTiers, bool) {
	if a.OAuthAccountGroup() == "" {
		return CodexAccountTiers{}, false
	}
	entry, ok := cachedTiers(tierCacheKey(a))
	return entry.tiers, ok && entry.err == nil
}

// DiscoverCodexAccountTiers obtains model-specific entitlements using the account's own credentials and proxy.
func DiscoverCodexAccountTiers(ctx context.Context, cfg *config.Config, a *auth.Auth, refresh bool) (CodexAccountTiers, error) {
	if a.OAuthAccountGroup() == "" {
		return CodexAccountTiers{}, errors.New("native Codex OAuth credential required")
	}
	key := tierCacheKey(a)
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
	proxy := a.ProxyURL
	if proxy == "" && cfg != nil {
		proxy = cfg.ProxyURL
	}
	transport, _, errProxy := proxyutil.BuildHTTPTransport(proxy)
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
	return parseCodexAccountTiers(data, time.Now().UTC())
}

func parseCodexAccountTiers(data []byte, checked time.Time) (CodexAccountTiers, error) {
	var empty CodexAccountTiers
	if !ojson.ValidBytes(data) {
		return empty, errors.New("invalid Codex model manifest")
	}
	models := ojson.GetBytes(data, "models")
	if !models.IsArray() {
		return empty, errors.New("Codex model manifest has no models array")
	}
	result := CodexAccountTiers{CheckedAt: checked, FastModels: []string{}, UltrafastModels: []string{}}
	for _, m := range models.Array() {
		slug := m.Get("slug").String()
		if slug == "" {
			continue
		}
		for _, tier := range m.Get("service_tiers").Array() {
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
	mode  string
	tiers CodexAccountTiers
}

func accountTierRule(ctx context.Context, cfg *config.Config, a *auth.Auth) (r codexTierRule) {
	if a.OAuthAccountGroup() == "" {
		return r
	}
	raw, _ := a.Metadata["service_tier"].(string)
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "fast", "priority":
		r.mode = "priority"
	case "ultrafast":
		r.mode = "ultrafast"
		r.tiers, _ = DiscoverCodexAccountTiers(ctx, cfg, a, false)
	}
	return r
}

func hasTierModel(models []string, model string) bool {
	i := sort.SearchStrings(models, model)
	return i < len(models) && models[i] == model
}

func (r codexTierRule) apply(doc *ojson.Doc, fallback string) bool {
	tier := r.mode
	if tier == "" {
		return false
	}
	if tier == "ultrafast" {
		model := doc.Get("model").String()
		if model == "" {
			model = fallback
		}
		if !hasTierModel(r.tiers.UltrafastModels, model) {
			if !hasTierModel(r.tiers.FastModels, model) {
				if !doc.Get("service_tier").Exists() {
					return false
				}
				return doc.Delete("service_tier") == nil
			}
			tier = "priority"
		}
	}
	return doc.Set("service_tier", tier) == nil
}
