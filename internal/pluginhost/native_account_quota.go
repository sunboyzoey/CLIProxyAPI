package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
)

const nativeQuotaURL = "https://chatgpt.com/backend-api/wham/usage"

type nativeQuotaData struct {
	pluginapi.QuotaFetchResponse
	Source        string                   `json:"source"`
	FetchedAt     string                   `json:"fetched_at"`
	Cached        bool                     `json:"cached"`
	Allowed       *bool                    `json:"allowed"`
	LimitReached  *bool                    `json:"limit_reached"`
	Availability  string                   `json:"availability"`
	ModelStatuses []nativeQuotaModelStatus `json:"model_statuses,omitempty"`
}

type nativeQuotaModelStatus struct {
	Model     string `json:"model"`
	Available bool   `json:"available"`
}

// nativeQuotaIdentity binds the observation to the actual OAuth grant. Neither
// a filename nor mutable metadata may substitute for the access-token claims.
func nativeQuotaIdentity(a *coreauth.Auth) (account, subject, identity string) {
	identity, account, subject = coreauth.NativeCodexIdentity(a)
	return account, subject, identity
}

// nativeOAuthDisplayName reads presentation claims only. Identity checks continue
// to use NativeCodexIdentity independently of optional profile fields.
func nativeOAuthDisplayName(a *coreauth.Auth, fallback string) string {
	claims := func(field string) ojson.Result {
		token, _ := a.Metadata[field].(string)
		payload, err := codex.DecodeJWTPayload(token)
		if err != nil || !ojson.ValidBytes(payload) {
			return ojson.Result{}
		}
		return ojson.ParseBytes(payload)
	}
	access := claims("access_token")
	profile := access.Get(`https://api\.openai\.com/profile`)
	if name := strings.TrimSpace(profile.Get("name").Str); name != "" {
		return name
	}
	id := claims("id_token")
	subject := access.Get("sub").Str
	const accountPath = `https://api\.openai\.com/auth.chatgpt_account_id`
	idAccount := id.Get(accountPath)
	accountMatches := idAccount.Type == ojson.Null ||
		(idAccount.Type == ojson.String && (idAccount.Str == "" || idAccount.Str == access.Get(accountPath).Str))
	if subject == "" || subject != id.Get("sub").Str || !accountMatches {
		id = ojson.Result{}
	}
	if name := strings.TrimSpace(id.Get("name").Str); name != "" {
		return name
	}
	if email := authEmail(a); email != "" {
		return email
	}
	if email := strings.TrimSpace(profile.Get("email").Str); email != "" {
		return email
	}
	if email := strings.TrimSpace(id.Get("email").Str); email != "" {
		return email
	}
	return fallback
}

// nativeOAuthInventory returns routing and accounting identifiers without exposing grants.
func (h *Host) nativeOAuthInventory() ([]byte, error) {
	manager := h.currentAuthManager()
	if manager == nil {
		return nil, errors.New("credential manager unavailable")
	}
	type entry struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		ID          string `json:"auth_id"`
		Index       string `json:"auth_index"`
		Identity    string `json:"identity"`
		Account     string `json:"account_id"`
		Disabled    bool   `json:"disabled"`
		Group       string `json:"group"`
		Tier        string `json:"service_tier"`
	}
	accounts := []entry{}
	for _, a := range manager.List() {
		if a.OAuthAccountGroup() == "" || coreauth.IsCodexUseSIWC(a) {
			continue
		}
		identity, account, _ := coreauth.NativeCodexIdentity(a)
		name := a.FileName
		if name == "" {
			name = a.ID
		}
		tier, _ := a.Metadata["service_tier"].(string)
		accounts = append(accounts, entry{
			Name: name, DisplayName: nativeOAuthDisplayName(a, name),
			ID: a.ID, Index: a.EnsureIndex(), Identity: identity, Account: account,
			Disabled: a.Disabled, Group: a.OAuthAccountGroup(), Tier: tier,
		})
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })
	return marshalRPCResult(map[string]any{"accounts": accounts})
}

// nativeAccountQuota keeps OAuth preparation, refresh ownership and transport
// policy in CPA. The plugin sends references only and never receives a token.
func (h *Host) nativeAccountQuota(ctx context.Context, request []byte) ([]byte, error) {
	if !ojson.ValidBytes(request) || !ojson.ParseBytes(request).IsObject() {
		return nil, errors.New("codex_quota_invalid_request")
	}
	doc := ojson.ParseBytes(request)
	index := strings.TrimSpace(doc.Get("auth_index").String())
	expectedID := strings.TrimSpace(doc.Get("expected_auth_id").String())
	expectedAccount := doc.Get("expected_account_id").String()
	expectedSubject := doc.Get("expected_subject").String()
	expectedIdentity := strings.TrimSpace(doc.Get("expected_identity").String())
	background := expectedIdentity != ""
	if expectedID == "" || !background && (index == "" || expectedAccount == "" || expectedSubject == "") {
		return nil, errors.New("codex_quota_identity_required")
	}
	operation, errAcquire := h.acquireHostHTTPOperation(ctx, doc.Get("host_callback_id").String(), doc.Get("operation_id").String())
	if errAcquire != nil {
		return nil, errors.New("codex_quota_callback_unavailable")
	}
	defer operation.finish()
	ctx = operation.ctx
	manager := h.currentAuthManager()
	var auth *coreauth.Auth
	if manager != nil {
		if background {
			auth, _ = manager.GetByID(expectedID)
		} else {
			auth, _ = h.authByIndex(index)
		}
	}
	if auth == nil || auth.ID != expectedID {
		return nil, errors.New("codex_quota_identity_changed")
	}
	account, subject, identity := nativeQuotaIdentity(auth)
	if identity == "" {
		return nil, errors.New("codex_quota_oauth_required")
	}
	if background {
		// Resolve current credentials in CPA without querying a replaced grant.
		if identity != expectedIdentity || auth.Disabled {
			return nil, errors.New("codex_quota_identity_changed")
		}
		index = auth.Index
	} else if account != expectedAccount || subject != expectedSubject {
		return nil, errors.New("codex_quota_identity_changed")
	}
	// Only credential acquisition has a deadline. The upstream request follows
	// the caller/plugin lifetime and does not add a wall-clock response timeout.
	prepareCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	type prepared struct {
		auth *coreauth.Auth
		err  error
	}
	done := make(chan prepared, 1)
	go func() {
		ready, errPrepare := manager.NativeProbeAuth(prepareCtx, auth.ID, auth.RegistrationEpoch)
		done <- prepared{ready, errPrepare}
	}()
	var ready *coreauth.Auth
	select {
	case <-prepareCtx.Done():
		cancel()
		return nil, errors.New("codex_quota_credentials_timeout")
	case result := <-done:
		cancel()
		if result.err != nil {
			return nil, errors.New("codex_quota_credentials_unavailable")
		}
		ready = result.auth
	}
	matches := func(a *coreauth.Auth) bool {
		_, _, current := nativeQuotaIdentity(a)
		return a != nil && a.ID == auth.ID && a.Index == index && a.RegistrationEpoch == auth.RegistrationEpoch && current == identity && (!background || !a.Disabled)
	}
	latest, exists := manager.GetByID(auth.ID)
	if !exists || !matches(ready) || !matches(latest) {
		return nil, errors.New("codex_quota_identity_changed")
	}
	quota, errFetch := h.fetchNativeAccountQuota(ctx, latest)
	if errFetch != nil {
		return nil, errFetch
	}
	latest, exists = manager.GetByID(auth.ID)
	if !exists || !matches(latest) {
		return nil, errors.New("codex_quota_identity_changed")
	}
	return marshalRPCResult(struct {
		AuthID   string          `json:"auth_id"`
		Provider string          `json:"provider"`
		Identity string          `json:"identity"`
		Quota    nativeQuotaData `json:"quota"`
	}{auth.ID, "codex", identity, quota})
}

func (h *Host) fetchNativeAccountQuota(ctx context.Context, auth *coreauth.Auth) (nativeQuotaData, error) {
	account, _, identity := nativeQuotaIdentity(auth)
	if identity == "" {
		return nativeQuotaData{}, errors.New("codex_quota_oauth_required")
	}
	cfg := h.currentRuntimeConfig()
	proxyURL := strings.TrimSpace(auth.ProxyURL)
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}
	setting, errProxy := proxyutil.Parse(proxyURL)
	if errProxy != nil || setting.Mode == proxyutil.ModeProxy && !proxyutil.ValidRequestProxy(proxyURL) {
		return nativeQuotaData{}, errors.New("codex_quota_invalid_proxy")
	}
	ctx = cliproxyexecutor.WithoutRequestProxyURL(ctx)
	client := helps.NewProxyAwareHTTPClient(ctx, cfg, auth, 0)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, nativeQuotaURL, nil)
	if errRequest != nil {
		return nativeQuotaData{}, errors.New("codex_quota_unavailable")
	}
	token, _ := auth.Metadata["access_token"].(string)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("ChatGPT-Account-Id", account)
	req.Header.Set("Accept", "application/json")
	// The generic HTTP bridge also logs raw upstream exchanges. This read-only
	// projection deliberately uses only its transport policy, never its logger.
	resp, errDo := client.Do(req)
	if errDo != nil {
		if ctx.Err() != nil {
			return nativeQuotaData{}, errors.New("codex_quota_cancelled")
		}
		return nativeQuotaData{}, errors.New("codex_quota_unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		code := "codex_quota_upstream_error"
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			code = "codex_quota_unauthorized"
		case http.StatusForbidden:
			code = "codex_quota_forbidden"
		case http.StatusTooManyRequests:
			code = "codex_quota_rate_limited"
		}
		return nativeQuotaData{}, errors.New(code)
	}
	raw, errRead := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if errRead != nil || len(raw) > 1<<20 {
		return nativeQuotaData{}, errors.New("codex_quota_invalid_response")
	}
	return normalizeNativeQuota(raw, time.Now().UTC())
}

func normalizeNativeQuota(raw []byte, fetched time.Time) (nativeQuotaData, error) {
	out := nativeQuotaData{Source: "codex_wham", FetchedAt: fetched.Format(time.RFC3339Nano), Availability: "unknown"}
	if !ojson.ValidBytes(raw) || !ojson.ParseBytes(raw).IsObject() {
		return out, errors.New("codex_quota_invalid_response")
	}
	root := ojson.ParseBytes(raw)
	if plan := nativeQuotaLabel(root.Get("plan_type")); plan != "" {
		out.Subscription = &pluginapi.QuotaSubscription{Plan: plan}
	}
	rate := root.Get("rate_limit")
	out.Allowed, out.LimitReached = nativeQuotaBool(rate.Get("allowed")), nativeQuotaBool(rate.Get("limit_reached"))
	permits := out.Allowed != nil && *out.Allowed || out.LimitReached != nil && !*out.LimitReached
	blocks := out.Allowed != nil && !*out.Allowed || out.LimitReached != nil && *out.LimitReached
	if permits && !blocks {
		out.Availability = "available"
	} else if blocks && !permits {
		out.Availability = "exhausted"
	}
	addGroup := func(name string, limits ojson.Result) {
		group := pluginapi.QuotaGroup{DisplayName: name}
		for _, window := range []string{"primary", "secondary"} {
			w := limits.Get(window + "_window")
			used := w.Get("used_percent")
			if used.Type != ojson.Number || math.IsNaN(used.Float()) || math.IsInf(used.Float(), 0) || used.Float() < 0 || used.Float() > 100 {
				continue
			}
			label := "主要窗口"
			if window == "secondary" {
				label = "次要窗口"
			}
			bucket := pluginapi.QuotaBucket{Window: window, RemainingFraction: 1 - used.Float()/100, Description: label}
			seconds := w.Get("limit_window_seconds")
			if seconds.Type == ojson.Number && seconds.Float() == float64(seconds.Int()) {
				switch seconds.Int() {
				case 18000:
					bucket.Window = "5h"
				case 604800:
					bucket.Window = "weekly"
				}
				if seconds.Int() > 0 && seconds.Int() <= 31536000 {
					bucket.Description += " · " + nativeQuotaDuration(seconds.Int())
				}
			}
			reset := w.Get("reset_at")
			if reset.Type == ojson.Number && reset.Int() > 0 && reset.Int() < 253402300800 && reset.Float() == float64(reset.Int()) {
				bucket.ResetTime = time.Unix(reset.Int(), 0).UTC().Format(time.RFC3339)
			}
			group.Buckets = append(group.Buckets, bucket)
		}
		if len(group.Buckets) > 0 {
			out.Groups = append(out.Groups, group)
		}
	}
	addGroup("Codex 账号额度", rate)
	addGroup("代码审查额度", root.Get("code_review_rate_limit"))
	for i, extra := range root.Get("additional_rate_limits").Array() {
		if i >= 64 {
			break
		}
		name := nativeQuotaLabel(extra.Get("limit_name"))
		if name == "" {
			name = nativeQuotaLabel(extra.Get("model_name"))
		}
		if name == "" {
			name = fmt.Sprintf("附加窗口 %d", i+1)
		}
		addGroup(name, extra.Get("rate_limit"))
	}
	models := root.Get("model_usage").Map()
	keys := make([]string, 0, len(models))
	for key := range models {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for i, key := range keys {
		if i >= 64 {
			break
		}
		if available := nativeQuotaBool(models[key].Get("available")); available != nil {
			label := nativeQuotaText(key)
			if label != "" {
				out.ModelStatuses = append(out.ModelStatuses, nativeQuotaModelStatus{label, *available})
			}
		}
	}
	if len(out.Groups) == 0 && out.Allowed == nil && out.LimitReached == nil && len(out.ModelStatuses) == 0 && out.Subscription == nil {
		return out, errors.New("codex_quota_unknown")
	}
	return out, nil
}

func nativeQuotaBool(value ojson.Result) *bool {
	if value.Type != ojson.True && value.Type != ojson.False {
		return nil
	}
	b := value.Bool()
	return &b
}

func nativeQuotaLabel(value ojson.Result) string {
	if value.Type != ojson.String {
		return ""
	}
	return nativeQuotaText(value.String())
}

func nativeQuotaText(value string) string {
	value = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value))
	runes := []rune(value)
	if len(runes) > 100 {
		runes = runes[:100]
	}
	return string(runes)
}

func nativeQuotaDuration(seconds int64) string {
	for _, unit := range []struct {
		seconds int64
		label   string
	}{{86400, "天"}, {3600, "小时"}, {60, "分钟"}, {1, "秒"}} {
		if seconds%unit.seconds == 0 {
			return fmt.Sprintf("%d %s", seconds/unit.seconds, unit.label)
		}
	}
	return ""
}
