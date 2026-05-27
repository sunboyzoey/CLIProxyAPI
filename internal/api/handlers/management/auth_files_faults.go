package management

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	faultSweepDefaultConcurrency = 16
	faultSweepMaxConcurrency     = 64
	faultSweepMaxBodyBytes       = 1 << 20

	antigravityDefaultProjectID = "bamboo-precept-lgxtn"
)

var (
	faultSweepAntigravityModelURLs = []string{
		"https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:fetchAvailableModels",
		"https://cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels",
	}
	faultSweepGeminiCLIQuotaURL = "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota"
	faultSweepClaudeUsageURL    = "https://api.anthropic.com/api/oauth/usage"
	faultSweepCodexUsageURL     = "https://chatgpt.com/backend-api/wham/usage"
	faultSweepKimiUsageURL      = "https://api.kimi.com/coding/v1/usages"
	faultSweepXAIBillingURL     = "https://cli-chat-proxy.grok.com/v1/billing"
)

type removeFaultyAuthFilesRequest struct {
	Concurrency  int      `json:"concurrency"`
	Providers    []string `json:"providers"`
	ReloadMemory *bool    `json:"reload_memory"`
}

type removeFaultyAuthFilesResponse struct {
	Status         string                  `json:"status"`
	Total          int                     `json:"total"`
	Checked        int                     `json:"checked"`
	OK             int                     `json:"ok"`
	Removed401     int                     `json:"removed_401"`
	Quarantined429 int                     `json:"quarantined_429"`
	Failed         int                     `json:"failed"`
	Skipped        int                     `json:"skipped"`
	MemoryReloaded bool                    `json:"memory_reloaded"`
	ReloadError    string                  `json:"reload_error,omitempty"`
	DurationMS     int64                   `json:"duration_ms"`
	Details        []faultSweepAuthOutcome `json:"details,omitempty"`
}

type faultSweepAuthOutcome struct {
	ID         string `json:"id,omitempty"`
	FileName   string `json:"file_name,omitempty"`
	Provider   string `json:"provider,omitempty"`
	Status     string `json:"status"`
	StatusCode int    `json:"status_code,omitempty"`
	Message    string `json:"message,omitempty"`
}

// RemoveFaultyAuthFiles checks all in-memory OAuth credentials, removes auths
// that return 401, and quarantines auths that return 429.
func (h *Handler) RemoveFaultyAuthFiles(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager unavailable"})
		return
	}

	var req removeFaultyAuthFilesRequest
	if c.Request.Body != nil && c.Request.ContentLength != 0 {
		if errBind := c.ShouldBindJSON(&req); errBind != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}
	}

	concurrency := req.Concurrency
	if concurrency <= 0 {
		concurrency = faultSweepDefaultConcurrency
	}
	if concurrency > faultSweepMaxConcurrency {
		concurrency = faultSweepMaxConcurrency
	}

	reloadMemory := true
	if req.ReloadMemory != nil {
		reloadMemory = *req.ReloadMemory
	}

	providerFilter := normalizeFaultSweepProviderFilter(req.Providers)
	auths := h.authManager.List()
	start := time.Now()

	jobs := make(chan *coreauth.Auth)
	results := make(chan faultSweepAuthOutcome)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for auth := range jobs {
				results <- h.checkFaultyAuth(c.Request.Context(), auth, providerFilter)
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, auth := range auths {
			select {
			case <-c.Request.Context().Done():
				return
			case jobs <- auth:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	resp := removeFaultyAuthFilesResponse{
		Status: "ok",
		Total:  len(auths),
	}
	for result := range results {
		if result.Status != "ok" {
			resp.Details = append(resp.Details, result)
		}
		switch result.Status {
		case "ok":
			resp.OK++
			resp.Checked++
		case "removed_401":
			resp.Removed401++
			resp.Checked++
		case "quarantined_429":
			resp.Quarantined429++
			resp.Checked++
		case "failed":
			resp.Failed++
			resp.Checked++
		default:
			resp.Skipped++
		}
	}

	sort.Slice(resp.Details, func(i, j int) bool {
		if resp.Details[i].Status == resp.Details[j].Status {
			return resp.Details[i].ID < resp.Details[j].ID
		}
		return resp.Details[i].Status < resp.Details[j].Status
	})

	if reloadMemory {
		preservedAuths := faultSweepPreservedRuntimeAuths(h.authManager.List())
		if errLoad := h.authManager.Load(c.Request.Context()); errLoad != nil {
			resp.ReloadError = errLoad.Error()
			log.WithError(errLoad).Warn("management remove-faulty auth memory reload failed")
		} else {
			resp.MemoryReloaded = true
			if errRestore := h.restoreFaultSweepPreservedAuths(c.Request.Context(), preservedAuths); errRestore != nil {
				resp.ReloadError = errRestore.Error()
				log.WithError(errRestore).Warn("management remove-faulty preserved auth restore failed")
			}
		}
	}
	resp.DurationMS = time.Since(start).Milliseconds()

	c.JSON(http.StatusOK, resp)
}

func faultSweepPreservedRuntimeAuths(auths []*coreauth.Auth) []*coreauth.Auth {
	preserved := make([]*coreauth.Auth, 0)
	for _, auth := range auths {
		if auth == nil || strings.TrimSpace(auth.ID) == "" {
			continue
		}
		if kind, _ := auth.AccountInfo(); strings.EqualFold(strings.TrimSpace(kind), "api_key") {
			preserved = append(preserved, auth.Clone())
			continue
		}
		if authPathForFaultSweep(auth) == "" {
			preserved = append(preserved, auth.Clone())
		}
	}
	return preserved
}

func (h *Handler) restoreFaultSweepPreservedAuths(ctx context.Context, auths []*coreauth.Auth) error {
	if h == nil || h.authManager == nil || len(auths) == 0 {
		return nil
	}
	var errs []string
	for _, auth := range auths {
		if auth == nil || strings.TrimSpace(auth.ID) == "" {
			continue
		}
		if _, ok := h.authManager.GetByID(auth.ID); ok {
			continue
		}
		if _, errRegister := h.authManager.Register(ctx, auth); errRegister != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", auth.ID, errRegister))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func normalizeFaultSweepProviderFilter(providers []string) map[string]struct{} {
	if len(providers) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		provider = strings.ToLower(strings.TrimSpace(provider))
		if provider != "" {
			out[provider] = struct{}{}
		}
	}
	return out
}

func (h *Handler) checkFaultyAuth(ctx context.Context, auth *coreauth.Auth, providerFilter map[string]struct{}) faultSweepAuthOutcome {
	out := faultSweepOutcomeForAuth(auth)
	if auth == nil || strings.TrimSpace(auth.ID) == "" {
		out.Status = "skipped"
		out.Message = "empty auth"
		return out
	}

	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	if len(providerFilter) > 0 {
		if _, ok := providerFilter[provider]; !ok {
			out.Status = "skipped"
			out.Message = "provider filtered"
			return out
		}
	}
	if auth.Disabled || auth.Status == coreauth.StatusDisabled {
		out.Status = "skipped"
		out.Message = "auth disabled"
		return out
	}
	if kind, _ := auth.AccountInfo(); strings.EqualFold(strings.TrimSpace(kind), "api_key") {
		out.Status = "skipped"
		out.Message = "api key auth is not checked by OAuth quota sweep"
		return out
	}
	if !faultSweepProviderSupported(provider) {
		out.Status = "skipped"
		out.Message = "provider has no OAuth quota check"
		return out
	}
	if (provider == "gemini-cli" || provider == "gemini") && geminiCLIProjectID(auth) == "" {
		out.Status = "skipped"
		out.Message = "gemini-cli project id not found"
		return out
	}

	token, errToken := h.resolveTokenForAuth(ctx, auth)
	if errToken != nil {
		statusCode := apiCallErrorStatusCode(errToken)
		return h.applyFaultSweepFailure(ctx, auth, out, statusCode, errToken.Error())
	}
	if strings.TrimSpace(token) == "" {
		out.Status = "skipped"
		out.Message = "auth token not found"
		return out
	}

	statusCode, message, errCheck := h.checkFaultyAuthProvider(ctx, auth, provider, token)
	if errCheck != nil {
		if statusCode == 0 {
			statusCode = apiCallErrorStatusCode(errCheck)
		}
		return h.applyFaultSweepFailure(ctx, auth, out, statusCode, errCheck.Error())
	}
	return h.applyFaultSweepFailure(ctx, auth, out, statusCode, message)
}

func faultSweepProviderSupported(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "antigravity", "claude", "anthropic", "codex", "gemini-cli", "gemini", "kimi", "xai":
		return true
	default:
		return false
	}
}

func faultSweepOutcomeForAuth(auth *coreauth.Auth) faultSweepAuthOutcome {
	if auth == nil {
		return faultSweepAuthOutcome{Status: "skipped"}
	}
	return faultSweepAuthOutcome{
		ID:       strings.TrimSpace(auth.ID),
		FileName: strings.TrimSpace(auth.FileName),
		Provider: strings.TrimSpace(auth.Provider),
		Status:   "skipped",
	}
}

func (h *Handler) applyFaultSweepFailure(ctx context.Context, auth *coreauth.Auth, out faultSweepAuthOutcome, statusCode int, message string) faultSweepAuthOutcome {
	message = strings.TrimSpace(message)
	out.StatusCode = statusCode
	out.Message = message

	if statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices {
		out.Status = "ok"
		out.Message = ""
		return out
	}

	switch statusCode {
	case http.StatusUnauthorized:
		h.markFaultSweepResult(ctx, auth, statusCode, "fault sweep upstream returned 401")
		out.Status = "removed_401"
		if out.Message == "" {
			out.Message = "unauthorized"
		}
	case http.StatusTooManyRequests:
		h.markFaultSweepResult(ctx, auth, statusCode, "fault sweep upstream returned 429")
		out.Status = "quarantined_429"
		if out.Message == "" {
			out.Message = "rate limited"
		}
	case 0:
		out.Status = "failed"
		if out.Message == "" {
			out.Message = "request failed"
		}
	default:
		out.Status = "failed"
	}
	return out
}

func (h *Handler) markFaultSweepResult(ctx context.Context, auth *coreauth.Auth, statusCode int, message string) {
	if h == nil || h.authManager == nil || auth == nil || strings.TrimSpace(auth.ID) == "" {
		return
	}
	code := "upstream_error"
	if statusCode == http.StatusUnauthorized {
		code = "unauthorized"
	} else if statusCode == http.StatusTooManyRequests {
		code = "rate_limited"
	}
	h.authManager.MarkResult(ctx, coreauth.Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Success:  false,
		Error: &coreauth.Error{
			Code:       code,
			Message:    message,
			HTTPStatus: statusCode,
			Retryable:  statusCode == http.StatusTooManyRequests,
		},
	})
}

func (h *Handler) checkFaultyAuthProvider(ctx context.Context, auth *coreauth.Auth, provider, token string) (int, string, error) {
	switch provider {
	case "antigravity":
		return h.checkAntigravityFault(ctx, auth, token)
	case "claude", "anthropic":
		return h.checkOAuthFaultURL(ctx, auth, http.MethodGet, faultSweepClaudeUsageURL, map[string]string{
			"Authorization":  "Bearer " + token,
			"Content-Type":   "application/json",
			"anthropic-beta": "oauth-2025-04-20",
		}, nil)
	case "codex":
		headers := map[string]string{
			"Authorization": "Bearer " + token,
			"Content-Type":  "application/json",
			"User-Agent":    "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal",
		}
		if accountID := codexAccountID(auth); accountID != "" {
			headers["Chatgpt-Account-Id"] = accountID
		}
		return h.checkOAuthFaultURL(ctx, auth, http.MethodGet, faultSweepCodexUsageURL, headers, nil)
	case "gemini-cli", "gemini":
		projectID := geminiCLIProjectID(auth)
		body, _ := json.Marshal(map[string]string{"project": projectID})
		return h.checkOAuthFaultURL(ctx, auth, http.MethodPost, faultSweepGeminiCLIQuotaURL, map[string]string{
			"Authorization": "Bearer " + token,
			"Content-Type":  "application/json",
		}, body)
	case "kimi":
		return h.checkOAuthFaultURL(ctx, auth, http.MethodGet, faultSweepKimiUsageURL, map[string]string{
			"Authorization": "Bearer " + token,
		}, nil)
	case "xai":
		return h.checkOAuthFaultURL(ctx, auth, http.MethodGet, faultSweepXAIBillingURL, map[string]string{
			"Authorization": "Bearer " + token,
		}, nil)
	default:
		return 0, "", nil
	}
}

func (h *Handler) checkAntigravityFault(ctx context.Context, auth *coreauth.Auth, token string) (int, string, error) {
	projectID := antigravityProjectID(auth)
	body, _ := json.Marshal(map[string]string{"project": projectID})
	var lastStatus int
	var lastMessage string
	for _, targetURL := range faultSweepAntigravityModelURLs {
		statusCode, message, errCheck := h.checkOAuthFaultURL(ctx, auth, http.MethodPost, targetURL, map[string]string{
			"Authorization": "Bearer " + token,
			"Content-Type":  "application/json",
			"User-Agent":    "antigravity/1.11.5 windows/amd64",
		}, body)
		if errCheck != nil {
			return statusCode, message, errCheck
		}
		if statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices {
			return statusCode, message, nil
		}
		lastStatus = statusCode
		lastMessage = message
		if statusCode == http.StatusUnauthorized || statusCode == http.StatusTooManyRequests {
			return statusCode, message, nil
		}
	}
	return lastStatus, lastMessage, nil
}

func (h *Handler) checkOAuthFaultURL(ctx context.Context, auth *coreauth.Auth, method, targetURL string, headers map[string]string, body []byte) (int, string, error) {
	if strings.TrimSpace(targetURL) == "" {
		return 0, "quota URL is empty", nil
	}
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, errReq := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if errReq != nil {
		return 0, "", errReq
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Transport: h.apiCallTransport(auth)}
	resp, errDo := client.Do(req)
	if errDo != nil {
		return 0, "", errDo
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("fault sweep response body close error: %v", errClose)
		}
	}()

	respBody, errRead := io.ReadAll(io.LimitReader(resp.Body, faultSweepMaxBodyBytes))
	if errRead != nil {
		return resp.StatusCode, "", errRead
	}
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return resp.StatusCode, "", nil
	}
	return resp.StatusCode, faultSweepErrorMessage(resp.StatusCode, respBody), nil
}

func faultSweepErrorMessage(statusCode int, body []byte) string {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return fmt.Sprintf("HTTP %d", statusCode)
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err == nil {
		if msg := nestedString(parsed, "error", "message"); msg != "" {
			return fmt.Sprintf("%d %s", statusCode, msg)
		}
		if msg := stringFromAny(parsed["message"]); msg != "" {
			return fmt.Sprintf("%d %s", statusCode, msg)
		}
		if msg := stringFromAny(parsed["error"]); msg != "" {
			return fmt.Sprintf("%d %s", statusCode, msg)
		}
	}
	return fmt.Sprintf("%d %s", statusCode, string(body))
}

func antigravityProjectID(auth *coreauth.Auth) string {
	if projectID := projectIDFromAuth(auth); projectID != "" {
		return projectID
	}
	if projectID := projectIDFromAuthFile(auth); projectID != "" {
		return projectID
	}
	return antigravityDefaultProjectID
}

func geminiCLIProjectID(auth *coreauth.Auth) string {
	return projectIDFromAuth(auth)
}

func projectIDFromAuth(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	for _, attrs := range []map[string]string{auth.Attributes} {
		for _, key := range []string{"project_id", "projectId", "project"} {
			if v := strings.TrimSpace(attrs[key]); v != "" {
				return v
			}
		}
		if v := projectIDFromAccountString(attrs["account"]); v != "" {
			return v
		}
	}
	for _, metadata := range []map[string]any{auth.Metadata} {
		for _, key := range []string{"project_id", "projectId", "project"} {
			if v := stringFromAny(metadata[key]); v != "" {
				return v
			}
		}
		if v := projectIDFromAccountString(stringFromAny(metadata["account"])); v != "" {
			return v
		}
	}
	if _, account := auth.AccountInfo(); account != "" {
		return projectIDFromAccountString(account)
	}
	return ""
}

func projectIDFromAuthFile(auth *coreauth.Auth) string {
	path := authPathForFaultSweep(auth)
	if path == "" {
		return ""
	}
	data, errRead := os.ReadFile(path)
	if errRead != nil || len(data) == 0 {
		return ""
	}
	var root map[string]any
	if errUnmarshal := json.Unmarshal(data, &root); errUnmarshal != nil {
		return ""
	}
	if v := projectIDFromMap(root); v != "" {
		return v
	}
	for _, key := range []string{"installed", "web"} {
		if nested, ok := root[key].(map[string]any); ok {
			if v := projectIDFromMap(nested); v != "" {
				return v
			}
		}
	}
	return ""
}

func projectIDFromMap(values map[string]any) string {
	if len(values) == 0 {
		return ""
	}
	for _, key := range []string{"project_id", "projectId", "project"} {
		if v := stringFromAny(values[key]); v != "" {
			return v
		}
	}
	return ""
}

func projectIDFromAccountString(account string) string {
	account = strings.TrimSpace(account)
	if account == "" {
		return ""
	}
	lastOpen := strings.LastIndex(account, "(")
	lastClose := strings.LastIndex(account, ")")
	if lastOpen < 0 || lastClose <= lastOpen {
		return ""
	}
	return strings.TrimSpace(account[lastOpen+1 : lastClose])
}

func authPathForFaultSweep(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil {
		if path := strings.TrimSpace(auth.Attributes["path"]); path != "" {
			return filepath.Clean(path)
		}
	}
	if strings.TrimSpace(auth.ID) != "" && filepath.IsAbs(auth.ID) {
		return filepath.Clean(auth.ID)
	}
	if strings.TrimSpace(auth.FileName) != "" && filepath.IsAbs(auth.FileName) {
		return filepath.Clean(auth.FileName)
	}
	return ""
}

func codexAccountID(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	for _, metadata := range []map[string]any{auth.Metadata} {
		for _, key := range []string{"account_id", "accountId", "chatgpt_account_id", "chatgptAccountId"} {
			if v := stringFromAny(metadata[key]); v != "" {
				return v
			}
		}
		if v := chatGPTAccountIDFromJWT(stringFromAny(metadata["id_token"])); v != "" {
			return v
		}
	}
	if auth.Attributes != nil {
		for _, key := range []string{"account_id", "accountId", "chatgpt_account_id", "chatgptAccountId"} {
			if v := strings.TrimSpace(auth.Attributes[key]); v != "" {
				return v
			}
		}
		if v := chatGPTAccountIDFromJWT(strings.TrimSpace(auth.Attributes["id_token"])); v != "" {
			return v
		}
	}
	return ""
}

func chatGPTAccountIDFromJWT(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, errDecode := base64.RawURLEncoding.DecodeString(parts[1])
	if errDecode != nil {
		return ""
	}
	var claims map[string]any
	if errUnmarshal := json.Unmarshal(payload, &claims); errUnmarshal != nil {
		return ""
	}
	return firstStringFromMap(claims, "chatgpt_account_id", "chatgptAccountId")
}

func firstStringFromMap(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if v := stringFromAny(values[key]); v != "" {
			return v
		}
	}
	return ""
}

func nestedString(values map[string]any, keys ...string) string {
	var current any = values
	for _, key := range keys {
		asMap, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = asMap[key]
	}
	return stringFromAny(current)
}

func stringFromAny(raw any) string {
	switch typed := raw.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return ""
	}
}
