package helps

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

// Capture the selected OAuth identity, never a refreshable token fingerprint.
// This immutable snapshot prevents delayed callbacks being attributed to a new
// credential that later occupies the same auth ID. No token leaves this helper.
func codexUsageAuthIdentity(provider string, auth *cliproxyauth.Auth) string {
	if provider != "codex" || auth == nil || auth.AuthKind() != cliproxyauth.AuthKindOAuth || cliproxyauth.IsCodexUseSIWC(auth) {
		return ""
	}
	if strings.TrimSpace(auth.Attributes["api_key"]) != "" {
		return ""
	}
	if key, _ := auth.Metadata["api_key"].(string); strings.TrimSpace(key) != "" {
		return ""
	}
	token, _ := auth.Metadata["access_token"].(string)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	claims := observedObject(raw)
	sub := claims["sub"]
	account := observedObject([]byte(claims["https://api.openai.com/auth"].Raw))["chatgpt_account_id"]
	if sub.Type != ojson.String || account.Type != ojson.String || sub.String() == "" || account.String() == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(sub.String() + "\x00" + account.String()))
	return hex.EncodeToString(hash[:])
}

// The legacy aggregate detail normalizes absent fields to zero and may infer a
// total. Preserve the upstream presence separately before those transformations.
func codexObservedTokens(raw []byte) *usage.ObservedTokens {
	object := observedObject(raw)
	if object == nil {
		return nil
	}
	inputDetails := observedObject([]byte(object["input_tokens_details"].Raw))
	outputDetails := observedObject([]byte(object["output_tokens_details"].Raw))
	out := &usage.ObservedTokens{
		InputTokens:         observedCounter(object["input_tokens"]),
		OutputTokens:        observedCounter(object["output_tokens"]),
		TotalTokens:         observedCounter(object["total_tokens"]),
		CacheReadTokens:     observedCounter(inputDetails["cached_tokens"]),
		CacheCreationTokens: observedCounter(inputDetails["cache_creation_tokens"]),
		ReasoningTokens:     observedCounter(outputDetails["reasoning_tokens"]),
	}
	if out.CacheReadTokens == nil {
		out.CacheReadTokens = observedCounter(object["cache_read_input_tokens"])
	}
	if out.CacheCreationTokens == nil {
		out.CacheCreationTokens = observedCounter(inputDetails["cache_write_tokens"])
	}
	if out.CacheCreationTokens == nil {
		out.CacheCreationTokens = observedCounter(object["cache_creation_input_tokens"])
	}
	if out.ReasoningTokens == nil {
		out.ReasoningTokens = observedCounter(object["reasoning_tokens"])
	}
	return out
}

// Reject duplicate properties, malformed objects, and coercible number strings.
func observedObject(raw []byte) map[string]ojson.Result {
	if !ojson.ValidBytes(raw) {
		return nil
	}
	value := ojson.ParseBytes(raw)
	if !value.IsObject() {
		return nil
	}
	out := map[string]ojson.Result{}
	valid := true
	value.ForEach(func(key, value ojson.Result) bool {
		if _, exists := out[key.String()]; exists {
			valid = false
			return false
		}
		out[key.String()] = value
		return true
	})
	if !valid {
		return nil
	}
	return out
}

func observedCounter(value ojson.Result) *int64 {
	if value.Type != ojson.Number {
		return nil
	}
	number, err := strconv.ParseInt(value.Raw, 10, 64)
	if err != nil || number < 0 {
		return nil
	}
	return &number
}

func hasObservedTokens(value *usage.ObservedTokens) bool {
	return value != nil && (value.InputTokens != nil || value.OutputTokens != nil || value.TotalTokens != nil || value.CacheReadTokens != nil || value.CacheCreationTokens != nil || value.ReasoningTokens != nil)
}

// Compact returns a plain Responses object instead of a terminal SSE envelope.
func ParseCodexCompactUsage(raw []byte) usage.Detail {
	detail := ParseOpenAIUsage(raw)
	root := ojson.ParseBytes(raw)
	detail.Observed = codexObservedTokens([]byte(root.Get("usage").Raw))
	detail.ResponseStatus = codexUsageResponseStatus(root)
	return detail
}

func codexUsageResponseStatus(root ojson.Result) string {
	status := root.Get("response.status").String()
	if status == "" {
		status = root.Get("status").String()
	}
	// A non-success response status must never be promoted by a contradictory
	// completed event label.
	if status == "failed" || status == "incomplete" {
		return status
	}
	switch root.Get("type").String() {
	case "response.completed":
		return "completed"
	case "response.incomplete":
		return "incomplete"
	case "response.failed":
		return "failed"
	}
	switch status {
	case "completed", "incomplete", "failed":
		return status
	}
	return ""
}
