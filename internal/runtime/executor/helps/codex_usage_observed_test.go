package helps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/MoeForge/moego/base64"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

func observedTestAuth(suffix string) *cliproxyauth.Auth {
	token := "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"subject-a","https://api.openai.com/auth":{"chatgpt_account_id":"account-a"}}`)) + "." + suffix
	return &cliproxyauth.Auth{ID: "native.json", Provider: "codex", Metadata: map[string]any{"access_token": token}}
}

func TestCodexUsageIdentityCapturedBeforeRefreshOrReplacement(t *testing.T) {
	auth := observedTestAuth("first")
	reporter := NewUsageReporter(context.Background(), "codex", "gpt-test", auth)
	expected := sha256.Sum256([]byte("subject-a\x00account-a"))
	want := hex.EncodeToString(expected[:])
	if reporter.authIdentity != want {
		t.Fatal("OAuth identity did not use subject and account")
	}
	auth.Metadata["access_token"] = observedTestAuth("refreshed").Metadata["access_token"]
	reporter.UpdateAccessTokenFingerprint(auth)
	if reporter.buildRecord(usage.Detail{}, false).AuthIdentity != want {
		t.Fatal("refresh split stable OAuth identity")
	}
	auth.Metadata["access_token"] = "unreadable-replacement"
	reporter.UpdateAccessTokenFingerprint(auth)
	if reporter.buildRecord(usage.Detail{}, false).AuthIdentity != want {
		t.Fatal("replacement changed an executing attempt identity")
	}
	additional, ok := reporter.buildAdditionalModelRecord("gpt-image-test", usage.Detail{InputTokens: 1, OutputTokens: 1})
	if !ok || !additional.Supplemental || reporter.buildRecord(usage.Detail{}, false).Supplemental {
		t.Fatal("additional model accounting was not separated from execution counts")
	}
	for _, modify := range []func(*cliproxyauth.Auth){
		func(a *cliproxyauth.Auth) { a.Attributes = map[string]string{"api_key": "synthetic-key"} },
		func(a *cliproxyauth.Auth) { a.Metadata["api_key"] = "synthetic-key" },
		func(a *cliproxyauth.Auth) { a.Metadata["use_siwc"] = true },
		func(a *cliproxyauth.Auth) { a.Metadata["access_token"] = "invalid" },
	} {
		candidate := observedTestAuth("fixture")
		modify(candidate)
		if codexUsageAuthIdentity("codex", candidate) != "" {
			t.Fatal("nonstandard/API-key identity accepted")
		}
	}
	if codexUsageAuthIdentity("bps", observedTestAuth("fixture")) != "" {
		t.Fatal("BPS identity accepted by native sink")
	}
}

func TestCodexObservedUsagePreservesZerosMissingAndMalformed(t *testing.T) {
	detail, ok := ParseCodexUsage([]byte(`{"type":"response.completed","response":{"usage":{"input_tokens":20,"output_tokens":0,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}}}`))
	if !ok || detail.Observed == nil || detail.Observed.InputTokens == nil || *detail.Observed.InputTokens != 20 || detail.Observed.OutputTokens == nil || *detail.Observed.OutputTokens != 0 || detail.Observed.ReasoningTokens == nil || *detail.Observed.ReasoningTokens != 0 {
		t.Fatal("measured zero or nonzero counter missing")
	}
	if detail.Observed.TotalTokens != nil || detail.Observed.CacheCreationTokens != nil || detail.ResponseStatus != "completed" {
		t.Fatal("inferred total or missing cache count reported as measured")
	}
	for _, raw := range []string{
		`{"input_tokens":-1,"output_tokens":1.5,"total_tokens":9223372036854775808}`,
		`{"input_tokens":"1","output_tokens":null}`,
		`{"input_tokens":1,"input_tokens":2}`,
	} {
		counters := codexObservedTokens([]byte(raw))
		if hasObservedTokens(counters) {
			t.Fatal("invalid counters accepted")
		}
	}
	cacheWrite := codexObservedTokens([]byte(`{"input_tokens_details":{"cache_write_tokens":4}}`))
	if cacheWrite == nil || cacheWrite.CacheCreationTokens == nil || *cacheWrite.CacheCreationTokens != 4 {
		t.Fatal("measured cache-write alias lost")
	}
	compact := ParseCodexCompactUsage([]byte(`{"usage":{"input_tokens":4,"output_tokens":0}}`))
	if compact.Observed == nil || compact.Observed.InputTokens == nil || *compact.Observed.InputTokens != 4 || compact.Observed.OutputTokens == nil || compact.Observed.TotalTokens != nil {
		t.Fatal("compact usage lost presence")
	}
}

func TestCodexObservedStreamPreservesExplicitZeroAndTerminalOutcome(t *testing.T) {
	var buffer StreamUsageBuffer
	if !buffer.ObserveResponsesStream([]byte(`data: {"type":"response.completed","response":{"service_tier":"default","usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}}`)) {
		t.Fatal("all-zero terminal measurement ignored")
	}
	if buffer.detail.Observed == nil || buffer.detail.Observed.InputTokens == nil || *buffer.detail.Observed.InputTokens != 0 {
		t.Fatal("all-zero stream usage became missing")
	}
	for _, status := range []string{"incomplete", "failed"} {
		detail, ok := ParseCodexUsage([]byte(`{"type":"response.` + status + `","response":{}}`))
		if !ok || detail.ResponseStatus != status || detail.Observed != nil {
			t.Fatal("terminal outcome without usage was lost")
		}
	}
	conflict, ok := ParseCodexUsage([]byte(`{"type":"response.completed","response":{"status":"failed"}}`))
	if !ok || conflict.ResponseStatus != "failed" {
		t.Fatal("contradictory completion promoted an explicit failure")
	}
	for _, tc := range []struct {
		err  error
		code string
	}{{context.Canceled, "context_canceled"}, {context.DeadlineExceeded, "context_deadline_exceeded"}, {errors.New("synthetic other failure"), ""}} {
		if failure := failFromErrors(tc.err); failure.Code != tc.code {
			t.Fatal("cancellation classification lost")
		}
	}
}
