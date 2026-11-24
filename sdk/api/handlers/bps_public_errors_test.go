package handlers

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/MoeForge/moego/ojson"
)

func TestBPSPublicErrorsAcrossResponseFormats(t *testing.T) {
	cases := []struct {
		name, raw, code string
		status          int
	}{
		{"validation", "basispoints_request_invalid: This BPS transport supports tool_choice auto or none.", "unsupported_value", 400},
		{"protocol", "basispoints_protocol_error", "upstream_error", 502},
		{"stream", "bps_incomplete_stream", "upstream_error", 502},
		{"identity", "bps_binding_identity_changed: private-account@example.test", "request_conflict", 409},
		{"quota", "bps_account_quota_exhausted", "rate_limit_exceeded", 429},
		{"auth", "bps_reauthorization_required", "upstream_authentication_required", 401},
		{"capacity", "basispoints_image_relay_unavailable", "service_unavailable", 503},
		{"history", "bps_previous_response_not_found", "previous_response_not_found", 404},
		{"policy", "bps_cyber_policy", "request_rejected", 400},
		{"context", "bps_context_length_exceeded", "context_length_exceeded", 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			builders := []struct {
				name, path string
				build      func() []byte
			}{
				{"http", "error", func() []byte { return BuildErrorResponseBodyWithError(tc.status, tc.raw, errors.New(tc.raw)) }},
				{"sse", "error", func() []byte { return BuildOpenAIResponsesStreamErrorChunk(tc.status, tc.raw, 7) }},
				{"failed", "response.error", func() []byte { return BuildOpenAIResponsesStreamFailedChunk(tc.status, tc.raw, 7) }},
			}
			for _, builder := range builders {
				body := string(builder.build())
				if !ojson.Valid(body) || privateBPSErrorText(body) || strings.Contains(body, "private-account") {
					t.Fatalf("%s leaked or invalid: %s", builder.name, body)
				}
				if got := ojson.Get(body, builder.path+".code").String(); got != tc.code {
					t.Fatalf("%s code=%s want=%s", builder.name, got, tc.code)
				}
				if builder.name != "http" && ojson.Get(body, "sequence_number").Int() != 7 {
					t.Fatalf("sequence lost: %s", body)
				}
			}
		})
	}
}

func TestBPSPublicErrorStructuredMetadata(t *testing.T) {
	for _, path := range []string{"error", "response.error", "body.error", ""} {
		input := ojson.NewDocString("{}")
		prefix := path
		if prefix != "" {
			prefix += "."
		}
		_ = input.Set(prefix+"code", "model_cooldown")
		_ = input.Set(prefix+"provider", "bps")
		_ = input.Set(prefix+"message", "private deployment path /root/private and token secret")
		_ = input.Set(prefix+"reset_seconds", 123)
		_ = input.Set(prefix+"retry_after_seconds", 4)
		_ = input.Set(prefix+"retryable", false)
		_ = input.Set(prefix+"extra", "private-account")
		_ = input.Set("sequence_number", 9)
		raw := input.String()
		for _, body := range []string{string(BuildErrorResponseBody(429, raw)), string(BuildOpenAIResponsesStreamErrorChunk(429, raw, 1))} {
			if privateBPSErrorText(body) || strings.Contains(body, "private") || strings.Contains(body, "secret") {
				t.Fatalf("leaked: %s", body)
			}
			if ojson.Get(body, "error.reset_seconds").Int() != 123 || ojson.Get(body, "error.retry_after_seconds").Int() != 4 || ojson.Get(body, "sequence_number").Int() != 9 {
				t.Fatalf("metadata lost: %s", body)
			}
			if value := ojson.Get(body, "error.retryable"); value.Type != ojson.False {
				t.Fatalf("retry flag lost: %s", body)
			}
		}
	}
}

func TestBPSPublicErrorDoesNotAlterOtherProviders(t *testing.T) {
	for _, raw := range []string{"usage_limit_reached", "request speed 12 kbps", "unexpected EOF"} {
		if got := SanitizeBPSPublicError(502, raw); got != raw {
			t.Fatalf("changed %q into %q", raw, got)
		}
	}
	input := ojson.NewDocString("{}")
	_ = input.Set("error.code", "model_cooldown")
	_ = input.Set("error.provider", "codex")
	_ = input.Set("error.message", "Usage limit reached.")
	raw := input.String()
	if got := SanitizeBPSPublicError(429, raw); got != raw {
		t.Fatalf("non-BPS JSON changed: %s", got)
	}
}

func TestBPSPublicHeaderFiltering(t *testing.T) {
	original := http.Header{"X-BPS-Upstream-Transport": {"websocket"}, "x-basispoints-debug": {"private"}, "Retry-After": {"7"}, "X-Request-Id": {"request123"}}
	out := FilterUpstreamHeaders(original)
	if len(out) != 2 || out.Get("Retry-After") != "7" || out.Get("X-Request-Id") != "request123" {
		t.Fatalf("unexpected headers: %v", out)
	}
	if len(original) != 4 {
		t.Fatal("internal diagnostic headers were mutated")
	}
}

func TestBPSPublicSearchAndToolChoiceDiagnostics(t *testing.T) {
	for _, tc := range []struct{ message, code, param string }{
		{"web_search.user_location requires an explicitly enabled query-hint compatibility mode", "unsupported_value", "tools[].user_location"},
		{"web_search.user_location must be an approximate location object", "invalid_value", "tools[].user_location"},
		{"web_search.filters.allowed_domains is not supported", "unsupported_value", "tools[].filters.allowed_domains"},
		{"tool_choice must select auto, none, required", "unsupported_value", "tool_choice"},
	} {
		doc := ojson.NewDocString("{}")
		_ = doc.Set("error.code", "basispoints_request_invalid")
		_ = doc.Set("error.message", tc.message+" private-value")
		result := SanitizeBPSPublicError(400, doc.String())
		out := ojson.Parse(result)
		if out.Get("error.code").String() != tc.code || out.Get("error.param").String() != tc.param || strings.Contains(result, "private-value") {
			t.Fatalf("wrong safe error: %s", result)
		}
	}
}
