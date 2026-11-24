package handlers

import (
	"net/http"
	"strings"

	"github.com/MoeForge/moego/ojson"
)

// SanitizeBPSPublicError runs only at the client response boundary. Internal
// errors keep their original codes for scheduling, cooldowns and diagnostics.
// Rebuild from safe fields rather than replacing words in upstream messages.
func SanitizeBPSPublicError(status int, raw string) string {
	root := ojson.Parse(raw)
	node := root
	for _, path := range []string{"error", "response.error", "body.error"} {
		if candidate := root.Get(path); candidate.IsObject() {
			node = candidate
			break
		}
	}
	message := raw
	if root.IsObject() {
		message = node.Get("message").String()
	}
	originalCode := strings.ToLower(strings.TrimSpace(node.Get("code").String()))
	private := privateBPSErrorText(originalCode) || privateBPSErrorText(message)
	for _, object := range []ojson.Result{root, node} {
		provider := strings.ToLower(strings.TrimSpace(object.Get("provider").String()))
		private = private || provider == "bps" || provider == "basispoints"
	}
	if !private {
		return raw
	}

	code, kind, messageOut := "upstream_error", "server_error", "The upstream service could not complete the request."
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		code, kind, messageOut = "invalid_request_error", "invalid_request_error", "The request contains an unsupported or invalid parameter."
	case http.StatusUnauthorized:
		code, kind, messageOut = "upstream_authentication_required", "authentication_error", "Upstream authentication is unavailable."
	case http.StatusForbidden:
		code, kind, messageOut = "permission_denied", "permission_error", "The upstream service denied this request."
	case http.StatusNotFound:
		code, kind, messageOut = "resource_not_found", "invalid_request_error", "The requested resource is unavailable."
	case http.StatusConflict:
		code, kind, messageOut = "request_conflict", "invalid_request_error", "The request conflicts with the current service state."
	case http.StatusTooManyRequests:
		code, kind, messageOut = "rate_limit_exceeded", "rate_limit_error", "The service is temporarily rate limited. Retry after the indicated delay."
	case http.StatusServiceUnavailable:
		code, messageOut = "service_unavailable", "The service is temporarily unavailable."
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		code, messageOut = "request_timeout", "The upstream request did not complete in time."
	case 499:
		code, messageOut = "request_canceled", "The request was canceled."
	}

	// Specific caller-actionable reasons are fixed text, never upstream prose.
	param := ""
	signal := strings.ToLower(originalCode + " " + message)
	if status == http.StatusBadRequest || status == http.StatusUnprocessableEntity {
		switch {
		case strings.Contains(signal, "web_search.user_location"):
			code, param = "unsupported_value", "tools[].user_location"
			messageOut = "Location-aware search is unavailable in strict mode. An administrator may enable approximate query hints; they do not enforce geographic filtering."
			if strings.Contains(signal, "must be an approximate") {
				code = "invalid_value"
				messageOut = "user_location must be a valid approximate location object."
			}
		case strings.Contains(signal, "web_search.filters.allowed_domains"):
			code, param, messageOut = "unsupported_value", "tools[].filters.allowed_domains", "The configured search backend does not support domain filtering."
		case strings.Contains(signal, "tool_choice"):
			code, param = "unsupported_value", "tool_choice"
			messageOut = "tool_choice must be auto, none, required, or an unambiguous declared function/custom tool with a matching type."
		case strings.Contains(signal, "function_call.arguments"):
			code, param = "invalid_tool_arguments", "input"
			messageOut = "Historical function arguments must be a complete JSON object. Restore the original tool call."
		case strings.Contains(signal, "no matching original call"):
			code, param = "invalid_tool_history", "input"
			messageOut = "A tool result has no matching original call. Provide the complete call and result history."
		case strings.Contains(signal, "context_length_exceeded"):
			code, messageOut = "context_length_exceeded", "The request exceeds the model context limit."
		case strings.Contains(signal, "content_policy"), strings.Contains(signal, "cyber_policy"), strings.Contains(signal, "request_rejected"):
			code, messageOut = "request_rejected", "The upstream service rejected this request under its usage policies."
		}
	}
	if status == http.StatusNotFound && strings.Contains(signal, "previous_response") {
		code, param, messageOut = "previous_response_not_found", "previous_response_id", "The previous response is unavailable. Provide the complete conversation history."
	}
	doc := ojson.NewDocString("{}")
	_ = doc.Set("error.type", kind)
	_ = doc.Set("error.code", code)
	_ = doc.Set("error.message", messageOut)
	if param != "" {
		_ = doc.Set("error.param", param)
	}
	// Preserve numeric retry metadata and SSE ordering without exposing account
	// identities, provider names, upstream bodies or deployment paths.
	for _, field := range []string{"retry_after_seconds", "reset_seconds"} {
		value := node.Get(field)
		if value.Type == ojson.Number && value.Int() >= 0 {
			_ = doc.Set("error."+field, value.Int())
		}
	}
	if value := node.Get("retryable"); value.Type == ojson.True || value.Type == ojson.False {
		_ = doc.Set("error.retryable", value.Bool())
	}
	if value := root.Get("sequence_number"); value.Type == ojson.Number && value.Int() >= 0 {
		_ = doc.Set("sequence_number", value.Int())
	}
	return doc.String()
}

func privateBPSErrorText(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "basispoints") {
		return true
	}
	for _, token := range strings.FieldsFunc(lower, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_')
	}) {
		if token == "bps" || strings.HasPrefix(token, "bps_") || strings.HasPrefix(token, "invalid_bps_") {
			return true
		}
	}
	return false
}
