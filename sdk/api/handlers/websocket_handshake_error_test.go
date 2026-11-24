package handlers

import (
	"github.com/MoeForge/moego/ojson"
	"testing"
)

func TestWebsocketHandshakeErrorPreservesPublicClassification(t *testing.T) {
	doc := ojson.NewDocString("{}")
	doc.Set("error.type", "permission_error")
	doc.Set("error.code", "websocket_handshake_rejected")
	doc.Set("error.message", "Upstream rejected the WebSocket handshake (HTTP 403) without an explanation.")
	body := doc.String()
	for _, tc := range []struct {
		name, path string
		body       []byte
	}{
		{name: "HTTP JSON", path: "error.code", body: BuildErrorResponseBody(403, body)},
		{name: "Responses error", path: "error.code", body: BuildOpenAIResponsesStreamErrorChunk(403, body, 0)},
		{name: "Responses failed", path: "response.error.code", body: BuildOpenAIResponsesStreamFailedChunk(403, body, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ojson.GetBytes(tc.body, tc.path).String(); got != "websocket_handshake_rejected" {
				t.Fatalf("wrong public error code %q: %s", got, tc.body)
			}
		})
	}
}
