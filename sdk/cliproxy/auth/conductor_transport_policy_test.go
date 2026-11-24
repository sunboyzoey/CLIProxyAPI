package auth

import (
	"context"
	"testing"

	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestAfterAuthTransportPolicyAttemptIsolation(t *testing.T) {
	req := core.Request{Model: "gpt-6-astra", Payload: []byte(`{"stream":true}`)}
	opts := core.Options{Stream: true, SourceFormat: translator.FormatOpenAIResponse, Metadata: map[string]any{core.SelectedAuthMetadataKey: "selected"}}
	opts.RequestAfterAuthInterceptor = func(_ context.Context, r core.RequestAfterAuthInterceptRequest) core.RequestAfterAuthInterceptResponse {
		if r.Provider != "codex" || !r.Stream || r.SourceFormat != translator.FormatOpenAIResponse {
			t.Fatalf("missing selected attempt context: %+v", r)
		}
		if r.AuthID == "selected" {
			return core.RequestAfterAuthInterceptResponse{UpstreamTransport: "websocket"}
		}
		if r.AuthID == "invalid" {
			return core.RequestAfterAuthInterceptResponse{UpstreamTransport: "bogus"}
		}
		return core.RequestAfterAuthInterceptResponse{}
	}
	for _, tc := range []struct{ id, want string }{{"selected", "websocket"}, {"other", ""}, {"selected", "websocket"}, {"invalid", ""}} {
		opts.Metadata[core.SelectedAuthMetadataKey] = tc.id
		_, next, errIntercept := prepareRequestAfterAuth(t.Context(), nil, nil, "codex", req, opts, req.Model)
		if errIntercept != nil {
			t.Fatal(errIntercept)
		}
		if next.UpstreamTransport != tc.want {
			t.Fatalf("auth %s transport=%q want=%q", tc.id, next.UpstreamTransport, tc.want)
		}
		opts = next
	}
}
