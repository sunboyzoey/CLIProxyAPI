package pluginhost

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestTransportPolicyAfterAuthOnly(t *testing.T) {
	for _, mode := range []string{"websocket", "http", "invalid", ""} {
		t.Run(mode, func(t *testing.T) {
			host := newHostWithRecords(capabilityRecord{id: "policy", plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{RequestInterceptor: requestInterceptorFunc(func(_ context.Context, r pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
				if r.Provider != "codex" || r.AuthID != "selected" {
					t.Fatal("selected auth identity lost")
				}
				return pluginapi.RequestInterceptResponse{UpstreamTransport: mode}, nil
			})}}})
			req := pluginapi.RequestInterceptRequest{Provider: "codex", AuthID: "selected"}
			if got := host.InterceptRequestBeforeAuth(t.Context(), req); got.UpstreamTransport != "" {
				t.Fatal("before-auth policy accepted")
			}
			want := mode
			if mode == "invalid" {
				want = ""
			}
			if got := host.InterceptRequestAfterAuth(t.Context(), req); got.UpstreamTransport != want {
				t.Fatalf("transport=%q want=%q", got.UpstreamTransport, want)
			}
		})
	}
}
