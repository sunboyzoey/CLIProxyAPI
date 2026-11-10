package pluginhost

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestExecutorTraceUsesHostIDWithoutChangingCallerMetadata(t *testing.T) {
	req := coreexecutor.Request{Metadata: map[string]any{"cpa_request_id": "forged", "other": "preserved"}}
	ctx := logging.WithRequestID(context.Background(), "server-trace")
	result := buildTracedExecutorRequest(ctx, New(), "bps", nil, req, coreexecutor.Options{})
	if result.Metadata["cpa_request_id"] != "server-trace" || result.Metadata["other"] != "preserved" {
		t.Fatal("trace metadata was not isolated")
	}
	if req.Metadata["cpa_request_id"] != "forged" {
		t.Fatal("caller metadata was mutated")
	}
	result = buildTracedExecutorRequest(context.Background(), New(), "bps", nil, req, coreexecutor.Options{})
	if _, ok := result.Metadata["cpa_request_id"]; ok {
		t.Fatal("untrusted request ID survived")
	}
}
