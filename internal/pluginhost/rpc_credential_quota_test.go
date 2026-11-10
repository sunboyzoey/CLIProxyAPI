package pluginhost

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// Exercise the RPC error bridge through the real auth manager. A shared quota
// failure must make sibling models unavailable without cooling another account.
func TestRPCCredentialQuotaUsesNativeAccountCooldown(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		t.Run(fmt.Sprint(scoped), func(t *testing.T) {
			const modelA = "rpc-scope-model-a"
			const modelB = "rpc-scope-model-b"
			provider := "rpc-scope-provider-" + fmt.Sprint(scoped)
			authID := "rpc-scope-account-" + fmt.Sprint(scoped)
			_, quotaErr := decodeEnvelopeResult[rpcEmptyResponse](pluginabi.Envelope{Error: &pluginabi.Error{
				Code: "bps_insufficient_quota", Message: "bps_insufficient_quota", HTTPStatus: http.StatusTooManyRequests,
				RetryAfterSeconds: 120, CredentialScope: scoped,
			}})
			record := normalizeTestCapabilityRecord(capabilityRecord{id: "rpc-scope-plugin-" + fmt.Sprint(scoped)})
			host := newHostWithRecords(record)
			calls := []string{}
			executor := &fakeExecutor{identifier: provider, execute: func(_ context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
				calls = append(calls, req.AuthID+"/"+req.Model)
				if req.Model == modelA {
					return pluginapi.ExecutorResponse{}, quotaErr
				}
				return pluginapi.ExecutorResponse{Payload: []byte(`{"choices":[]}`)}, nil
			}}
			adapter := newExecutorAdapterForRecordForTest(host, record, executor, []sdktranslator.Format{sdktranslator.FormatOpenAI}, []sdktranslator.Format{sdktranslator.FormatOpenAI})
			adapter.provider = provider
			manager := coreauth.NewManager(nil, nil, nil)
			manager.RegisterExecutor(adapter)
			register := func(id string) {
				if _, err := manager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: provider, Status: coreauth.StatusActive, FileName: id + ".json", Attributes: map[string]string{"type": "api_key"}}); err != nil {
					t.Fatal(err)
				}
				registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: modelA}, {ID: modelB}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
			}
			register(authID)
			execute := func(model string) error {
				_, err := manager.Execute(context.Background(), []string{provider}, coreexecutor.Request{Model: model, Payload: []byte(`{"messages":[]}`)}, coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI, ResponseFormat: sdktranslator.FormatOpenAI})
				return err
			}
			if err := execute(modelA); err == nil {
				t.Fatal("quota failure lost")
			}
			state, _ := manager.GetByID(authID)
			if scoped && (!state.Quota.Exceeded || state.Quota.Reason != "credential_quota") {
				t.Fatalf("missing native account cooldown: %+v", state.Quota)
			}
			before := len(calls)
			err := execute(modelB)
			if scoped {
				if err == nil || len(calls) != before {
					t.Fatal("sibling model bypassed credential quota")
				}
				register(authID + "-other")
				if err := execute(modelB); err != nil {
					t.Fatalf("independent credential unavailable: %v", err)
				}
				if calls[len(calls)-1] != authID+"-other/"+modelB {
					t.Fatal("cooled credential was selected")
				}
			} else if err != nil || len(calls) != before+1 {
				t.Fatalf("model-only error blocked sibling: %v", err)
			}
		})
	}
}
