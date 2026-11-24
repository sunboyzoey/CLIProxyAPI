package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestRPCRequestScopeLifecycleAndConflictingQuotaFlag(t *testing.T) {
	lookup := newTestSymbolLookup(&testPlugin{registerResult: validTestPlugin("request-scope")})
	if _, err := registerRPCPlugin(context.Background(), nil, "request-scope", lookup, pluginabi.MethodPluginRegister, nil); err != nil {
		t.Fatal(err)
	}
	if !lookup.lastLifecycle.RequestScopeErrors {
		t.Fatal("host did not advertise request-scope error support")
	}
	for _, credentialScope := range []bool{false, true} {
		detail := &pluginabi.Error{Code: "local_admission", Message: "local_admission", HTTPStatus: 429, RequestScope: true, CredentialScope: credentialScope}
		_, decoded := decodeEnvelopeResult[rpcEmptyResponse](pluginabi.Envelope{Error: detail})
		for _, err := range []error{detail, decoded, rpcStreamError("", detail)} {
			var scoped coreexecutor.RequestScopedError
			if !errors.As(err, &scoped) || scoped.IsRequestScoped() == credentialScope {
				t.Fatal("request scope lost or suppressed explicit credential quota")
			}
		}
	}
}

func TestRPCRequestScopeStreamCallbacks(t *testing.T) {
	for _, method := range []string{"emit", "close"} {
		t.Run(method, func(t *testing.T) {
			host := New()
			id, chunks, cleanup := host.streams.open(context.Background())
			defer cleanup()
			doc := ojson.NewDocString(`{"error_detail":{"code":"bps_rate_wait_timeout","message":"bps_rate_wait_timeout","http_status":429,"request_scope":true}}`)
			doc.Set("stream_id", id)
			raw := doc.Bytes()
			var err error
			if method == "emit" {
				_, err = host.callHostStreamEmit(context.Background(), raw)
			} else {
				_, err = host.callHostStreamClose(raw)
			}
			if err != nil {
				t.Fatal(err)
			}
			chunk := <-chunks
			var scoped coreexecutor.RequestScopedError
			if !errors.As(chunk.Err, &scoped) || !scoped.IsRequestScoped() {
				t.Fatal("stream callback dropped request scope")
			}
		})
	}
}

// Real auth-manager contract: local admission must preserve HTTP status while
// neither marking quota/model cooldown nor replaying the request on another auth.
func TestRPCRequestScopeDoesNotCoolOrRotateCredentials(t *testing.T) {
	for _, mode := range []string{"sync", "stream-bootstrap", "stream-chunk"} {
		for code, status := range map[string]int{"bps_rate_queue_full": 429, "bps_rate_wait_timeout": 429, "bps_rate_limiter_closed": 503, "bps_start_authorization_blocked": 409, "bps_start_authorization_stale": 409} {
			t.Run(mode+"/"+code, func(t *testing.T) {
				provider := "request-scope-" + mode + "-" + code
				const model = "request-scope-model"
				detail := &pluginabi.Error{Code: code, Message: code, HTTPStatus: status, RequestScope: true}
				_, failure := decodeEnvelopeResult[rpcEmptyResponse](pluginabi.Envelope{Error: detail})
				if mode != "sync" {
					failure = rpcStreamError("", detail)
				}
				record := normalizeTestCapabilityRecord(capabilityRecord{id: provider})
				host := newHostWithRecords(record)
				calls := 0
				executor := &fakeExecutor{identifier: provider,
					execute: func(context.Context, pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
						calls++
						return pluginapi.ExecutorResponse{}, failure
					},
					executeStream: func(context.Context, pluginapi.ExecutorRequest) (pluginapi.ExecutorStreamResponse, error) {
						calls++
						if mode == "stream-bootstrap" {
							return pluginapi.ExecutorStreamResponse{}, failure
						}
						chunks := make(chan pluginapi.ExecutorStreamChunk, 2)
						chunks <- pluginapi.ExecutorStreamChunk{Payload: []byte("data: {\"id\":\"r\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"}}]}\n\n")}
						chunks <- pluginapi.ExecutorStreamChunk{Err: failure}
						close(chunks)
						return pluginapi.ExecutorStreamResponse{Chunks: chunks}, nil
					},
				}
				adapter := newExecutorAdapterForRecordForTest(host, record, executor, []sdktranslator.Format{sdktranslator.FormatOpenAI}, []sdktranslator.Format{sdktranslator.FormatOpenAI})
				adapter.provider = provider
				manager := coreauth.NewManager(nil, nil, nil)
				manager.RegisterExecutor(adapter)
				ids := []string{provider + "-a", provider + "-b"}
				for _, id := range ids {
					if _, err := manager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: provider, Status: coreauth.StatusActive, FileName: id + ".json", Attributes: map[string]string{"type": "api_key"}}); err != nil {
						t.Fatal(err)
					}
					registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: model}})
					t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
				}
				request := coreexecutor.Request{Model: model, Payload: []byte(`{"messages":[]}`)}
				options := coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI, ResponseFormat: sdktranslator.FormatOpenAI}
				var err error
				if mode == "sync" {
					_, err = manager.Execute(context.Background(), []string{provider}, request, options)
				} else {
					var stream *coreexecutor.StreamResult
					stream, err = manager.ExecuteStream(context.Background(), []string{provider}, request, options)
					if stream != nil {
						for chunk := range stream.Chunks {
							if chunk.Err != nil {
								err = chunk.Err
							}
						}
					}
				}
				var statusErr interface{ StatusCode() int }
				if err == nil || !errors.As(err, &statusErr) || statusErr.StatusCode() != status || calls != 1 {
					t.Fatalf("lost status or retried local failure: err=%v calls=%d expected=%d", err, calls, status)
				}
				for _, id := range ids {
					state, ok := manager.GetByID(id)
					if !ok {
						t.Fatal("authorization disappeared")
					}
					if state.Quota.Exceeded || state.Unavailable || !state.NextRetryAfter.IsZero() {
						t.Fatalf("local failure cooled account %s: %+v", id, state.Quota)
					}
					for name, modelState := range state.ModelStates {
						if modelState.Quota.Exceeded || modelState.Unavailable || !modelState.NextRetryAfter.IsZero() {
							t.Fatal(fmt.Sprintf("local failure cooled model %s: %+v", name, modelState))
						}
					}
				}
			})
		}
	}
}
