package test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/translator"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	openaihandlers "github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// Set CPA_CODEX_WS_POLICY_PLUGIN to the built standalone library to exercise the
// real C ABI, selected-auth hook, HTTP handler and native upstream transports.
func TestCodexWSPolicyPluginHTTPIntegration(t *testing.T) {
	library := os.Getenv("CPA_CODEX_WS_POLICY_PLUGIN")
	if library == "" {
		t.Skip("set CPA_CODEX_WS_POLICY_PLUGIN to the built codex-ws-bridge library")
	}
	binary, errRead := os.ReadFile(library)
	if errRead != nil {
		t.Fatal(errRead)
	}
	for _, tc := range []struct {
		name, mode, selected              string
		legacy, disconnect, rejectUpgrade bool
		wantWS, wantHTTP                  int
	}{
		{name: "selected account", mode: "websocket", selected: "selected.json", wantWS: 1},
		{name: "unselected account", mode: "websocket", selected: "other.json", wantHTTP: 1},
		{name: "force HTTP overrides legacy", mode: "http", selected: "selected.json", legacy: true, wantHTTP: 1},
		{name: "sent disconnect never replays", mode: "websocket", selected: "selected.json", disconnect: true, wantWS: 1},
		{name: "handshake fallback before sending", mode: "websocket", selected: "selected.json", rejectUpgrade: true, wantWS: 1, wantHTTP: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var wsCount, httpCount atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				completed := `{"type":"response.completed","response":{"id":"resp_local","model":"gpt-6-astra","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`
				if !websocket.IsWebSocketUpgrade(r) {
					httpCount.Add(1)
					w.Header().Set("Content-Type", "text/event-stream")
					if _, errWrite := fmt.Fprintf(w, "data: %s\n\n", completed); errWrite != nil {
						t.Error(errWrite)
					}
					return
				}
				wsCount.Add(1)
				if tc.rejectUpgrade {
					w.WriteHeader(http.StatusUpgradeRequired)
					return
				}
				conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if errUpgrade != nil {
					t.Error(errUpgrade)
					return
				}
				defer func() {
					if errClose := conn.Close(); errClose != nil {
						t.Log(errClose)
					}
				}()
				for turn := 1; ; turn++ {
					if _, _, errRead := conn.ReadMessage(); errRead != nil {
						if tc.name != "selected account" {
							t.Error(errRead)
						}
						return
					}
					if tc.disconnect {
						return
					}
					doc := ojson.NewDocString(completed)
					doc.Set("response.id", fmt.Sprintf("resp_local_%d", turn))
					completed = doc.String()
					for _, event := range []string{`{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_local","call_id":"call_local","name":"lookup","arguments":""}}`, `{"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_local","delta":"{}"}`, completed} {
						if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(event)); errWrite != nil {
							t.Error(errWrite)
							return
						}
					}
					if tc.name != "selected account" {
						return
					}
				}
			}))
			defer upstream.Close()
			dir := t.TempDir()
			platform := filepath.Join(dir, runtime.GOOS, runtime.GOARCH)
			if errMkdir := os.MkdirAll(platform, 0700); errMkdir != nil {
				t.Fatal(errMkdir)
			}
			if errWrite := os.WriteFile(filepath.Join(platform, "codex-ws-bridge"+filepath.Ext(library)), binary, 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			cfg, errConfig := config.ParseConfigBytes([]byte(fmt.Sprintf("plugins:\n  enabled: true\n  dir: %q\n  configs:\n    codex-ws-bridge:\n      enabled: true\n      mode: %s\n      auth_ids: [%s]\n", dir, tc.mode, tc.selected)))
			if errConfig != nil {
				t.Fatal(errConfig)
			}
			cfg.SDKConfig.Streaming.BootstrapRetries = 2
			host := pluginhost.New()
			t.Cleanup(host.ShutdownAll)
			host.ApplyConfig(t.Context(), cfg)
			if !host.PluginRegistered("codex-ws-bridge") {
				t.Fatal("native policy plugin did not register")
			}
			manager := coreauth.NewManager(nil, &coreauth.RoundRobinSelector{}, nil)
			manager.SetRetryConfig(2, 0, 0)
			executor := runtimeexecutor.NewCodexAutoExecutor(cfg)
			defer executor.CloseExecutionSession(coreauth.CloseAllExecutionSessionsID)
			manager.RegisterExecutor(executor)
			const authID = "selected.json"
			registry.GetGlobalRegistry().RegisterClient(authID, "codex", []*registry.ModelInfo{{ID: "gpt-6-astra"}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authID) })
			if _, errRegister := manager.Register(t.Context(), &coreauth.Auth{ID: authID, Provider: "codex", Status: coreauth.StatusActive, Attributes: map[string]string{"base_url": upstream.URL}, Metadata: map[string]any{"access_token": "synthetic-token", "http_sse_websockets": tc.legacy, "disable_cooling": true}}); errRegister != nil {
				t.Fatal(errRegister)
			}
			gin.SetMode(gin.TestMode)
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-6-astra","stream":true,"input":"hello"}`))
			c.Request.Header.Set("Content-Type", "application/json")
			base := handlers.NewBaseAPIHandlers(&cfg.SDKConfig, manager)
			base.SetPluginHost(host)
			openaihandlers.NewOpenAIResponsesAPIHandler(base).Responses(c)
			if got := int(wsCount.Load()); got != tc.wantWS {
				t.Fatalf("WS calls=%d want=%d body=%s", got, tc.wantWS, recorder.Body.String())
			}
			if got := int(httpCount.Load()); got != tc.wantHTTP {
				t.Fatalf("HTTP calls=%d want=%d body=%s", got, tc.wantHTTP, recorder.Body.String())
			}
			if tc.name == "selected account" {
				for turn := 2; turn <= 10; turn++ {
					repeat := httptest.NewRecorder()
					next, _ := gin.CreateTestContext(repeat)
					next.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-6-astra","stream":true,"input":[{"role":"user","content":"hello"},{"role":"assistant","content":"prior reply"},{"role":"user","content":"next question"}]}`))
					next.Request.Header.Set("Content-Type", "application/json")
					openaihandlers.NewOpenAIResponsesAPIHandler(base).Responses(next)
					if repeat.Code != http.StatusOK || !strings.Contains(repeat.Body.String(), fmt.Sprintf("resp_local_%d", turn)) {
						t.Fatalf("pooled turn %d: %d %s", turn, repeat.Code, repeat.Body.String())
					}
				}
				if wsCount.Load() != 1 || httpCount.Load() != 0 {
					t.Fatalf("ten plugin requests: WS handshakes=%d HTTP=%d", wsCount.Load(), httpCount.Load())
				}
				nextCfg, errNext := config.ParseConfigBytes([]byte(fmt.Sprintf("plugins:\n  enabled: true\n  dir: %q\n  configs:\n    codex-ws-bridge:\n      enabled: true\n      mode: http\n      auth_ids: [selected.json]\n", dir)))
				if errNext != nil {
					t.Fatal(errNext)
				}
				host.ApplyConfig(t.Context(), nextCfg)
				if !host.PluginRegistered("codex-ws-bridge") {
					t.Fatal("policy failed reconfiguration")
				}
				nextRecorder := httptest.NewRecorder()
				nextContext, _ := gin.CreateTestContext(nextRecorder)
				nextContext.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-6-astra","stream":true,"input":"after reload"}`))
				nextContext.Request.Header.Set("Content-Type", "application/json")
				openaihandlers.NewOpenAIResponsesAPIHandler(base).Responses(nextContext)
				if nextRecorder.Code != http.StatusOK || wsCount.Load() != 1 || httpCount.Load() != 1 {
					t.Fatalf("hot reload did not switch transport: WS=%d HTTP=%d response=%s", wsCount.Load(), httpCount.Load(), nextRecorder.Body.String())
				}
			}
			if tc.disconnect {
				if recorder.Code < 400 && !strings.Contains(recorder.Body.String(), "error") {
					t.Fatal("disconnect did not surface error")
				}
			} else {
				if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "response.completed") {
					t.Fatalf("response %d: %s", recorder.Code, recorder.Body.String())
				}
				if tc.wantWS == 1 && tc.wantHTTP == 0 && !strings.Contains(recorder.Body.String(), "response.function_call_arguments.delta") {
					t.Fatal("tool event was lost")
				}
			}
		})
	}
}
