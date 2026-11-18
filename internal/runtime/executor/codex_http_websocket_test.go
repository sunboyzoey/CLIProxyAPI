package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func httpWSAuth(url string) *auth.Auth {
	return &auth.Auth{ID: "http-ws-test", Provider: "codex", Attributes: map[string]string{"base_url": url}, Metadata: map[string]any{"access_token": "test", "http_sse_websockets": true}}
}

func httpWSRequest() (core.Request, core.Options) {
	return core.Request{Model: "gpt-6-astra", Payload: []byte(`{"model":"gpt-6-astra","stream":true,"input":[]}`)}, core.Options{SourceFormat: translator.FormatOpenAIResponse, ResponseFormat: translator.FormatOpenAIResponse}
}

func closeHTTPWSTestConn(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	if errClose := conn.Close(); errClose != nil {
		t.Logf("close test websocket: %v", errClose)
	}
}

func TestCodexHTTPWebsocketEligibility(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*auth.Auth, *core.Request, *core.Options)
		want   bool
	}{
		{name: "independent opt in", want: true},
		{name: "plugin enables without auth flag", want: true, change: func(a *auth.Auth, _ *core.Request, o *core.Options) {
			delete(a.Metadata, "http_sse_websockets")
			o.UpstreamTransport = "websocket"
		}},
		{name: "plugin forces HTTP over auth flag", change: func(_ *auth.Auth, _ *core.Request, o *core.Options) { o.UpstreamTransport = "http" }},
		{name: "plugin cannot enable API key", change: func(a *auth.Auth, _ *core.Request, o *core.Options) {
			a.Attributes["api_key"] = "key"
			o.UpstreamTransport = "websocket"
		}},
		{name: "plugin cannot enable BPS", change: func(a *auth.Auth, _ *core.Request, o *core.Options) {
			a.Provider = "bps"
			o.UpstreamTransport = "websocket"
		}},
		{name: "plugin cannot enable continuation", change: func(_ *auth.Auth, r *core.Request, o *core.Options) {
			r.Payload = []byte(`{"stream":true,"previous_response_id":"prior"}`)
			o.UpstreamTransport = "websocket"
		}},
		{name: "client header cannot enable", change: func(a *auth.Auth, _ *core.Request, o *core.Options) {
			delete(a.Metadata, "http_sse_websockets")
			o.Headers = http.Header{"Upstream-Transport": {"websocket"}}
			o.Metadata = map[string]any{"upstream_transport": "websocket"}
		}},
		{name: "off", change: func(a *auth.Auth, _ *core.Request, _ *core.Options) { delete(a.Metadata, "http_sse_websockets") }},
		{name: "string is not opt in", change: func(a *auth.Auth, _ *core.Request, _ *core.Options) { a.Metadata["http_sse_websockets"] = "true" }},
		{name: "api key", change: func(a *auth.Auth, _ *core.Request, _ *core.Options) { a.Attributes["api_key"] = "key" }},
		{name: "bps", change: func(a *auth.Auth, _ *core.Request, _ *core.Options) { a.Provider = "bps" }},
		{name: "compact", change: func(_ *auth.Auth, _ *core.Request, o *core.Options) { o.Alt = "responses/compact" }},
		{name: "chat bridge", change: func(_ *auth.Auth, _ *core.Request, o *core.Options) { o.SourceFormat = translator.FormatOpenAI }},
		{name: "nonstream", change: func(_ *auth.Auth, r *core.Request, _ *core.Options) { r.Payload = []byte(`{"stream":false}`) }},
		{name: "continuation", change: func(_ *auth.Auth, r *core.Request, _ *core.Options) {
			r.Payload = []byte(`{"stream":true,"previous_response_id":"resp_old"}`)
		}},
		{name: "malformed continuation", change: func(_ *auth.Auth, r *core.Request, _ *core.Options) {
			r.Payload = []byte(`{"stream":true,"previous_response_id":17}`)
		}},
		{name: "null continuation", want: true, change: func(_ *auth.Auth, r *core.Request, _ *core.Options) {
			r.Payload = []byte(`{"stream":true,"previous_response_id":null}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := httpWSAuth("http://example.invalid")
			req, opts := httpWSRequest()
			if tc.change != nil {
				tc.change(a, &req, &opts)
			}
			if got := codexHTTPWebsocketsEnabled(t.Context(), a, req, opts); got != tc.want {
				t.Fatalf("eligibility=%v, want %v", got, tc.want)
			}
			if codexHTTPWebsocketsEnabled(core.WithDownstreamWebsocket(t.Context()), a, req, opts) {
				t.Fatal("client websocket selected HTTP bridge")
			}
		})
	}
}

func TestCodexHTTPWebsocketStreamsToolsAndFinalPayload(t *testing.T) {
	firstRead := make(chan struct{})
	captured := make(chan []byte, 1)
	events := []string{
		`{"type":"response.created","sequence_number":0,"response":{"id":"resp_tools","model":"gpt-6-astra","status":"in_progress"}}`,
		`{"type":"response.output_item.added","sequence_number":1,"output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"lookup","arguments":""}}`,
		`{"type":"response.function_call_arguments.delta","sequence_number":2,"item_id":"fc_1","output_index":0,"delta":"{}"}`,
		`{"type":"response.output_item.done","sequence_number":3,"output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"lookup","arguments":"{}","status":"completed"}}`,
		`{"type":"response.output_item.added","sequence_number":4,"output_index":1,"item":{"type":"custom_tool_call","id":"ct_1","call_id":"call_2","name":"apply_patch","input":""}}`,
		`{"type":"response.custom_tool_call_input.delta","sequence_number":5,"item_id":"ct_1","output_index":1,"delta":"*** Begin Patch"}`,
		`{"type":"response.reasoning_summary_text.delta","sequence_number":6,"item_id":"rs_1","output_index":2,"summary_index":0,"delta":"Checking"}`,
		`{"type":"response.image_generation_call.partial_image","sequence_number":7,"item_id":"img_1","output_index":3,"partial_image_index":0,"partial_image_b64":"eA=="}`,
		`{"type":"response.vendor_extension","sequence_number":8,"detail":{"keep":true}}`,
		`{"type":"response.completed","sequence_number":9,"response":{"id":"resp_tools","model":"gpt-6-astra","status":"completed","output":[],"usage":{"input_tokens":7,"output_tokens":3,"total_tokens":10}}}`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !websocket.IsWebSocketUpgrade(r) {
			t.Error("expected WS upgrade")
			w.WriteHeader(500)
			return
		}
		conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Error(errUpgrade)
			return
		}
		defer closeHTTPWSTestConn(t, conn)
		_, body, errRead := conn.ReadMessage()
		if errRead != nil {
			t.Error(errRead)
			return
		}
		captured <- body
		for i, event := range events {
			if i == 1 {
				select {
				case <-firstRead:
				case <-t.Context().Done():
					return
				}
			}
			if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(event)); errWrite != nil {
				t.Error(errWrite)
				return
			}
		}
	}))
	defer server.Close()
	cfg := &config.Config{Codex: config.CodexConfig{StreamBootstrapBuffering: true}, SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}, Payload: config.PayloadConfig{
		Override: []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"instructions": "configured", "parallel_tool_calls": false}}},
		Filter:   []config.PayloadFilterRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: []string{"store"}}},
	}}
	exec := NewCodexAutoExecutor(cfg)
	req, opts := httpWSRequest()
	req.Payload = []byte(`{"model":"gpt-6-astra","stream":true,"store":false,"parallel_tool_calls":true,"instructions":"original","tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{}}},{"type":"custom","name":"apply_patch"}],"input":[{"type":"function_call_output","call_id":"prior_call","output":"found"},{"type":"custom_tool_call_output","call_id":"prior_custom","output":"patched"}]}`)
	var finalized atomic.Int32
	opts.Metadata = map[string]any{core.ExecutionSessionMetadataKey: t.Name(), core.FinalizedResponseFormatCallbackMetadataKey: func(string) { finalized.Add(1) }}
	before := helps.PayloadConfigEvaluationCount()
	result, errExecute := exec.ExecuteStream(t.Context(), httpWSAuth(server.URL), req, opts)
	if errExecute != nil {
		t.Fatal(errExecute)
	}
	var payloads [][]byte
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatal(chunk.Err)
		}
		if len(payloads) == 0 {
			close(firstRead)
		}
		payloads = append(payloads, bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(chunk.Payload), []byte("data:"))))
	}
	if len(payloads) != len(events) {
		t.Fatalf("events=%d, want %d", len(payloads), len(events))
	}
	for i, want := range events[:len(events)-1] {
		if !bytes.Equal(payloads[i], []byte(want)) {
			t.Errorf("event %d changed: %s", i, payloads[i])
		}
	}
	terminal := payloads[len(payloads)-1]
	for path, want := range map[string]int64{"sequence_number": 9, "response.usage.input_tokens": 7, "response.usage.output_tokens": 3, "response.usage.total_tokens": 10} {
		if got := ojson.GetBytes(terminal, path).Int(); got != want {
			t.Errorf("%s=%d want %d", path, got, want)
		}
	}
	if ojson.GetBytes(terminal, "response.id").String() != "resp_tools" || ojson.GetBytes(terminal, "response.output.0.call_id").String() != "call_1" {
		t.Fatalf("terminal output lost: %s", terminal)
	}
	body := <-captured
	if ojson.GetBytes(body, "type").String() != "response.create" || ojson.GetBytes(body, "instructions").String() != "configured" || ojson.GetBytes(body, "parallel_tool_calls").Bool() || ojson.GetBytes(body, "store").Exists() {
		t.Fatalf("final payload rules lost: %s", body)
	}
	if ojson.GetBytes(body, "input.0.call_id").String() != "prior_call" || ojson.GetBytes(body, "input.0.output").String() != "found" || ojson.GetBytes(body, "tools.#").Int() != 2 || ojson.GetBytes(body, "input.1.call_id").String() != "prior_custom" || ojson.GetBytes(body, "input.1.output").String() != "patched" {
		t.Fatalf("tool history or definitions lost: %s", body)
	}
	if finalized.Load() != 1 || helps.PayloadConfigEvaluationCount()-before != 1 {
		t.Fatal("payload configuration was not applied exactly once")
	}
}

func TestCodexHTTPWebsocketHandshakeFallback(t *testing.T) {
	for _, status := range []int{400, 404, 405, 426, 502, 503, 504, 401, 403, 429} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var upgrades, posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if websocket.IsWebSocketUpgrade(r) {
					upgrades.Add(1)
					w.Header().Set("Retry-After", "60")
					w.WriteHeader(status)
					return
				}
				posts.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"http_fallback\",\"status\":\"completed\",\"output\":[]}}\n\n")
			}))
			defer server.Close()
			req, opts := httpWSRequest()
			result, errExecute := NewCodexAutoExecutor(&config.Config{}).ExecuteStream(t.Context(), httpWSAuth(server.URL), req, opts)
			fallback := status != 401 && status != 403 && status != 429
			if fallback {
				if errExecute != nil {
					t.Fatal(errExecute)
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
				}
				if posts.Load() != 1 {
					t.Fatal("missing single HTTP fallback")
				}
			} else {
				if errExecute == nil {
					t.Fatal("auth/quota error bypassed")
				}
				var sc interface{ StatusCode() int }
				if !errors.As(errExecute, &sc) || sc.StatusCode() != status {
					t.Fatalf("status lost: %v", errExecute)
				}
				if posts.Load() != 0 {
					t.Fatal("unexpected HTTP fallback")
				}
			}
			if upgrades.Load() != 1 {
				t.Fatalf("upgrades=%d", upgrades.Load())
			}
		})
	}
}

func TestCodexHTTPWebsocketAfterSendErrorsDoNotReplay(t *testing.T) {
	for _, tc := range []struct {
		name, event string
		status      int
	}{
		{name: "clean close before terminal", status: 502},
		{name: "quota after send", event: `{"type":"error","status":429,"error":{"code":"rate_limit_exceeded","message":"slow down"}}`, status: 429},
		{name: "auth after send", event: `{"type":"error","status":401,"error":{"code":"invalid_api_key","message":"expired"}}`, status: 401},
		{name: "failed response", event: `{"type":"response.failed","status":500,"response":{"id":"r1","status":"failed","error":{"code":"server_error","message":"failed"}}}`, status: 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if errUpgrade != nil {
					t.Error(errUpgrade)
					return
				}
				defer closeHTTPWSTestConn(t, conn)
				if _, _, errRead := conn.ReadMessage(); errRead != nil {
					t.Error(errRead)
					return
				}
				if tc.event != "" {
					if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(tc.event)); errWrite != nil {
						t.Error(errWrite)
					}
				} else {
					if errWrite := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); errWrite != nil {
						t.Error(errWrite)
					}
				}
			}))
			defer server.Close()
			req, opts := httpWSRequest()
			opts.Metadata = map[string]any{core.ExecutionSessionMetadataKey: t.Name()}
			exec := NewCodexAutoExecutor(&config.Config{})
			result, errExecute := exec.ExecuteStream(t.Context(), httpWSAuth(server.URL), req, opts)
			if errExecute != nil {
				t.Fatal(errExecute)
			}
			var terminalErr error
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					terminalErr = chunk.Err
				}
			}
			var sc interface{ StatusCode() int }
			if !auth.IsRequestStopError(terminalErr) || !errors.As(terminalErr, &sc) || sc.StatusCode() != tc.status {
				t.Fatalf("unsafe or incorrect error: %v", terminalErr)
			}
			if tc.event == "" && !strings.Contains(terminalErr.Error(), "upstream_stream_incomplete") {
				t.Fatal(terminalErr)
			}
			if attempts.Load() != 1 {
				t.Fatalf("request replayed %d times", attempts.Load())
			}
		})
	}
}

func TestCodexHTTPWebsocketCancellationClosesUpstream(t *testing.T) {
	received := make(chan struct{})
	closed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Error(errUpgrade)
			return
		}
		defer closeHTTPWSTestConn(t, conn)
		if _, _, errRead := conn.ReadMessage(); errRead != nil {
			t.Error(errRead)
			return
		}
		close(received)
		_, _, _ = conn.ReadMessage()
		close(closed)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, opts := httpWSRequest()
	result, errExecute := NewCodexAutoExecutor(&config.Config{}).ExecuteStream(ctx, httpWSAuth(server.URL), req, opts)
	if errExecute != nil {
		t.Fatal(errExecute)
	}
	<-received
	cancel()
	for range result.Chunks {
	}
	<-closed
}

func TestCodexHTTPWebsocketConfiguredContinuationIsNotOverwritten(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { attempts.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	cfg := &config.Config{Payload: config.PayloadConfig{Override: []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"previous_response_id": "configured_parent"}}}}}
	req, opts := httpWSRequest()
	_, errExecute := NewCodexAutoExecutor(cfg).ExecuteStream(t.Context(), httpWSAuth(server.URL), req, opts)
	if errExecute == nil || !strings.Contains(errExecute.Error(), "previous_response_id") {
		t.Fatalf("configured continuation was ignored: %v", errExecute)
	}
	if attempts.Load() != 0 {
		t.Fatal("isolated bridge sent a configured continuation")
	}
}

func TestCodexHTTPWebsocketDisabledAndNonstreamKeepHTTP(t *testing.T) {
	for _, nonstream := range []bool{false, true} {
		t.Run(fmt.Sprint(nonstream), func(t *testing.T) {
			var posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if websocket.IsWebSocketUpgrade(r) {
					t.Error("unexpected upgrade")
					w.WriteHeader(500)
					return
				}
				posts.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"http_result\",\"status\":\"completed\",\"output\":[]}}\n\n")
			}))
			defer server.Close()
			req, opts := httpWSRequest()
			a := httpWSAuth(server.URL)
			exec := NewCodexAutoExecutor(&config.Config{})
			if nonstream {
				req.Payload = []byte(`{"model":"gpt-6-astra","stream":false,"input":[]}`)
				_, errExecute := exec.Execute(t.Context(), a, req, opts)
				if errExecute != nil {
					t.Fatal(errExecute)
				}
			} else {
				delete(a.Metadata, "http_sse_websockets")
				result, errExecute := exec.ExecuteStream(t.Context(), a, req, opts)
				if errExecute != nil {
					t.Fatal(errExecute)
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
				}
			}
			if posts.Load() != 1 {
				t.Fatalf("HTTP requests=%d", posts.Load())
			}
		})
	}
}
