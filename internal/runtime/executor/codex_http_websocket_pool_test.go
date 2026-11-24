package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type poolMockServer struct {
	url      string
	upgrades atomic.Int32
	posts    atomic.Int32
}

func newPoolMockServer(t *testing.T, reply func(*websocket.Conn, int, int, []byte) bool) *poolMockServer {
	t.Helper()
	mock := &poolMockServer{}
	var mu sync.Mutex
	var handlers sync.WaitGroup
	var connections []*websocket.Conn
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers.Add(1)
		defer handlers.Done()
		if !websocket.IsWebSocketUpgrade(r) {
			mock.posts.Add(1)
			w.WriteHeader(500)
			return
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		mu.Lock()
		connections = append(connections, conn)
		mu.Unlock()
		defer closeHTTPWSTestConn(t, conn)
		id := int(mock.upgrades.Add(1))
		for turn := 1; ; turn++ {
			_, body, errRead := conn.ReadMessage()
			if errRead != nil {
				return
			}
			if !reply(conn, id, turn, body) {
				return
			}
		}
	}))
	mock.url = server.URL
	t.Cleanup(func() {
		server.Close()
		mu.Lock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		handlers.Wait()
	})
	return mock
}
func poolCompleted(conn *websocket.Conn, id, turn int) bool {
	doc := ojson.NewDocString("{}")
	doc.Set("type", "response.completed")
	doc.Set("response.id", fmt.Sprintf("resp_%d_%d", id, turn))
	doc.Set("response.status", "completed")
	doc.Set("response.output", []any{})
	doc.Set("response.usage.input_tokens", 1)
	doc.Set("response.usage.output_tokens", 1)
	return conn.WriteMessage(websocket.TextMessage, doc.Bytes()) == nil
}
func poolTestExecutor(t *testing.T, cfg *config.Config) *CodexAutoExecutor {
	t.Helper()
	exec := NewCodexAutoExecutor(cfg)
	exec.wsExec.store = &codexWebsocketSessionStore{}
	t.Cleanup(func() { exec.CloseExecutionSession(auth.CloseAllExecutionSessionsID) })
	return exec
}
func collectPoolStream(ctx context.Context, exec *CodexAutoExecutor, a *auth.Auth, req core.Request, opts core.Options) (string, error) {
	stream, err := exec.ExecuteStream(ctx, a, req, opts)
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			return out.String(), chunk.Err
		}
		out.Write(chunk.Payload)
	}
	return out.String(), nil
}

// End invokes the actual bound close callback, as Home/executionregistry do.
type poolRequestLifecycle struct {
	cancelOnBind bool
	mu           sync.Mutex
	closeFn      func() error
	once         sync.Once
	ends         atomic.Int32
}

func (l *poolRequestLifecycle) Bind(fn func() error) error {
	l.mu.Lock()
	l.closeFn = fn
	l.mu.Unlock()
	if l.cancelOnBind {
		return fn()
	}
	return nil
}
func (l *poolRequestLifecycle) End(string) {
	l.once.Do(func() {
		l.ends.Add(1)
		l.mu.Lock()
		fn := l.closeFn
		l.mu.Unlock()
		if fn != nil {
			_ = fn()
		}
	})
}
func (l *poolRequestLifecycle) lateClose() {
	l.mu.Lock()
	fn := l.closeFn
	l.mu.Unlock()
	if fn != nil {
		_ = fn()
	}
}

func TestCodexHTTPWebsocketPoolSequentialReuseAndLifecycle(t *testing.T) {
	server := newPoolMockServer(t, func(conn *websocket.Conn, id, turn int, body []byte) bool {
		if ojson.GetBytes(body, "type").String() != "response.create" {
			t.Error("missing transport frame")
		}
		return poolCompleted(conn, id, turn)
	})
	exec := poolTestExecutor(t, &config.Config{})
	a := httpWSAuth(server.url)
	req, opts := httpWSRequest()
	var previous *poolRequestLifecycle
	for turn := 1; turn <= 10; turn++ {
		lifecycle := &poolRequestLifecycle{}
		opts.ExecutionLifecycle = lifecycle
		out, err := collectPoolStream(t.Context(), exec, a, req, opts)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains([]byte(out), []byte(fmt.Sprintf("resp_1_%d", turn))) {
			t.Fatalf("wrong response: %s", out)
		}
		if lifecycle.ends.Load() != 1 {
			t.Fatal("request lifecycle stayed retained between turns")
		}
		if previous != nil {
			previous.lateClose()
		}
		previous = lifecycle
	}
	if server.upgrades.Load() != 1 || server.posts.Load() != 0 {
		t.Fatalf("ten requests: upgrades=%d HTTP=%d", server.upgrades.Load(), server.posts.Load())
	}
}

func TestCodexHTTPWebsocketPoolAccountAndCredentialIsolation(t *testing.T) {
	server := newPoolMockServer(t, func(conn *websocket.Conn, id, turn int, _ []byte) bool { return poolCompleted(conn, id, turn) })
	exec := poolTestExecutor(t, &config.Config{})
	req, opts := httpWSRequest()
	a := httpWSAuth(server.url)
	for _, step := range []struct {
		id, token, session string
		want               int32
	}{
		{"a", "token-1", "", 1}, {"a", "token-1", "", 1}, {"b", "token-1", "", 2},
		{"a", "token-2", "", 3}, {"a", "token-2", "client-session", 4}, {"a", "token-2", "client-session", 4},
	} {
		a.ID = step.id
		a.Metadata["access_token"] = step.token
		opts.Headers = http.Header{}
		if step.session != "" {
			opts.Headers.Set("Session-Id", step.session)
		}
		if _, err := collectPoolStream(t.Context(), exec, a, req, opts); err != nil {
			t.Fatal(err)
		}
		if server.upgrades.Load() != step.want {
			t.Fatalf("step=%+v upgrades=%d", step, server.upgrades.Load())
		}
	}
	exec.CloseAuthExecutionSessions("a")
	if _, err := collectPoolStream(t.Context(), exec, a, req, opts); err != nil {
		t.Fatal(err)
	}
	if server.upgrades.Load() != 5 {
		t.Fatal("removed account connection reused")
	}
}

func TestCodexHTTPWebsocketPoolConcurrentExclusiveLeases(t *testing.T) {
	started := make(chan int, 2)
	release := make(chan struct{})
	server := newPoolMockServer(t, func(conn *websocket.Conn, id, turn int, _ []byte) bool {
		if turn == 1 {
			started <- id
			<-release
		}
		return poolCompleted(conn, id, turn)
	})
	exec := poolTestExecutor(t, &config.Config{Codex: config.CodexConfig{HTTPWebsocketPoolMaxPerAccount: 2}})
	a := httpWSAuth(server.url)
	req, opts := httpWSRequest()
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func(a *auth.Auth) { _, err := collectPoolStream(t.Context(), exec, a, req, opts); results <- err }(a.Clone())
	}
	first, second := <-started, <-started
	if first == second {
		t.Error("two active requests shared a connection")
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := collectPoolStream(t.Context(), exec, a, req, opts); err != nil {
		t.Fatal(err)
	}
	if server.upgrades.Load() != 2 {
		t.Fatalf("idle connection not reused: %d", server.upgrades.Load())
	}
}

func TestCodexHTTPWebsocketPoolNoReplayAfterSentDisconnect(t *testing.T) {
	server := newPoolMockServer(t, func(_ *websocket.Conn, _, _ int, _ []byte) bool { return false })
	exec := poolTestExecutor(t, &config.Config{})
	req, opts := httpWSRequest()
	_, err := collectPoolStream(t.Context(), exec, httpWSAuth(server.url), req, opts)
	if err == nil {
		t.Fatal("disconnect became success")
	}
	var stopper interface{ IsRequestStop() bool }
	if !errors.As(err, &stopper) || !stopper.IsRequestStop() {
		t.Fatalf("missing no-replay marker: %v", err)
	}
	if server.upgrades.Load() != 1 || server.posts.Load() != 0 {
		t.Fatal("sent generation replayed")
	}
}

func TestCodexHTTPWebsocketPoolToolsAndFinalPayloadRules(t *testing.T) {
	var bodiesMu sync.Mutex
	var bodies [][]byte
	server := newPoolMockServer(t, func(conn *websocket.Conn, id, turn int, body []byte) bool {
		bodiesMu.Lock()
		bodies = append(bodies, append([]byte(nil), body...))
		bodiesMu.Unlock()
		doc := ojson.NewDocString("{}")
		doc.Set("type", "response.function_call_arguments.delta")
		doc.Set("item_id", fmt.Sprintf("tool_%d", turn))
		doc.Set("delta", "arguments")
		if err := conn.WriteMessage(websocket.TextMessage, doc.Bytes()); err != nil {
			return false
		}
		doc = ojson.NewDocString("{}")
		doc.Set("type", "response.custom_tool_call_input.delta")
		doc.Set("item_id", fmt.Sprintf("custom_%d", turn))
		doc.Set("delta", "patch")
		if err := conn.WriteMessage(websocket.TextMessage, doc.Bytes()); err != nil {
			return false
		}
		return poolCompleted(conn, id, turn)
	})
	cfg := &config.Config{Payload: config.PayloadConfig{
		Override: []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"instructions": "configured", "parallel_tool_calls": false}}},
		Filter:   []config.PayloadFilterRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: []string{"store"}}},
	}}
	exec := poolTestExecutor(t, cfg)
	a := httpWSAuth(server.url)
	req, opts := httpWSRequest()
	before := helps.PayloadConfigEvaluationCount()
	for turn := 1; turn <= 2; turn++ {
		doc := ojson.NewDoc(req.Payload)
		doc.Set("instructions", "original")
		doc.Set("store", false)
		doc.Set("tools", []any{map[string]any{"type": "function", "name": "lookup", "parameters": map[string]any{"type": "object"}}, map[string]any{"type": "custom", "name": "apply_patch"}})
		doc.Set("input", []any{map[string]any{"type": "function_call_output", "call_id": fmt.Sprintf("call_%d", turn), "output": "found"}, map[string]any{"type": "custom_tool_call_output", "call_id": fmt.Sprintf("custom_%d", turn), "output": "patched"}})
		req.Payload = doc.Bytes()
		out, err := collectPoolStream(t.Context(), exec, a, req, opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range []string{"response.function_call_arguments.delta", "response.custom_tool_call_input.delta", "response.completed"} {
			if !bytes.Contains([]byte(out), []byte(event)) {
				t.Fatalf("lost %s on turn %d", event, turn)
			}
		}
	}
	if helps.PayloadConfigEvaluationCount()-before != 2 {
		t.Fatal("payload rules were not evaluated exactly once per turn")
	}
	if server.upgrades.Load() != 1 {
		t.Fatal("tool follow-up did not reuse the connection")
	}
	bodiesMu.Lock()
	defer bodiesMu.Unlock()
	for i, body := range bodies {
		if ojson.GetBytes(body, "instructions").String() != "configured" || ojson.GetBytes(body, "store").Exists() || ojson.GetBytes(body, "parallel_tool_calls").Bool() {
			t.Fatalf("payload barrier violated: %s", body)
		}
		if ojson.GetBytes(body, "input.0.call_id").String() != fmt.Sprintf("call_%d", i+1) {
			t.Fatalf("tool output changed: %s", body)
		}
		if ojson.GetBytes(body, "previous_response_id").Exists() {
			t.Fatal("pool injected continuation state")
		}
	}
}

func TestCodexHTTPWebsocketPoolCancelDiscardsActiveSocket(t *testing.T) {
	started := make(chan struct{})
	closed := make(chan struct{})
	server := newPoolMockServer(t, func(conn *websocket.Conn, id, turn int, _ []byte) bool {
		if id == 1 {
			close(started)
			_, _, _ = conn.ReadMessage()
			close(closed)
			return false
		}
		return poolCompleted(conn, id, turn)
	})
	exec := poolTestExecutor(t, &config.Config{})
	a := httpWSAuth(server.url)
	req, opts := httpWSRequest()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stream, err := exec.ExecuteStream(ctx, a, req, opts)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	cancel()
	for range stream.Chunks {
	}
	<-closed
	if _, err := collectPoolStream(t.Context(), exec, a, req, opts); err != nil {
		t.Fatal(err)
	}
	if server.upgrades.Load() != 2 || server.posts.Load() != 0 {
		t.Fatal("cancelled stream socket was reused or generation replayed")
	}
}

func TestCodexHTTPWebsocketPoolIdleRetirement(t *testing.T) {
	for _, mode := range []string{"unsolicited", "peer_close"} {
		t.Run(mode, func(t *testing.T) {
			trigger := make(chan struct{})
			retired := make(chan struct{})
			server := newPoolMockServer(t, func(conn *websocket.Conn, id, turn int, _ []byte) bool {
				if !poolCompleted(conn, id, turn) {
					return false
				}
				if id != 1 {
					return true
				}
				<-trigger
				if mode == "unsolicited" {
					doc := ojson.NewDocString("{}")
					doc.Set("type", "response.completed")
					doc.Set("response.id", "resp_1_1")
					if err := conn.WriteMessage(websocket.TextMessage, doc.Bytes()); err != nil {
						t.Error(err)
					}
				} else {
					if err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "idle close")); err != nil {
						t.Error(err)
					}
				}
				// Synchronize with the resident reader retiring the idle connection.
				if _, _, err := conn.ReadMessage(); err == nil {
					t.Error("dirty socket carried another request")
				}
				close(retired)
				return false
			})
			exec := poolTestExecutor(t, &config.Config{})
			a := httpWSAuth(server.url)
			req, opts := httpWSRequest()
			if _, err := collectPoolStream(t.Context(), exec, a, req, opts); err != nil {
				t.Fatal(err)
			}
			close(trigger)
			<-retired
			if _, err := collectPoolStream(t.Context(), exec, a, req, opts); err != nil {
				t.Fatal(err)
			}
			if server.upgrades.Load() != 2 || server.posts.Load() != 0 {
				t.Fatal("idle socket was not replaced through WS")
			}
		})
	}
}

func TestCodexHTTPWebsocketPoolAccountRemovedDuringDial(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	noPayload := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			noPayload <- false
			return
		}
		defer closeHTTPWSTestConn(t, conn)
		_, _, err = conn.ReadMessage()
		noPayload <- err != nil
	}))
	defer server.Close()
	exec := poolTestExecutor(t, &config.Config{})
	a := httpWSAuth(server.URL)
	req, opts := httpWSRequest()
	result := make(chan error, 1)
	go func() { _, err := collectPoolStream(t.Context(), exec, a, req, opts); result <- err }()
	<-started
	exec.CloseAuthExecutionSessions(a.ID)
	close(release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("removed dial survived: %v", err)
	}
	if !<-noPayload {
		t.Fatal("retired dial sent business payload")
	}
}

func TestCodexHTTPWebsocketPoolCancellationDuringLifecycleBind(t *testing.T) {
	var requests atomic.Int32
	server := newPoolMockServer(t, func(conn *websocket.Conn, id, turn int, _ []byte) bool {
		requests.Add(1)
		return poolCompleted(conn, id, turn)
	})
	exec := poolTestExecutor(t, &config.Config{})
	req, opts := httpWSRequest()
	opts.ExecutionLifecycle = &poolRequestLifecycle{cancelOnBind: true}
	if _, err := collectPoolStream(t.Context(), exec, httpWSAuth(server.url), req, opts); err == nil {
		t.Fatal("cancellation during lifecycle bind did not stop the request")
	}
	if requests.Load() != 0 || server.posts.Load() != 0 {
		t.Fatal("cancelled lifecycle sent or replayed a request")
	}
}

func TestCodexHTTPWebsocketPoolSessionInstructionsFullContext(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(fmt.Sprint(configured), func(t *testing.T) {
			captured := make(chan []byte, 2)
			server := newPoolMockServer(t, func(conn *websocket.Conn, id, turn int, body []byte) bool {
				captured <- bytes.Clone(body)
				return poolCompleted(conn, id, turn)
			})
			cfg := &config.Config{}
			if configured {
				cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: map[string]any{"input.0.content.0.text": "configured-prefix", "instructions": "configured-instructions"}}}
			}
			exec := poolTestExecutor(t, cfg)
			a := httpWSAuth(server.url)
			req, opts := httpWSRequest()
			opts.Headers = http.Header{"Session-Id": {t.Name()}}
			opts.Metadata = map[string]any{core.CallerScopeMetadataKey: "pool-caller"}
			for _, mode := range []string{"start", "reuse"} {
				doc := ojson.NewDocString("{}")
				_ = doc.Set("stream", true)
				_ = doc.Set("input", "hi")
				_ = doc.Set("client_metadata.cpa_session_instructions", mode)
				if mode == "start" {
					_ = doc.Set("instructions", "baseline")
				}
				req.Payload = doc.Bytes()
				if _, err := collectPoolStream(t.Context(), exec, a, req, opts); err != nil {
					t.Fatal(err)
				}
				body := <-captured
				wantPrefix, wantInstructions := "baseline", ""
				if configured {
					wantPrefix, wantInstructions = "configured-prefix", "configured-instructions"
				}
				if ojson.GetBytes(body, "input.0.content.0.text").String() != wantPrefix || ojson.GetBytes(body, "instructions").String() != wantInstructions {
					t.Fatalf("full-context instructions or final payload rules lost: %s", body)
				}
				if ojson.GetBytes(body, "client_metadata.cpa_session_instructions").Exists() || ojson.GetBytes(body, "previous_response_id").Exists() {
					t.Fatalf("connection-bound state leaked into an HTTP bridge turn: %s", body)
				}
			}
			if server.upgrades.Load() != 1 {
				t.Fatalf("session instruction turns failed to reuse connection: %d", server.upgrades.Load())
			}
		})
	}
}
