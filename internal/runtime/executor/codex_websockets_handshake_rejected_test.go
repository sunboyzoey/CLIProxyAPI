package executor

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestCodexWebsocketUnexplainedHandshakeClassification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		length  int64
		body    string
		headers http.Header
		want    bool
	}{
		{name: "confirmed empty forbidden", status: 403, want: true},
		{name: "unknown body length", status: 403, length: -1},
		{name: "unread body", status: 403, length: 42},
		{name: "explicit permission refusal", status: 403, body: "permission denied"},
		{name: "explicit quota", status: 403, body: fmt.Sprintf("{%q:{%q:%q}}", "error", "code", "insufficient_quota")},
		{name: "challenge body", status: 403, body: "<html>challenge</html>"},
		{name: "challenge header", status: 403, headers: http.Header{"Cf-Mitigated": {"challenge"}}},
		{name: "quota header", status: 403, headers: http.Header{"X-Codex-Limit-Reached": {"true"}}},
		{name: "disallowed header", status: 403, headers: http.Header{"X-Codex-Allowed": {"false"}}},
		{name: "unauthorized", status: 401},
		{name: "payment", status: 402},
		{name: "rate limit", status: 429},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := newCodexWebsocketHandshakeStatusErr(&http.Response{StatusCode: tc.status, ContentLength: tc.length, Header: tc.headers}, []byte(tc.body), false)
			got := err.ErrorCode() == auth.ErrorCodeWebsocketHandshakeRejected
			if got != tc.want {
				t.Fatalf("classified=%v, want %v: %v", got, tc.want, err)
			}
			if tc.want {
				if err.StatusCode() != 403 || err.IsCredentialScoped() {
					t.Fatalf("lost status or widened scope: %+v", err)
				}
				classified := auth.ResultErrorFromError(err)
				if classified.Code != auth.ErrorCodeWebsocketHandshakeRejected || classified.HTTPStatus != 403 {
					t.Fatalf("classification lost: %+v", classified)
				}
				if ojson.Get(err.Error(), "error.code").String() != auth.ErrorCodeWebsocketHandshakeRejected {
					t.Fatalf("incorrect public error: %v", err)
				}
			}
		})
	}
	// Normal HTTP/business errors are outside the handshake-only classifier.
	if err := newCodexStatusErrWithHeadersAndCooling(403, nil, nil, false); err.ErrorCode() == auth.ErrorCodeWebsocketHandshakeRejected {
		t.Fatal("ordinary 403 was reclassified")
	}
}

func TestCodexWebsocketEmptyForbiddenHandshakeExecution(t *testing.T) {
	for _, mode := range []string{"http-sse-bridge", "native-stream", "native-buffered"} {
		t.Run(mode, func(t *testing.T) {
			var upgrades, posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if websocket.IsWebSocketUpgrade(r) {
					upgrades.Add(1)
				} else {
					posts.Add(1)
				}
				w.Header().Set("Content-Length", "0")
				w.Header().Set("Retry-After", "17")
				w.WriteHeader(http.StatusForbidden)
			}))
			defer server.Close()
			req, opts := httpWSRequest()
			a := httpWSAuth(server.URL)
			var err error
			switch mode {
			case "http-sse-bridge":
				_, err = NewCodexAutoExecutor(&config.Config{}).ExecuteStream(t.Context(), a, req, opts)
			case "native-stream":
				_, err = NewCodexWebsocketsExecutor(&config.Config{}).ExecuteStream(t.Context(), a, req, opts)
			case "native-buffered":
				_, err = NewCodexWebsocketsExecutor(&config.Config{}).Execute(t.Context(), a, req, opts)
			}
			var classified interface {
				StatusCode() int
				ErrorCode() string
				RetryAfter() *time.Duration
			}
			if !errors.As(err, &classified) {
				t.Fatalf("missing typed refusal: %v", err)
			}
			if classified.StatusCode() != 403 || classified.ErrorCode() != auth.ErrorCodeWebsocketHandshakeRejected {
				t.Fatalf("incorrect classification: %v", err)
			}
			if d := classified.RetryAfter(); d == nil || *d != 17*time.Second {
				t.Fatalf("Retry-After lost: %v", d)
			}
			if upgrades.Load() != 1 || posts.Load() != 0 {
				t.Fatalf("unexpected retry/fallback: upgrades=%d posts=%d", upgrades.Load(), posts.Load())
			}
		})
	}
}
