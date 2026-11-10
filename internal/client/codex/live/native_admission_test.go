package live

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/base64"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func nativeLiveFixture(t *testing.T) (*Handler, *auth.Manager, *captureExecutor, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := auth.NewManager(nil, nil, nil)
	executor := &captureExecutor{responseBody: io.NopCloser(strings.NewReader("v=0\r\n"))}
	manager.RegisterExecutor(executor)
	token := "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"live-subject","https://api.openai.com/auth":{"chatgpt_account_id":"live-account"}}`)) + ".fixture"
	registerCredential(t, manager, &auth.Auth{ID: "native-live", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": token, "account_id": "live-account", "max_concurrent": 1}})
	handler := NewHandler(manager, nil)
	t.Cleanup(handler.Close)
	router := gin.New()
	router.POST("/v1/live", handler.Handle)
	router.POST("/v1/realtime/calls/:call_id/hangup", handler.HandleHangup)
	router.GET("/v1/realtime", handler.HandleDirectWebsocket)
	return handler, manager, executor, router
}

func nativeLiveRequest(ctx context.Context) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/live", strings.NewReader(`{"model":"gpt-live-1-codex","sdp":"v=0"}`)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func awaitLiveCounts(t *testing.T, manager *auth.Manager, active, queued int) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		got := manager.NativeConcurrency("native-live")
		if got.Active == active && got.Queued == queued {
			return
		}
		select {
		case <-timer.C:
			t.Fatalf("live activity active=%d queued=%d, want %d/%d", got.Active, got.Queued, active, queued)
		default:
			runtime.Gosched()
		}
	}
}

func TestNativeLiveAdmissionRetainsUntilHangupAndCancelsQueuedSessions(t *testing.T) {
	handler, manager, executor, router := nativeLiveFixture(t)
	bootstrapCtx, cancelBootstrap := context.WithCancel(t.Context())
	first := httptest.NewRecorder()
	router.ServeHTTP(first, nativeLiveRequest(bootstrapCtx))
	if first.Code != http.StatusCreated {
		t.Fatalf("bootstrap status=%d", first.Code)
	}
	cancelBootstrap() // Completing the bootstrap HTTP request is not ending the call.
	awaitLiveCounts(t, manager, 1, 0)
	for _, directWS := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan struct{})
		queued := httptest.NewRecorder()
		request := nativeLiveRequest(ctx)
		if directWS {
			request = httptest.NewRequest(http.MethodGet, "/v1/realtime?model=gpt-realtime", nil).WithContext(ctx)
			request.Header.Set("Connection", "Upgrade")
			request.Header.Set("Upgrade", "websocket")
		}
		go func() { router.ServeHTTP(queued, request); close(result) }()
		awaitLiveCounts(t, manager, 1, 1)
		if executor.httpCalls.Load() != 1 {
			t.Fatal("queued live request reached upstream")
		}
		cancel()
		select {
		case <-result:
		case <-time.After(5 * time.Second):
			t.Fatal("queued cancellation did not finish")
		}
		awaitLiveCounts(t, manager, 1, 0)
	}
	executor.statusCode = http.StatusOK
	executor.responseBody = io.NopCloser(strings.NewReader(`{"status":"ok"}`))
	hangupCtx, cancelHangup := context.WithTimeout(t.Context(), time.Second)
	defer cancelHangup()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/realtime/calls/call-123/hangup", nil).WithContext(hangupCtx))
	if response.Code != http.StatusOK {
		t.Fatalf("hangup tried to acquire a second slot: status=%d", response.Code)
	}
	awaitLiveCounts(t, manager, 0, 0)
	if _, ok := handler.sessions.peek("call-123"); ok {
		t.Fatal("hangup retained session")
	}
	handler.Close()
	awaitLiveCounts(t, manager, 0, 0)
}

func TestNativeLiveAdmissionReleasedByAllSessionEndPaths(t *testing.T) {
	for _, finish := range []string{"expire", "close", "replace", "sideband", "media"} {
		t.Run(finish, func(t *testing.T) {
			handler, manager, _, router := nativeLiveFixture(t)
			media := &fakeMediaSession{downstreamSDP: "v=0\r\n"}
			if finish == "media" {
				handler.mediaRelay = &fakeMediaRelay{upstreamOffer: "v=0\r\n", session: media}
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, nativeLiveRequest(t.Context()))
			if response.Code != http.StatusCreated {
				t.Fatalf("bootstrap status=%d", response.Code)
			}
			awaitLiveCounts(t, manager, 1, 0)
			session, ok := handler.sessions.peek("call-123")
			if !ok {
				t.Fatal("call not retained")
			}
			switch finish {
			case "expire":
				handler.sessions.expire(session.callID, session.token)
			case "close":
				handler.Close()
			case "replace":
				handler.sessions.put(session.callID, liveSession{authID: "other-auth"})
			case "sideband":
				handler.sessions.complete(session, "session_closed")
			case "media":
				if media.closeHandler == nil {
					t.Fatal("missing media close handler")
				}
				media.closeHandler("peer_closed")
			}
			awaitLiveCounts(t, manager, 0, 0)
			handler.Close()
			awaitLiveCounts(t, manager, 0, 0)
		})
	}
}

func TestNativeLiveAdmissionReleasesFailedOrCanceledBootstrap(t *testing.T) {
	for _, failure := range []string{"upstream", "read", "canceled", "write"} {
		t.Run(failure, func(t *testing.T) {
			handler, manager, executor, router := nativeLiveFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch failure {
			case "upstream":
				executor.statusCode = http.StatusBadGateway
			case "read":
				executor.responseBody = &errorResponseBody{payload: []byte("partial")}
			case "canceled":
				executor.beforeReturn = cancel
			}
			var writer http.ResponseWriter = httptest.NewRecorder()
			if failure == "write" {
				writer = &failingHTTPWriter{header: make(http.Header)}
			}
			router.ServeHTTP(writer, nativeLiveRequest(ctx))
			awaitLiveCounts(t, manager, 0, 0)
			if _, ok := handler.sessions.peek("call-123"); ok {
				t.Fatal("failed bootstrap retained session")
			}
		})
	}
}

type admissionRejectingExecutor struct {
	*captureExecutor
	manager        *auth.Manager
	observedActive int
}

func (e *admissionRejectingExecutor) PrepareRequest(_ *http.Request, _ *auth.Auth) error {
	e.observedActive = e.manager.NativeConcurrency("native-live").Active
	return errors.New("synthetic handshake preparation failure")
}

func TestNativeDirectWebsocketAdmissionReleasedOnHandshakeFailure(t *testing.T) {
	_, manager, executor, router := nativeLiveFixture(t)
	rejecting := &admissionRejectingExecutor{captureExecutor: executor, manager: manager}
	manager.RegisterExecutor(rejecting)
	request := httptest.NewRequest(http.MethodGet, "/v1/realtime?model=gpt-realtime", nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if rejecting.observedActive != 1 {
		t.Fatal("websocket preparation bypassed admission")
	}
	if response.Code != http.StatusBadGateway {
		t.Fatalf("unexpected handshake failure status=%d", response.Code)
	}
	awaitLiveCounts(t, manager, 0, 0)
	if executor.httpCalls.Load() != 0 {
		t.Fatal("failed mock handshake sent HTTP")
	}
}

func TestNativeDirectSessionShutdownAndCancellationReleaseResources(t *testing.T) {
	for _, cancelSession := range []bool{false, true} {
		t.Run(map[bool]string{false: "shutdown", true: "cancel"}[cancelSession], func(t *testing.T) {
			handler, manager, _, _ := nativeLiveFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			_, _, release, err := handler.acquireOAuth(ctx, defaultLiveModel, coreexecutor.Options{})
			if err != nil {
				t.Fatal(err)
			}
			var closed atomic.Bool
			stop, active := handler.retainDirectSession(ctx, func() error { closed.Store(true); return nil }, func() error { release(); return nil })
			if !active {
				t.Fatal("active handler rejected session")
			}
			awaitLiveCounts(t, manager, 1, 0)
			if cancelSession {
				cancel()
			} else {
				handler.Close()
			}
			awaitLiveCounts(t, manager, 0, 0)
			if !closed.Load() {
				t.Fatal("session released admission before socket resources closed")
			}
			stop()
			stop()
			awaitLiveCounts(t, manager, 0, 0)
		})
	}
}

func TestNativeLiveShutdownRejectsNewBootstrap(t *testing.T) {
	handler, manager, executor, router := nativeLiveFixture(t)
	handler.Close()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, nativeLiveRequest(t.Context()))
	if response.Code != http.StatusServiceUnavailable || executor.httpCalls.Load() != 0 {
		t.Fatal("shutdown accepted a new upstream call")
	}
	awaitLiveCounts(t, manager, 0, 0)
}
