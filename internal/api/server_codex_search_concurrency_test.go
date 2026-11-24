package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func registerNativeSearchConcurrencyAuth(t *testing.T, server *Server, id, subject string) {
	t.Helper()
	doc := ojson.NewDocString(`{"https://api.openai.com/auth":{"chatgpt_account_id":"search-account"}}`)
	_ = doc.Set("sub", subject)
	token := "e30." + base64.RawURLEncoding.EncodeToString(doc.Bytes()) + ".fixture"
	_, err := server.handlers.AuthManager.Register(t.Context(), &auth.Auth{ID: id, Provider: "codex", Status: auth.StatusActive,
		Metadata: map[string]any{"access_token": token, "account_id": "search-account", "max_concurrent": 1}})
	if err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: "native-search-model"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
}

func awaitNativeSearchCounts(t *testing.T, manager *auth.Manager, id string, active, queued int) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		got := manager.NativeConcurrency(id)
		if got.Active == active && got.Queued == queued {
			return
		}
		select {
		case <-timer.C:
			t.Fatalf("search counts = %+v, want %d active/%d queued", got, active, queued)
		default:
			runtime.Gosched()
		}
	}
}

type nativeSearchBlockingBody struct {
	ctx    context.Context
	finish <-chan struct{}
	closed chan struct{}
	once   sync.Once
}

func (body *nativeSearchBlockingBody) Read([]byte) (int, error) {
	select {
	case <-body.ctx.Done():
		return 0, body.ctx.Err()
	case <-body.finish:
		return 0, io.EOF
	}
}
func (body *nativeSearchBlockingBody) Close() error {
	body.once.Do(func() { close(body.closed) })
	return nil
}

type nativeSearchConcurrencyExecutor struct {
	codexSearchCaptureExecutor
	started chan string
	finish  chan struct{}
	bodies  chan *nativeSearchBlockingBody
}

func (executor *nativeSearchConcurrencyExecutor) Execute(ctx context.Context, selected *auth.Auth, _ coreexecutor.Request, _ coreexecutor.Options) (coreexecutor.Response, error) {
	executor.started <- selected.ID
	select {
	case <-ctx.Done():
		return coreexecutor.Response{}, ctx.Err()
	case <-executor.finish:
		return coreexecutor.Response{Payload: []byte(`{"output":[]}`)}, nil
	}
}
func (executor *nativeSearchConcurrencyExecutor) HttpRequest(ctx context.Context, selected *auth.Auth, _ *http.Request) (*http.Response, error) {
	executor.started <- selected.ID
	body := &nativeSearchBlockingBody{ctx: ctx, finish: executor.finish, closed: make(chan struct{})}
	executor.bodies <- body
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: body}, nil
}

func serveNativeSearch(server *Server, ctx context.Context) <-chan *httptest.ResponseRecorder {
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		request := httptest.NewRequest(http.MethodPost, "/v1/alpha/search", strings.NewReader(`{"model":"native-search-model","query":"test"}`)).WithContext(ctx)
		request.Header.Set("Authorization", "Bearer test-key")
		recorder := httptest.NewRecorder()
		server.engine.ServeHTTP(recorder, request)
		done <- recorder
	}()
	return done
}

func TestCodexAlphaSearchNativeConcurrencySharesGenerationSlots(t *testing.T) {
	server := newTestServer(t)
	manager := server.handlers.AuthManager
	manager.SetSelector(&auth.FillFirstSelector{})
	executor := &nativeSearchConcurrencyExecutor{started: make(chan string, 8), finish: make(chan struct{}), bodies: make(chan *nativeSearchBlockingBody, 8)}
	manager.RegisterExecutor(executor)
	registerNativeSearchConcurrencyAuth(t, server, "search-a", "subject-a")
	registerNativeSearchConcurrencyAuth(t, server, "search-b", "subject-b")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	generationDone := make(chan error, 1)
	go func() {
		_, err := manager.Execute(ctx, []string{"codex"}, coreexecutor.Request{Model: "native-search-model"}, coreexecutor.Options{})
		generationDone <- err
	}()
	if got := <-executor.started; got != "search-a" {
		t.Fatalf("generation selected %s", got)
	}
	searchCtx, cancelSearch := context.WithCancel(ctx)
	searchDone := serveNativeSearch(server, searchCtx)
	if got := <-executor.started; got != "search-b" {
		t.Fatalf("search did not rotate saturated generation credential: %s", got)
	}
	body := <-executor.bodies
	awaitNativeSearchCounts(t, manager, "search-a", 1, 0)
	awaitNativeSearchCounts(t, manager, "search-b", 1, 0)
	queuedCtx, cancelQueued := context.WithCancel(ctx)
	queuedDone := serveNativeSearch(server, queuedCtx)
	awaitNativeSearchCounts(t, manager, "search-a", 1, 1)
	cancelQueued()
	<-queuedDone
	awaitNativeSearchCounts(t, manager, "search-a", 1, 0)
	select {
	case <-executor.started:
		t.Fatal("queued search reached upstream before capacity became available")
	default:
	}
	cancelSearch()
	<-searchDone
	<-body.closed
	awaitNativeSearchCounts(t, manager, "search-b", 0, 0)
	close(executor.finish)
	if err := <-generationDone; err != nil {
		t.Fatal(err)
	}
	awaitNativeSearchCounts(t, manager, "search-a", 0, 0)
	for _, id := range []string{"search-a", "search-b"} {
		current, _ := manager.GetByID(id)
		if current.Unavailable || current.Quota.Exceeded {
			t.Fatal("search capacity changed credential availability")
		}
	}
}

func TestCodexAlphaSearchNativeConcurrencyReleasesAcrossHTTPPaths(t *testing.T) {
	for _, path := range []string{"complete", "prepare_error", "request_error", "read_error"} {
		t.Run(path, func(t *testing.T) {
			server := newTestServer(t)
			executor := &codexSearchCaptureExecutor{}
			server.handlers.AuthManager.RegisterExecutor(executor)
			registerNativeSearchConcurrencyAuth(t, server, "search-path", "subject")
			switch path {
			case "prepare_error":
				executor.prepareErr = errors.New("test preparation failure")
			case "request_error":
				executor.httpErr = errors.New("test upstream failure")
			case "read_error":
				executor.responseBody = &errorSearchResponseBody{}
			default:
				executor.beforeReturn = func() {
					if got := server.handlers.AuthManager.NativeConcurrency("search-path"); got.Active != 1 {
						t.Error("direct HTTP request did not own exactly one lease")
					}
				}
			}
			recorder := <-serveNativeSearch(server, t.Context())
			if path == "complete" && recorder.Code != http.StatusOK {
				t.Fatalf("search status: %d", recorder.Code)
			}
			awaitNativeSearchCounts(t, server.handlers.AuthManager, "search-path", 0, 0)
		})
	}
}
