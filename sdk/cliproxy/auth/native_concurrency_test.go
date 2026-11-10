package auth

import (
	"context"
	"errors"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func nativeConcurrencyTestAuth(id, subject, account string, limit int) *Auth {
	doc := ojson.NewDocString(`{"https://api.openai.com/auth":{}}`)
	_ = doc.Set("sub", subject)
	_ = doc.Set("https://api\\.openai\\.com/auth.chatgpt_account_id", account)
	token := "e30." + base64.RawURLEncoding.EncodeToString(doc.Bytes()) + ".fixture"
	return &Auth{ID: id, Provider: "codex", Metadata: map[string]any{"access_token": token, "account_id": account, "max_concurrent": limit}, Status: StatusActive}
}

func awaitNativeCounts(t *testing.T, manager *Manager, id string, active, queued int) {
	t.Helper()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		snapshot := manager.NativeConcurrency(id)
		if snapshot.Active == active && snapshot.Queued == queued {
			return
		}
		select {
		case <-timeout.C:
			t.Fatalf("activity = %+v, want active=%d queued=%d", snapshot, active, queued)
		default:
			runtime.Gosched()
		}
	}
}

type nativeConcurrencyExecutor struct {
	started chan string
	finish  <-chan struct{}
}

func (*nativeConcurrencyExecutor) Identifier() string { return "codex" }
func (*nativeConcurrencyExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}
func (*nativeConcurrencyExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}
func (e *nativeConcurrencyExecutor) Execute(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.started <- auth.ID
	select {
	case <-e.finish:
		return cliproxyexecutor.Response{Payload: []byte(`{"output":[]}`)}, nil
	case <-ctx.Done():
		return cliproxyexecutor.Response{}, ctx.Err()
	}
}
func (e *nativeConcurrencyExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, auth, req, opts)
}
func (e *nativeConcurrencyExecutor) ExecuteStream(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.started <- auth.ID
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: initial\n\n")}
	go func() {
		defer close(chunks)
		select {
		case <-e.finish:
		case <-ctx.Done():
		}
	}()
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func nativeConcurrencyFixture(t *testing.T, auths ...*Auth) (*Manager, *nativeConcurrencyExecutor, chan struct{}) {
	t.Helper()
	finish := make(chan struct{})
	exec := &nativeConcurrencyExecutor{started: make(chan string, 64), finish: finish}
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.RegisterExecutor(exec)
	for _, auth := range auths {
		if _, err := manager.Register(t.Context(), auth); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: "native-limit-model"}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	}
	return manager, exec, finish
}

func TestNativeConcurrencyExecuteRotatesThenQueuesAndCancels(t *testing.T) {
	manager, executor, finish := nativeConcurrencyFixture(t, nativeConcurrencyTestAuth("a", "subject-a", "account", 1), nativeConcurrencyTestAuth("b", "subject-b", "account", 1))
	var requests sync.WaitGroup
	for range 2 {
		requests.Go(func() {
			if _, err := manager.Execute(t.Context(), []string{"codex"}, cliproxyexecutor.Request{Model: "native-limit-model"}, cliproxyexecutor.Options{}); err != nil {
				t.Error(err)
			}
		})
	}
	first, second := <-executor.started, <-executor.started
	if first == second {
		t.Fatal("saturated account was selected twice")
	}
	ctx, cancel := context.WithCancel(t.Context())
	queuedResult := make(chan error, 1)
	go func() {
		_, err := manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: "native-limit-model"}, cliproxyexecutor.Options{})
		queuedResult <- err
	}()
	awaitNativeCounts(t, manager, "a", 1, 1)
	cancel()
	if err := <-queuedResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("queued cancellation: %v", err)
	}
	awaitNativeCounts(t, manager, "a", 1, 0)
	current, _ := manager.GetByID("a")
	if current.Unavailable || current.Quota.Exceeded || current.Failed != 0 {
		t.Fatal("capacity wait cooled or failed the credential")
	}
	close(finish)
	requests.Wait()
	awaitNativeCounts(t, manager, "a", 0, 0)
	awaitNativeCounts(t, manager, "b", 0, 0)
}

func TestNativeConcurrencyStreamLeaseCoversHTTPAndWebsocket(t *testing.T) {
	for _, websocket := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "websocket"}[websocket], func(t *testing.T) {
			manager, executor, finish := nativeConcurrencyFixture(t, nativeConcurrencyTestAuth("stream", "subject", "account", 1))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if websocket {
				ctx = cliproxyexecutor.WithDownstreamWebsocket(ctx)
			}
			result, err := manager.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: "native-limit-model"}, cliproxyexecutor.Options{Stream: true})
			if err != nil {
				t.Fatal(err)
			}
			<-executor.started
			<-result.Chunks
			awaitNativeCounts(t, manager, "stream", 1, 0)
			queuedCtx, cancelQueued := context.WithCancel(t.Context())
			defer cancelQueued()
			done := make(chan error, 1)
			go func() {
				_, err := manager.ExecuteCount(queuedCtx, []string{"codex"}, cliproxyexecutor.Request{Model: "native-limit-model"}, cliproxyexecutor.Options{})
				done <- err
			}()
			awaitNativeCounts(t, manager, "stream", 1, 1)
			cancel()
			<-executor.started
			awaitNativeCounts(t, manager, "stream", 1, 0)
			close(finish)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			for range result.Chunks {
			}
			awaitNativeCounts(t, manager, "stream", 0, 0)
		})
	}
}

func TestNativeConcurrencyIdentityIsolationAndUnlimited(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	a := nativeConcurrencyTestAuth("one", "sub", "acct", 1)
	duplicate := nativeConcurrencyTestAuth("duplicate", "sub", "acct", 0)
	other := nativeConcurrencyTestAuth("other", "other-sub", "acct", 0)
	for _, auth := range []*Auth{a, duplicate, other} {
		if _, err := manager.Register(t.Context(), auth); err != nil {
			t.Fatal(err)
		}
	}
	a, _ = manager.GetByID(a.ID)
	duplicate, _ = manager.GetByID(duplicate.ID)
	other, _ = manager.GetByID(other.ID)
	lease, blocked, err := manager.tryNativeConcurrency(a)
	if err != nil || blocked != "" || lease == nil {
		t.Fatalf("admission: %v", err)
	}
	defer lease.release()
	if next, blocked, err := manager.tryNativeConcurrency(duplicate); next != nil || blocked == "" || err != nil {
		t.Fatal("duplicate credential bypassed account limit")
	}
	for range 8 {
		lease, blocked, err := manager.tryNativeConcurrency(other)
		if err != nil || blocked != "" || lease == nil {
			t.Fatal("unlimited account blocked")
		}
		defer lease.release()
	}
	awaitNativeCounts(t, manager, other.ID, 8, 0)
	for _, provider := range []string{"bps", "openai", "codex"} {
		unsupported := a.Clone()
		unsupported.Provider = provider
		unsupported.Attributes = map[string]string{"api_key": "synthetic-key"}
		if lease, blocked, err := manager.tryNativeConcurrency(unsupported); lease != nil || blocked != "" || err != nil {
			t.Fatal("API key/provider entered native limiter")
		}
	}
	bps := a.Clone()
	bps.Provider = "bps"
	if lease, blocked, err := manager.tryNativeConcurrency(bps); lease != nil || blocked != "" || err != nil {
		t.Fatal("BPS OAuth entered native limiter")
	}
}

func TestNativeConcurrencyAdmissionIsAtomicAcrossCredentialCopies(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth, err := manager.Register(t.Context(), nativeConcurrencyTestAuth("atomic", "sub", "acct", 3))
	if err != nil {
		t.Fatal(err)
	}
	leases := make(chan *nativeConcurrencyLease, 40)
	var attempts sync.WaitGroup
	for range 40 {
		attempts.Go(func() {
			lease, _, err := manager.tryNativeConcurrency(auth.Clone())
			if err != nil {
				t.Error(err)
			}
			if lease != nil {
				leases <- lease
			}
		})
	}
	attempts.Wait()
	close(leases)
	if len(leases) != 3 {
		t.Fatalf("atomic admission accepted %d, want 3", len(leases))
	}
	for lease := range leases {
		lease.release()
		lease.release()
	}
	awaitNativeCounts(t, manager, auth.ID, 0, 0)
}

func TestNativeConcurrencyStreamReleasesOnNormalCompletion(t *testing.T) {
	manager, _, finish := nativeConcurrencyFixture(t, nativeConcurrencyTestAuth("complete", "sub", "acct", 1))
	stream, err := manager.ExecuteStream(t.Context(), []string{"codex"}, cliproxyexecutor.Request{Model: "native-limit-model"}, cliproxyexecutor.Options{Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	<-stream.Chunks
	awaitNativeCounts(t, manager, "complete", 1, 0)
	close(finish)
	for range stream.Chunks {
	}
	awaitNativeCounts(t, manager, "complete", 0, 0)
}

func TestNativeConcurrencyLimitUpdateWakesQueuedRequest(t *testing.T) {
	manager, executor, finish := nativeConcurrencyFixture(t, nativeConcurrencyTestAuth("updated", "sub", "acct", 1))
	var requests sync.WaitGroup
	requests.Go(func() {
		_, _ = manager.Execute(t.Context(), []string{"codex"}, cliproxyexecutor.Request{Model: "native-limit-model"}, cliproxyexecutor.Options{})
	})
	<-executor.started
	requests.Go(func() {
		_, _ = manager.Execute(t.Context(), []string{"codex"}, cliproxyexecutor.Request{Model: "native-limit-model"}, cliproxyexecutor.Options{})
	})
	awaitNativeCounts(t, manager, "updated", 1, 1)
	_, _, err := manager.Modify(t.Context(), "updated", 0, func(current *Auth) error { current.Metadata["max_concurrent"] = 0; return nil })
	if err != nil {
		t.Fatal(err)
	}
	<-executor.started
	awaitNativeCounts(t, manager, "updated", 2, 0)
	close(finish)
	requests.Wait()
}

func TestNativeConcurrencyAcquireByKindRetainsLeaseWithoutHTTPReentry(t *testing.T) {
	manager, _, _ := nativeConcurrencyFixture(t, nativeConcurrencyTestAuth("retained", "subject", "account", 1))
	selected, release, err := manager.AcquireAuthByKind(t.Context(), "codex", "", AuthKindOAuth, cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.PinnedAuthMetadataKey: "retained"}})
	if err != nil || selected == nil {
		t.Fatalf("acquire OAuth: %v", err)
	}
	defer release()
	awaitNativeCounts(t, manager, "retained", 1, 0)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, releaseNext, err := manager.AcquireAuthByKind(ctx, "codex", "", AuthKindOAuth, cliproxyexecutor.Options{})
		releaseNext()
		done <- err
	}()
	awaitNativeCounts(t, manager, "retained", 1, 1)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("retained acquisition cancellation: %v", err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://fixture.invalid/tool", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.HttpRequest(t.Context(), selected, request); err != nil {
		t.Fatal(err)
	}
	awaitNativeCounts(t, manager, "retained", 1, 0)
	release()
	release()
	awaitNativeCounts(t, manager, "retained", 0, 0)
}
