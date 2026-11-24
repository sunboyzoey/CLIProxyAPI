package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	tr "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexOAuthGroupRoutingAndTier(t *testing.T) {
	const model = "gpt-6.2-sol"
	for _, transport := range []string{"http", "ws"} {
		t.Run(transport, func(t *testing.T) {
			mgr := auth.NewManager(nil, &auth.RoundRobinSelector{}, nil)
			cfg := &config.Config{}
			mgr.SetConfig(cfg)
			if transport == "http" {
				mgr.RegisterExecutor(NewCodexExecutor(cfg))
			} else {
				mgr.RegisterExecutor(NewCodexWebsocketsExecutor(cfg))
			}
			var reads []func() string
			var ids []string
			for _, g := range []string{"alpha", "beta"} {
				var capture capturedCodexRequest
				var rec codexWebsocketHintRecorder
				var url string
				if transport == "http" {
					server := newCodexRoutingHintServer(t, &capture)
					t.Cleanup(server.Close)
					url = server.URL
					reads = append(reads, func() string { return capture.serviceTier.String() })
				} else {
					server := newCodexWebsocketHintServer(t, &rec)
					t.Cleanup(server.Close)
					url = server.URL
					reads = append(reads, func() string {
						rec.mu.Lock()
						defer rec.mu.Unlock()
						if len(rec.frames) == 0 {
							return ""
						}
						return rec.frames[len(rec.frames)-1].tier
					})
				}
				a := codexOAuthTestAuth(url)
				a.ID = t.Name() + "/" + g
				a.Prefix = g
				a.Metadata["oauth_group"] = g
				ids = append(ids, a.ID)
				if g == "alpha" {
					a.Metadata["service_tier"] = "fast"
				}
				reg := registry.GetGlobalRegistry()
				reg.RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: model}, {ID: g + "/" + model}})
				t.Cleanup(func() { reg.UnregisterClient(a.ID) })
				if _, err := mgr.Register(context.Background(), a); err != nil {
					t.Fatal(err)
				}
				mgr.RefreshSchedulerEntry(a.ID)
			}
			call := func(g, slug, pin string) error {
				metadata := map[string]any{}
				if pin != "" {
					metadata[ex.PinnedAuthMetadataKey] = pin
				}
				_, err := mgr.Execute(auth.WithOAuthGroup(context.Background(), g), []string{"codex"}, ex.Request{Model: slug, Payload: []byte(`{"model":"gpt-6.2-sol","input":"test","service_tier":"ultrafast"}`)}, ex.Options{SourceFormat: tr.FromString("openai-response"), Metadata: metadata})
				return err
			}
			if err := call("alpha", model, ""); err != nil {
				t.Fatal(err)
			}
			if reads[0]() != "priority" || reads[1]() != "" {
				t.Fatal("alpha reached an incorrect account or tier")
			}
			if err := call("alpha", "beta/"+model, ""); err == nil {
				t.Fatal("cross-group prefix accepted")
			}
			if err := call("alpha", model, ids[1]); err == nil {
				t.Fatal("cross-group pin accepted")
			}
			if err := call("empty", model, ""); err == nil {
				t.Fatal("empty group unexpectedly served")
			}
			if reads[1]() != "" {
				t.Fatal("out-of-group traffic reached upstream")
			}
			if err := call("beta", model, ""); err != nil {
				t.Fatal(err)
			}
			if reads[1]() != "ultrafast" {
				t.Fatal("inherit did not preserve client tier")
			}
		})
	}
}

func TestCodexOAuthRetryStaysInGroup(t *testing.T) {
	const model = "gpt-6-sol"
	mgr := auth.NewManager(nil, &auth.RoundRobinSelector{}, nil)
	cfg := &config.Config{}
	mgr.SetConfig(cfg)
	mgr.SetRetryConfig(0, 0, 3)
	mgr.RegisterExecutor(NewCodexExecutor(cfg))
	var calls [3]atomic.Int32
	for i, g := range []string{"alpha", "alpha", "beta"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls[i].Add(1)
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		}))
		t.Cleanup(server.Close)
		a := codexOAuthTestAuth(server.URL)
		a.ID = t.Name() + "/" + []string{"first", "second", "outside"}[i]
		a.Metadata["oauth_group"] = g
		registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
		if _, err := mgr.Register(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		mgr.RefreshSchedulerEntry(a.ID)
	}
	ctx := auth.WithOAuthGroup(context.Background(), "alpha")
	_, err := mgr.Execute(ctx, []string{"codex"}, ex.Request{Model: model, Payload: []byte(`{"model":"gpt-6-sol","input":"test"}`)}, ex.Options{SourceFormat: tr.FromString("openai-response")})
	if err == nil || calls[0].Load() == 0 || calls[1].Load() == 0 || calls[2].Load() != 0 {
		t.Fatalf("err=%v; calls=%d,%d,%d", err, calls[0].Load(), calls[1].Load(), calls[2].Load())
	}
}
