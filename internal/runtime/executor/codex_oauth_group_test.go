package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MoeForge/moego/ojson"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	tr "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func useOAuthTierManifest(t *testing.T) {
	t.Helper()
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.RegisterProtocol("https", roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "chatgpt.com" || r.URL.Path != "/backend-api/codex/models" {
			return nil, fmt.Errorf("unexpected manifest request to %s", r.URL)
		}
		const manifest = `{"models":[{"slug":"gpt-6.2-sol","service_tiers":[{"id":"fast"},{"id":"ultrafast"}]},{"slug":"gpt-5.4-mini","service_tiers":[{"id":"fast"}]}]}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(manifest))}, nil
	}))
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
}

func TestCodexOAuthGroupRoutingAndTier(t *testing.T) {
	const model = "gpt-6.2-sol"
	useOAuthTierManifest(t)
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

func TestCodexOAuthImageResponsesTier(t *testing.T) {
	useOAuthTierManifest(t)
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			const mainModel = codexOpenAIImagesMainModel
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if r.URL.Path != "/responses" || ojson.GetBytes(body, "model").String() != mainModel || ojson.GetBytes(body, "service_tier").String() != "priority" {
					t.Errorf("unexpected image request: path %q, model %q, tier %q", r.URL.Path, ojson.GetBytes(body, "model").String(), ojson.GetBytes(body, "service_tier").String())
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: "+`{"type":"response.completed","response":{"output":[{"type":"image_generation_call","result":"aW1hZ2U="}]}}`+"\n\n")
			}))
			t.Cleanup(server.Close)
			e := NewCodexExecutor(&config.Config{})
			a := codexOAuthTestAuth(server.URL)
			a.ID = t.Name()
			a.Metadata["service_tier"] = "fast"
			req := ex.Request{Model: "image-tool", Payload: []byte(`{"model":"image-tool","prompt":"fixture"}`)}
			opts := codexOpenAIImageTestOptions(codexImagesGenerationsPath, stream)
			if stream {
				result, err := e.ExecuteStream(t.Context(), a, req, opts)
				if err != nil {
					t.Fatal(err)
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
				}
			} else if _, err := e.Execute(t.Context(), a, req, opts); err != nil {
				t.Fatal(err)
			}
		})
	}
}
