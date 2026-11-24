package pluginhost

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type loopbackRoundTripper struct{ calls atomic.Int32 }

func (r *loopbackRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls.Add(1)
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("context-proxy"))}, nil
}

func TestLoopbackDirectBypassesOnlyOptedInCallbackTransports(t *testing.T) {
	var localCalls, proxyCalls, defaultProxyCalls atomic.Int32
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		localCalls.Add(1)
		_, _ = io.WriteString(w, "local")
	}))
	defer local.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalls.Add(1)
		_, _ = io.WriteString(w, "global-proxy")
	}))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	originalDefault := http.DefaultTransport
	defaultTransport := originalDefault.(*http.Transport).Clone()
	defaultTransport.Proxy = func(*http.Request) (*url.URL, error) { defaultProxyCalls.Add(1); return proxyURL, nil }
	http.DefaultTransport = defaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalDefault; defaultTransport.CloseIdleConnections() })
	for _, method := range []string{pluginabi.MethodHostHTTPDo, pluginabi.MethodHostHTTPDoStream} {
		t.Run(method, func(t *testing.T) {
			h := New()
			h.runtimeConfig = &config.Config{}
			h.runtimeConfig.ProxyURL = proxy.URL
			contextProxy := &loopbackRoundTripper{}
			ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", contextProxy)
			beforeLocal, beforeProxy, beforeDefault := localCalls.Load(), proxyCalls.Load(), defaultProxyCalls.Load()
			status, body := loopbackTestCall(t, h, ctx, method, map[string]any{"url": local.URL, "loopback_direct": true})
			if status != 200 || body != "local" || localCalls.Load() != beforeLocal+1 || proxyCalls.Load() != beforeProxy || defaultProxyCalls.Load() != beforeDefault || contextProxy.calls.Load() != 0 {
				t.Fatal("local callback inherited an account, global, or default proxy")
			}
			_, body = loopbackTestCall(t, h, ctx, method, map[string]any{"url": local.URL, "loopback_direct": false})
			if body != "global-proxy" || proxyCalls.Load() != beforeProxy+1 || contextProxy.calls.Load() != 0 {
				t.Fatal("ordinary callback lost global proxy behavior")
			}
			h.runtimeConfig.ProxyURL = ""
			_, body = loopbackTestCall(t, h, ctx, method, map[string]any{"url": local.URL})
			if body != "context-proxy" || contextProxy.calls.Load() != 1 {
				t.Fatal("ordinary callback lost account context transport")
			}
		})
	}
}

func TestLoopbackDirectRejectsNonLiteralDestinations(t *testing.T) {
	for _, method := range []string{pluginabi.MethodHostHTTPDo, pluginabi.MethodHostHTTPDoStream} {
		for _, destination := range []string{"http://localhost:8792/responses", "https://127.0.0.1/responses", "http://example.invalid/responses", "http://192.0.2.1/responses", "http://user@127.0.0.1/responses", "http:127.0.0.1", "http://[::ffff:192.0.2.1]/"} {
			t.Run(method+"/"+destination, func(t *testing.T) {
				h := New()
				transport := &loopbackRoundTripper{}
				ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", transport)
				// Validate the effective nested request URL, not a benign outer URL.
				raw := loopbackTestRequest(t, map[string]any{"url": "http://127.0.0.1/", "loopback_direct": true, "request": map[string]any{"url": destination}})
				if _, err := h.callFromPlugin(ctx, method, raw); err == nil || transport.calls.Load() != 0 {
					t.Fatal("non-loopback destination reached transport")
				}
			})
		}
	}
}

func TestLoopbackDirectRejectsNonBooleanOption(t *testing.T) {
	for _, value := range []any{"true", 1, nil} {
		h := New()
		transport := &loopbackRoundTripper{}
		ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", transport)
		raw := loopbackTestRequest(t, map[string]any{"url": "http://127.0.0.1:9/", "loopback_direct": value})
		if _, err := h.callFromPlugin(ctx, pluginabi.MethodHostHTTPDo, raw); err == nil || transport.calls.Load() != 0 {
			t.Fatal("non-boolean option reached HTTP transport")
		}
	}
}

func TestLoopbackDirectDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { redirected.Add(1); w.WriteHeader(200) }))
	defer target.Close()
	for _, destination := range []string{target.URL, "http://example.invalid/upstream"} {
		for _, method := range []string{pluginabi.MethodHostHTTPDo, pluginabi.MethodHostHTTPDoStream} {
			t.Run(method+"/"+destination, func(t *testing.T) {
				redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, destination, http.StatusTemporaryRedirect)
				}))
				defer redirect.Close()
				status, _ := loopbackTestCall(t, New(), context.Background(), method, map[string]any{"url": redirect.URL, "loopback_direct": true})
				if status != http.StatusTemporaryRedirect || redirected.Load() != 0 {
					t.Fatal("loopback direct followed a redirect")
				}
			})
		}
	}
}

func TestLoopbackDirectPreservesOperationCancellation(t *testing.T) {
	for _, method := range []string{pluginabi.MethodHostHTTPDo, pluginabi.MethodHostHTTPDoStream} {
		t.Run(method, func(t *testing.T) {
			started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				select {
				case <-r.Context().Done():
					close(canceled)
				case <-release:
				}
			}))
			defer server.Close()
			defer close(release)
			h := New()
			operationID := openHostHTTPOperation(t, h, context.Background(), "")
			raw := loopbackTestRequest(t, map[string]any{"operation_id": operationID, "url": server.URL, "loopback_direct": true})
			done := make(chan error, 1)
			go func() { _, err := h.callFromPlugin(context.Background(), method, raw); done <- err }()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("local request did not start")
			}
			cancelRequest := loopbackTestRequest(t, map[string]any{"operation_id": operationID})
			if _, err := h.callFromPlugin(context.Background(), pluginabi.MethodHostHTTPCancel, cancelRequest); err != nil {
				t.Fatal(err)
			}
			select {
			case <-canceled:
			case <-time.After(2 * time.Second):
				t.Fatal("local request lost operation cancellation")
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("got %v, want cancellation", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("callback did not stop")
			}
		})
	}
}

func loopbackTestCall(t *testing.T, h *Host, ctx context.Context, method string, request map[string]any) (int, string) {
	t.Helper()
	raw := loopbackTestRequest(t, request)
	reply, err := h.callFromPlugin(ctx, method, raw)
	if err != nil {
		t.Fatal(err)
	}
	if method == pluginabi.MethodHostHTTPDo {
		response, err := decodeRPCEnvelope[pluginapi.HTTPResponse](reply)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(response.Body)
	}
	response, err := decodeRPCEnvelope[rpcHostHTTPStreamResponse](reply)
	if err != nil {
		t.Fatal(err)
	}
	defer h.httpStreams.close("", nil, response.StreamID)
	var body strings.Builder
	for {
		readRequest := loopbackTestRequest(t, map[string]any{"stream_id": response.StreamID})
		reply, err = h.callFromPlugin(ctx, pluginabi.MethodHostHTTPStreamRead, readRequest)
		if err != nil {
			t.Fatal(err)
		}
		chunk, err := decodeRPCEnvelope[rpcHostHTTPStreamReadResponse](reply)
		if err != nil || chunk.Error != "" {
			t.Fatalf("stream failed: %v %s", err, chunk.Error)
		}
		body.Write(chunk.Payload)
		if chunk.Done {
			return response.StatusCode, body.String()
		}
	}
}

func loopbackTestRequest(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	doc := ojson.NewDocString(`{}`)
	for key, value := range fields {
		if err := doc.Set(key, value); err != nil {
			t.Fatal(err)
		}
	}
	return doc.Bytes()
}
