package helps

import (
	"context"
	"errors"
	"net/http"
	"time"
)

type codexHTTPWebsocketKey struct{}

type codexHTTPWebsocketState struct{ generatedSession string }

// WithCodexHTTPWebsocket identifies the opt-in HTTP SSE to upstream WS bridge.
func WithCodexHTTPWebsocket(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, codexHTTPWebsocketKey{}, &codexHTTPWebsocketState{})
}

func IsCodexHTTPWebsocket(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	state, _ := ctx.Value(codexHTTPWebsocketKey{}).(*codexHTTPWebsocketState)
	return state != nil
}

type codexHTTPWebsocketSentError struct{ cause error }

func (e *codexHTTPWebsocketSentError) Error() string       { return e.cause.Error() }
func (e *codexHTTPWebsocketSentError) Unwrap() error       { return e.cause }
func (e *codexHTTPWebsocketSentError) IsRequestStop() bool { return true }
func (e *codexHTTPWebsocketSentError) StatusCode() int {
	var status interface{ StatusCode() int }
	if errors.As(e.cause, &status) {
		return status.StatusCode()
	}
	return http.StatusBadGateway
}
func (e *codexHTTPWebsocketSentError) Headers() http.Header {
	var headers interface{ Headers() http.Header }
	if errors.As(e.cause, &headers) {
		return headers.Headers()
	}
	return nil
}
func (e *codexHTTPWebsocketSentError) RetryAfter() *time.Duration {
	var retry interface{ RetryAfter() *time.Duration }
	if errors.As(e.cause, &retry) {
		return retry.RetryAfter()
	}
	return nil
}

// CodexHTTPWebsocketSentError prevents retries once response.create may have
// reached the upstream. An unsuccessful write is ambiguous and also stops retry.
func CodexHTTPWebsocketSentError(err error) error {
	if err == nil {
		return nil
	}
	var sent *codexHTTPWebsocketSentError
	if errors.As(err, &sent) {
		return err
	}
	return &codexHTTPWebsocketSentError{cause: err}
}

// CodexHTTPWebsocketHandshakeFallback allows a single HTTP fallback only before
// response.create is written. Authentication and quota failures stay visible.
func CodexHTTPWebsocketHandshakeFallback(ctx context.Context, resp *http.Response) bool {
	if ctx.Err() != nil {
		return false
	}
	if resp == nil {
		return true
	}
	switch resp.StatusCode {
	case 400, 404, 405, 426, 502, 503, 504:
		return true
	default:
		return false
	}
}

// SetGeneratedHTTPWebsocketSession records the random fallback during preparation,
// before request state is handed to background goroutines.
func SetGeneratedHTTPWebsocketSession(ctx context.Context, id string) {
	if state, ok := ctx.Value(codexHTTPWebsocketKey{}).(*codexHTTPWebsocketState); ok {
		state.generatedSession = id
	}
}
func GeneratedHTTPWebsocketSession(ctx context.Context) string {
	if state, ok := ctx.Value(codexHTTPWebsocketKey{}).(*codexHTTPWebsocketState); ok {
		return state.generatedSession
	}
	return ""
}
