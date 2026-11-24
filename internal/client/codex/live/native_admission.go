package live

import (
	"context"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Only new sessions acquire local capacity. Sideband and hangup operate under
// their stored session's lease and must not wait for a second slot themselves.
func (h *Handler) acquireOAuth(ctx context.Context, model string, opts coreexecutor.Options) (*auth.HomeDispatchSelection, *auth.Auth, func(), error) {
	if h.sessions.stopped() {
		return nil, nil, func() {}, &auth.Error{Code: "live_session_closed", Message: "Codex live session service stopped", HTTPStatus: http.StatusServiceUnavailable}
	}
	if h.authManager.HomeEnabled() {
		selection, selected, err := h.selectOAuth(ctx, model, opts)
		return selection, selected, func() {}, err
	}
	selected, release, err := h.authManager.AcquireAuthByKind(ctx, "codex", "", auth.AuthKindOAuth, opts)
	if err == nil && h.sessions.stopped() {
		release()
		return nil, nil, func() {}, &auth.Error{Code: "live_session_closed", Message: "Codex live session service stopped", HTTPStatus: http.StatusServiceUnavailable}
	}
	return nil, selected, release, err
}

// Direct WebSockets have no call ID or bootstrap lifetime. Track their resources
// until the relay ends, and close sockets before releasing admission on cancel
// or handler shutdown. This adds no timeout to an established upstream session.
func (h *Handler) retainDirectSession(ctx context.Context, closers ...func() error) (func(), bool) {
	resources := &liveSessionResources{}
	resources.add(closers...)
	release, active := h.sessions.trackResources(resources)
	if !active {
		return release, false
	}
	stopCancel := context.AfterFunc(ctx, resources.close)
	return func() { stopCancel(); release() }, true
}

func (s *sessionStore) trackResources(resources *liveSessionResources) (func(), bool) {
	if s == nil {
		resources.close()
		return func() {}, false
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		resources.close()
		return func() {}, false
	}
	if s.activeResources == nil {
		s.activeResources = make(map[*liveSessionResources]struct{})
	}
	s.activeResources[resources] = struct{}{}
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		delete(s.activeResources, resources)
		s.mu.Unlock()
		resources.close()
	}, true
}

func (s *sessionStore) stopped() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
