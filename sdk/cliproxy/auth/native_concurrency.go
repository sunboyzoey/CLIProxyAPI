package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// NativeConcurrencySnapshot reports local native Codex OAuth activity. A zero
// limit retains unlimited admission while still reporting live activity.
type NativeConcurrencySnapshot struct {
	AuthID        string `json:"auth_id"`
	Identity      string `json:"identity"`
	Active        int    `json:"active"`
	Queued        int    `json:"queued"`
	MaxConcurrent int    `json:"max_concurrent"`
	Supported     bool   `json:"supported"`
}

type nativeConcurrencyCounts struct{ active, queued int }

type nativeConcurrencyState struct {
	mu      sync.Mutex
	counts  map[string]*nativeConcurrencyCounts
	changed chan struct{}
}

func (s *nativeConcurrencyState) initLocked() {
	if s.counts == nil {
		s.counts = make(map[string]*nativeConcurrencyCounts)
	}
	if s.changed == nil {
		s.changed = make(chan struct{})
	}
}

func (s *nativeConcurrencyState) notify() {
	s.mu.Lock()
	s.initLocked()
	close(s.changed)
	s.changed = make(chan struct{})
	s.mu.Unlock()
}

func nativeConcurrencyOAuth(auth *Auth) bool {
	return auth != nil && strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") &&
		!IsCodexUseSIWC(auth) && !IsPluginVirtualAuth(auth) &&
		auth.AuthKind() != AuthKindAPIKey && authMetadataString(auth, "api_key") == "" &&
		strings.TrimSpace(auth.Attributes["api_key"]) == ""
}

// NativeCodexIdentity derives a credential identity without exposing tokens. The
// token subject and account jointly isolate users sharing an organization.
func NativeCodexIdentity(auth *Auth) (identity, accountID, subject string) {
	if !nativeConcurrencyOAuth(auth) {
		return "", "", ""
	}
	claims, err := codex.ParseJWTToken(authMetadataString(auth, "access_token"))
	if err != nil || claims.Sub == "" || claims.CodexAuthInfo.ChatgptAccountID == "" {
		return "", "", ""
	}
	account, sub := claims.CodexAuthInfo.ChatgptAccountID, claims.Sub
	sum := sha256.Sum256([]byte(sub + "\x00" + account))
	return hex.EncodeToString(sum[:]), account, sub
}

func nativeConcurrencyLimit(auth *Auth) int {
	if auth == nil {
		return 0
	}
	limit, ok := parseIntAny(auth.Metadata["max_concurrent"])
	if !ok || limit < 0 {
		return 0
	}
	return limit
}

// Caller holds m.mu. Duplicate files for the same subject/account share the
// strictest configured limit, so another copy cannot bypass admission.
func (m *Manager) nativeConcurrencyLimitLocked(identity string) int {
	limit := 0
	for _, candidate := range m.auths {
		configured := nativeConcurrencyLimit(candidate)
		if configured <= 0 {
			continue
		}
		key, _, _ := NativeCodexIdentity(candidate)
		if key == identity && (limit == 0 || configured < limit) {
			limit = configured
		}
	}
	return limit
}

// NativeConcurrency returns a coherent snapshot for the current credential.
func (m *Manager) NativeConcurrency(authID string) NativeConcurrencySnapshot {
	return m.NativeConcurrencies([]string{authID})[authID]
}

// NativeConcurrencies reads an entire dashboard batch in one inventory pass and
// one activity lock. All rows observe the same limit and counter snapshot.
func (m *Manager) NativeConcurrencies(authIDs []string) map[string]NativeConcurrencySnapshot {
	snapshots := make(map[string]NativeConcurrencySnapshot, len(authIDs))
	for _, id := range authIDs {
		snapshots[id] = NativeConcurrencySnapshot{AuthID: id}
	}
	if m == nil || m.HomeEnabled() {
		return snapshots
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	limits := make(map[string]int)
	for id, candidate := range m.auths {
		_, requested := snapshots[id]
		limit := nativeConcurrencyLimit(candidate)
		if !requested && limit <= 0 {
			continue
		}
		identity, _, _ := NativeCodexIdentity(candidate)
		if identity == "" {
			continue
		}
		if limit > 0 && (limits[identity] == 0 || limit < limits[identity]) {
			limits[identity] = limit
		}
		if requested {
			snapshots[id] = NativeConcurrencySnapshot{AuthID: id, Identity: identity, Supported: true}
		}
	}
	m.nativeConcurrency.mu.Lock()
	defer m.nativeConcurrency.mu.Unlock()
	for id, snapshot := range snapshots {
		snapshot.MaxConcurrent = limits[snapshot.Identity]
		if counts := m.nativeConcurrency.counts[snapshot.Identity]; counts != nil {
			snapshot.Active, snapshot.Queued = counts.active, counts.queued
		}
		snapshots[id] = snapshot
	}
	return snapshots
}

type nativeConcurrencyLease struct {
	once  sync.Once
	state *nativeConcurrencyState
	key   string
}

func (lease *nativeConcurrencyLease) release() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		s := lease.state
		s.mu.Lock()
		if counts := s.counts[lease.key]; counts != nil {
			counts.active--
			if counts.active == 0 && counts.queued == 0 {
				delete(s.counts, lease.key)
			}
		}
		close(s.changed)
		s.changed = make(chan struct{})
		s.mu.Unlock()
	})
}

func (m *Manager) tryNativeConcurrency(selected *Auth) (*nativeConcurrencyLease, string, error) {
	if !nativeConcurrencyOAuth(selected) {
		return nil, "", nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	current := m.auths[selected.ID]
	identity, _, _ := NativeCodexIdentity(current)
	selectedIdentity, _, _ := NativeCodexIdentity(selected)
	if current == nil || current.RegistrationEpoch != selected.RegistrationEpoch || current.Disabled || current.Status == StatusDisabled || identity != selectedIdentity {
		return nil, "", wrapRequestStopError(&schedulerSelectionChangedError{errors.New("native concurrency authorization changed")})
	}
	if identity == "" {
		if nativeConcurrencyLimit(current) > 0 {
			return nil, "", wrapRequestStopError(&schedulerSelectionChangedError{&Error{Code: "native_concurrency_identity_required", Message: "native concurrency requires a Codex OAuth identity", HTTPStatus: http.StatusConflict}})
		}
		return nil, "", nil
	}
	limit := m.nativeConcurrencyLimitLocked(identity)
	s := &m.nativeConcurrency
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initLocked()
	counts := s.counts[identity]
	if counts == nil {
		counts = &nativeConcurrencyCounts{}
		s.counts[identity] = counts
	}
	if limit > 0 && counts.active >= limit {
		return nil, identity, nil
	}
	counts.active++
	return &nativeConcurrencyLease{state: s, key: identity}, "", nil
}

// pickNextMixedAdmitted rotates past saturated credentials before waiting. A
// capacity rejection is local scheduling state, never an upstream auth result.
func (m *Manager) pickNextMixedAdmitted(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, ProviderExecutor, string, *nativeConcurrencyLease, error) {
	if m.HomeEnabled() {
		auth, executor, provider, err := m.pickNextMixed(ctx, providers, model, opts, tried)
		return auth, executor, provider, nil, err
	}
	return m.pickNativeAdmitted(ctx, tried, func(excluded map[string]struct{}) (*Auth, ProviderExecutor, string, error) {
		return m.pickNextMixed(ctx, providers, model, opts, excluded)
	})
}

// AcquireAuthWithCredentialPolicy selects and admits a standalone business
// request. Callers own release until their response body has been consumed and
// closed. HttpRequest itself does not acquire again, so executor-internal HTTP
// calls remain inside their existing execution lease.
func (m *Manager) AcquireAuthWithCredentialPolicy(ctx context.Context, provider, model, policy string, opts cliproxyexecutor.Options) (*Auth, func(), error) {
	noop := func() {}
	if m == nil || m.HomeEnabled() {
		return nil, noop, &Error{Code: "home_unavailable", Message: "local admission is unavailable while Home is enabled", HTTPStatus: http.StatusServiceUnavailable}
	}
	policy = normalizeCredentialPolicy(policy)
	if policy == "" {
		return nil, noop, &Error{Code: "invalid_credential_policy", Message: "credential policy is invalid", HTTPStatus: http.StatusBadRequest}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	selectionCtx := withCredentialPolicy(ctx, policy)
	selected, _, _, lease, err := m.pickNativeAdmitted(selectionCtx, nil, func(excluded map[string]struct{}) (*Auth, ProviderExecutor, string, error) {
		auth, executor, err := m.pickNextLegacy(selectionCtx, provider, model, opts, excluded)
		return auth, executor, provider, err
	})
	if err != nil {
		return nil, noop, unwrapExecutionBoundaryError(err)
	}
	if selected == nil || !credentialPolicyAllows(policy, selected) || m.HomeEnabled() {
		lease.release()
		return nil, noop, &Error{Code: "auth_not_found", Message: "selector returned no eligible local auth", HTTPStatus: http.StatusServiceUnavailable}
	}
	return selected, lease.release, nil
}

// AcquireAuthByKind admits a standalone execution or retained session with the
// same credential-kind filter as SelectAuthByKind. Session owners retain the
// idempotent release until session shutdown, rather than HTTP bootstrap return.
func (m *Manager) AcquireAuthByKind(ctx context.Context, provider, model, requiredKind string, opts cliproxyexecutor.Options) (*Auth, func(), error) {
	noop := func() {}
	if m == nil || m.HomeEnabled() {
		return nil, noop, &Error{Code: "home_unavailable", Message: "local admission is unavailable while Home is enabled", HTTPStatus: http.StatusServiceUnavailable}
	}
	requiredKind = normalizeAuthKind(requiredKind)
	if requiredKind == "" {
		return nil, noop, &Error{Code: "invalid_auth_kind", Message: "required auth kind is invalid", HTTPStatus: http.StatusBadRequest}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	selectionCtx := withRequiredAuthKind(ctx, requiredKind)
	selected, _, _, lease, err := m.pickNativeAdmitted(selectionCtx, nil, func(excluded map[string]struct{}) (*Auth, ProviderExecutor, string, error) {
		auth, executor, err := m.pickNextLegacy(selectionCtx, provider, model, opts, excluded)
		return auth, executor, provider, err
	})
	if err != nil {
		return nil, noop, unwrapExecutionBoundaryError(err)
	}
	if selected == nil || selected.AuthKind() != requiredKind || m.HomeEnabled() {
		lease.release()
		return nil, noop, &Error{Code: "auth_not_found", Message: "selector returned no eligible local auth", HTTPStatus: http.StatusServiceUnavailable}
	}
	return selected, lease.release, nil
}

func (m *Manager) pickNativeAdmitted(ctx context.Context, tried map[string]struct{}, pick func(map[string]struct{}) (*Auth, ProviderExecutor, string, error)) (*Auth, ProviderExecutor, string, *nativeConcurrencyLease, error) {
	s := &m.nativeConcurrency
	queuedKey := ""
	defer func() {
		if queuedKey != "" {
			s.mu.Lock()
			counts := s.counts[queuedKey]
			counts.queued--
			if counts.active == 0 && counts.queued == 0 {
				delete(s.counts, queuedKey)
			}
			s.mu.Unlock()
		}
	}()
	for {
		s.mu.Lock()
		s.initLocked()
		changed := s.changed
		s.mu.Unlock()
		excluded := make(map[string]struct{}, len(tried))
		for id := range tried {
			excluded[id] = struct{}{}
		}
		firstBlocked := ""
		for {
			auth, executor, provider, err := pick(excluded)
			if err != nil {
				var authErr *Error
				canWait := isAuthUnavailableError(err) || (errors.As(err, &authErr) && authErr.Code == "auth_not_found")
				if firstBlocked == "" || !canWait {
					return nil, nil, "", nil, err
				}
				break
			}
			// Only native Codex requests participate in this admission gate.
			// Other providers retain their own preparation and cancellation semantics.
			if !nativeConcurrencyOAuth(auth) {
				return auth, executor, provider, nil, nil
			}
			if err := ctx.Err(); err != nil {
				return nil, nil, "", nil, err
			}
			lease, blocked, errAdmission := m.tryNativeConcurrency(auth)
			if errAdmission != nil {
				return nil, nil, "", nil, errAdmission
			}
			if blocked == "" {
				return auth, executor, provider, lease, nil
			}
			if firstBlocked == "" {
				firstBlocked = blocked
			}
			excluded[auth.ID] = struct{}{}
		}
		if queuedKey != firstBlocked {
			s.mu.Lock()
			if queuedKey != "" {
				counts := s.counts[queuedKey]
				counts.queued--
				if counts.active == 0 && counts.queued == 0 {
					delete(s.counts, queuedKey)
				}
			}
			if s.counts[firstBlocked] == nil {
				s.counts[firstBlocked] = &nativeConcurrencyCounts{}
			}
			s.counts[firstBlocked].queued++
			queuedKey = firstBlocked
			s.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return nil, nil, "", nil, ctx.Err()
		case <-changed:
		}
	}
}
