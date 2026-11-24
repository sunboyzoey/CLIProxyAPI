package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func pluginSchedulerWantsLookupCandidates(scheduler PluginScheduler) bool {
	opt, ok := scheduler.(PluginSchedulerLookupCandidates)
	return ok && opt != nil && opt.SchedulerWantsLookupCandidates()
}

type schedulerSelectionChangedError struct{ error }

func (e *schedulerSelectionChangedError) IsRequestScoped() bool { return true }
func (e *schedulerSelectionChangedError) Unwrap() error         { return e.error }

// A capacity-aware scheduler may wait before returning a candidate. Revalidate
// against the live record at that boundary, without choosing another account or
// recording an execution result for a request that has not reached an executor.
func (m *Manager) revalidateSchedulerSelection(ctx context.Context, selected *Auth, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	changed := func() (*Auth, error) {
		return nil, wrapRequestStopError(&schedulerSelectionChangedError{&Error{
			Code: "scheduler_auth_state_changed", Message: "selected authorization changed while scheduling",
			HTTPStatus: http.StatusConflict,
		}})
	}
	if selected == nil {
		return changed()
	}
	eligibility := authSelectionEligibilityForRequest(ctx, opts)
	pinned := pinnedAuthIDFromMetadata(opts.Metadata)
	m.mu.RLock()
	defer m.mu.RUnlock()
	current := m.auths[selected.ID]
	if current == nil || current.RegistrationEpoch != selected.RegistrationEpoch ||
		current.Provider != selected.Provider || executorKeyFromAuth(current) != executorKeyFromAuth(selected) ||
		current.Disabled || current.Status == StatusDisabled ||
		(pinned != "" && current.ID != pinned) || !eligibility.allows(current) {
		return changed()
	}
	if _, used := tried[current.ID]; used {
		return changed()
	}
	if model != "" && !m.authSupportsRouteModel(registry.GetGlobalRegistry(), current, model) {
		return changed()
	}
	if _, err := m.availableAuthsForRouteModel([]*Auth{current}, current.Provider, model, time.Now()); err != nil {
		// Keep the original status, retry deadline and cause. Stop this selection
		// rather than replaying the continuation on another credential.
		return nil, wrapRequestStopError(err)
	}
	return current.Clone(), nil
}

// schedulerLookupCandidates must be called under the same manager read lock as
// availability filtering, using only candidates already authorized for this
// request. It does not enumerate credentials or relax routing restrictions.
func (m *Manager) schedulerLookupCandidates(auths []*Auth, model string, now time.Time) []pluginapi.SchedulerAuthCandidate {
	lookup := schedulerAuthCandidates(auths)
	i := 0
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		candidate := &lookup[i]
		i++
		blocked, reason, next := isAuthBlockedForModel(auth, m.selectionModelForAuth(auth, model), now)
		if !blocked {
			continue
		}
		candidate.UnavailableReason = "blocked"
		if reason != blockReasonDisabled && next.After(now) {
			candidate.UnavailableReason = "cooldown"
			delay := next.Sub(now)
			candidate.RetryAfterSeconds = int64(delay / time.Second)
			if delay%time.Second != 0 {
				candidate.RetryAfterSeconds++
			}
		}
	}
	return lookup
}
