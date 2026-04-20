package auth

import (
	"context"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// shouldAutoRemoveAuth determines whether an auth entry should be automatically
// removed from the pool based on the error status code and account type.
//
// Removal conditions:
//   - 401: token permanently invalid, cannot recover
//   - 403 with banned/suspended: account banned by OpenAI
//   - 429 on free accounts: quota exhausted, not worth waiting
//
// Non-removal conditions (handled by existing cooldown):
//   - 429 on plus/team: temporary rate limit, will recover
//   - 500/502/503/504: transient upstream errors
func shouldAutoRemoveAuth(auth *Auth, statusCode int) bool {
	if auth == nil {
		return false
	}

	switch statusCode {
	case 401:
		// Token invalid — unrecoverable
		return true

	case 403:
		// Only remove if explicitly banned/suspended
		msg := strings.ToLower(auth.StatusMessage)
		if strings.Contains(msg, "banned") ||
			strings.Contains(msg, "suspended") ||
			strings.Contains(msg, "deactivated") ||
			strings.Contains(msg, "payment_required") {
			return true
		}
		return false

	case 429:
		// Free accounts: remove (quota too small, not worth waiting)
		// Plus/Team accounts: keep (cooldown mechanism handles recovery)
		return isFreeAccount(auth)

	default:
		return false
	}
}

// isFreeAccount checks whether an auth entry is a free-tier ChatGPT account
// by inspecting JWT metadata for chatgpt_plan_type.
func isFreeAccount(auth *Auth) bool {
	if auth == nil {
		return true // safer to assume free if unknown
	}

	planType := extractPlanType(auth)
	planType = strings.ToLower(strings.TrimSpace(planType))

	// Known paid plan types
	switch planType {
	case "plus", "team", "enterprise", "business", "pro", "chatgptplus":
		return false
	}

	// Anything else (empty, "free", unknown) is treated as free
	return true
}

// extractPlanType tries to get the plan type from auth metadata.
func extractPlanType(auth *Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}

	// Direct metadata field
	for _, key := range []string{
		"chatgpt_plan_type",
		"plan_type",
		"resolved_plan_type",
	} {
		if v, ok := auth.Metadata[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}

	// Nested in auth info (from JWT)
	if authInfo, ok := auth.Metadata["https://api.openai.com/auth"].(map[string]any); ok {
		if v, ok := authInfo["chatgpt_plan_type"].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}

	return ""
}

// autoRemoveAuth disables and deletes an auth entry from the manager.
// It marks the auth as disabled first (so it stops being used immediately),
// then removes it from the store.
func (m *Manager) autoRemoveAuth(ctx context.Context, auth *Auth, reason string) {
	if m == nil || auth == nil {
		return
	}

	authID := auth.ID
	fileName := auth.FileName
	planType := extractPlanType(auth)

	log.WithFields(log.Fields{
		"auth_id":   authID,
		"file":      fileName,
		"reason":    reason,
		"plan_type": planType,
		"status":    auth.StatusMessage,
	}).Info("[AutoCleanup] removing auth from pool")

	// Mark disabled so it's excluded from scheduling immediately
	auth.Disabled = true
	auth.Status = StatusDisabled
	auth.StatusMessage = "auto-removed: " + reason
	auth.UpdatedAt = time.Now()
	auth.Unavailable = true

	// Delete from store (file system / database)
	if m.store != nil {
		if err := m.store.Delete(ctx, authID); err != nil {
			log.WithError(err).WithField("auth_id", authID).Warn("[AutoCleanup] store delete failed")
		}
	}

	// Remove from in-memory map
	delete(m.auths, authID)

	log.WithField("auth_id", authID).Info("[AutoCleanup] auth removed successfully")
}
