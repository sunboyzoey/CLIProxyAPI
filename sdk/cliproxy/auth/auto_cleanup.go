package auth

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	log "github.com/sirupsen/logrus"
)

// shouldAutoRemoveAuth determines whether an auth entry should be automatically
// removed from the pool based on the error status code and account type.
//
// Removal conditions:
//   - 401: token permanently invalid, cannot recover
//   - 403 with banned/suspended: account banned by OpenAI
//
// Non-removal conditions (handled by existing cooldown):
//   - 429: moved to the rate-limit quarantine directory by quarantineRateLimitedAuth
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
	if m.scheduler != nil {
		m.scheduler.removeAuth(authID)
	}

	log.WithField("auth_id", authID).Info("[AutoCleanup] auth removed successfully")
}

// quarantineRateLimitedAuth moves a 429-limited file-backed auth out of the active
// auth directory so external tooling can decide when to restore it.
func (m *Manager) quarantineRateLimitedAuth(ctx context.Context, auth *Auth, reason string) {
	if m == nil || auth == nil {
		return
	}

	authID := auth.ID
	srcPath := authFilePath(auth)
	dstDir := m.rateLimitAuthDir()
	dstPath := ""
	if srcPath != "" && dstDir != "" {
		var errMove error
		dstPath, errMove = moveAuthFileToDir(srcPath, dstDir)
		if errMove != nil {
			log.WithError(errMove).WithFields(log.Fields{
				"auth_id": authID,
				"src":     srcPath,
				"dst_dir": dstDir,
			}).Warn("[AutoCleanup] failed to quarantine rate-limited auth file")
		}
	}

	auth.Disabled = true
	auth.Status = StatusDisabled
	auth.StatusMessage = "rate-limited: " + reason
	auth.UpdatedAt = time.Now()
	auth.Unavailable = true

	delete(m.auths, authID)
	if m.scheduler != nil {
		m.scheduler.removeAuth(authID)
	}

	log.WithFields(log.Fields{
		"auth_id": authID,
		"src":     srcPath,
		"dst":     dstPath,
		"reason":  reason,
	}).Info("[AutoCleanup] rate-limited auth quarantined")

	_ = ctx
}

func authFilePath(auth *Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil {
		if path := strings.TrimSpace(auth.Attributes["path"]); path != "" {
			return path
		}
	}
	if strings.TrimSpace(auth.ID) != "" && filepath.IsAbs(auth.ID) {
		return auth.ID
	}
	return ""
}

func (m *Manager) rateLimitAuthDir() string {
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	authDir := ""
	rateLimitDir := ""
	if cfg != nil {
		authDir = strings.TrimSpace(cfg.AuthDir)
		rateLimitDir = strings.TrimSpace(cfg.RateLimitAuthDir)
	}
	authDir = expandHomePath(authDir)
	if authDir == "" {
		authDir = expandHomePath(internalconfig.DefaultAuthDir)
	}
	if rateLimitDir == "" {
		rateLimitDir = authDir + "-429"
	} else {
		rateLimitDir = expandHomePath(rateLimitDir)
	}
	if directoryContains(authDir, rateLimitDir) {
		safeDir := authDir + "-429"
		log.WithFields(log.Fields{
			"configured": rateLimitDir,
			"fallback":   safeDir,
		}).Warn("[AutoCleanup] rate-limit-auth-dir is inside auth-dir; using sibling fallback")
		rateLimitDir = safeDir
	}
	return filepath.Clean(rateLimitDir)
}

func expandHomePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || !strings.HasPrefix(path, "~") {
		return path
	}
	home, errHome := os.UserHomeDir()
	if errHome != nil || home == "" {
		return path
	}
	remainder := strings.TrimLeft(strings.TrimPrefix(path, "~"), `/\`)
	if remainder == "" {
		return filepath.Clean(home)
	}
	return filepath.Clean(filepath.Join(home, filepath.FromSlash(strings.ReplaceAll(remainder, "\\", "/"))))
}

func directoryContains(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	if parent == "" || child == "" {
		return false
	}
	rel, errRel := filepath.Rel(parent, child)
	if errRel != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func moveAuthFileToDir(srcPath, dstDir string) (string, error) {
	srcPath = filepath.Clean(strings.TrimSpace(srcPath))
	dstDir = filepath.Clean(strings.TrimSpace(dstDir))
	if srcPath == "" {
		return "", fmt.Errorf("source path is empty")
	}
	if dstDir == "" {
		return "", fmt.Errorf("destination directory is empty")
	}
	if errMkdir := os.MkdirAll(dstDir, 0o700); errMkdir != nil {
		return "", fmt.Errorf("create destination dir: %w", errMkdir)
	}
	dstPath := uniqueDestinationPath(filepath.Join(dstDir, filepath.Base(srcPath)))
	if errRename := os.Rename(srcPath, dstPath); errRename == nil {
		return dstPath, nil
	}
	if errCopy := copyFile(srcPath, dstPath); errCopy != nil {
		return "", errCopy
	}
	if errRemove := os.Remove(srcPath); errRemove != nil {
		return "", fmt.Errorf("remove source after copy: %w", errRemove)
	}
	return dstPath, nil
}

func uniqueDestinationPath(path string) string {
	if _, errStat := os.Stat(path); os.IsNotExist(errStat) {
		return path
	}
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	stamp := time.Now().UTC().Format("20060102T150405Z")
	for i := 0; ; i++ {
		candidate := fmt.Sprintf("%s.%s%s", base, stamp, ext)
		if i > 0 {
			candidate = fmt.Sprintf("%s.%s.%d%s", base, stamp, i, ext)
		}
		if _, errStat := os.Stat(candidate); os.IsNotExist(errStat) {
			return candidate
		}
	}
}

func copyFile(srcPath, dstPath string) error {
	src, errOpen := os.Open(srcPath)
	if errOpen != nil {
		return fmt.Errorf("open source: %w", errOpen)
	}
	defer func() {
		if errClose := src.Close(); errClose != nil {
			log.Errorf("[AutoCleanup] close source auth file: %v", errClose)
		}
	}()
	dst, errCreate := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errCreate != nil {
		return fmt.Errorf("create destination: %w", errCreate)
	}
	if _, errCopy := io.Copy(dst, src); errCopy != nil {
		_ = dst.Close()
		_ = os.Remove(dstPath)
		return fmt.Errorf("copy auth file: %w", errCopy)
	}
	if errClose := dst.Close(); errClose != nil {
		_ = os.Remove(dstPath)
		return fmt.Errorf("close destination: %w", errClose)
	}
	return nil
}
