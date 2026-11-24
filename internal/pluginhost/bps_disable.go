package pluginhost

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/MoeForge/moego/ojson"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const bpsPolicyDisableReason = "BPS upstream returned request_rejected; authorization disabled automatically. Manual recovery is required."

var errBPSAlreadyPolicyDisabled = errors.New("bps_already_policy_disabled")

// callHostBPSDisable is deliberately one-way and limited to the BPS plugin.
// Modify edits the latest credential under the manager's mutation gate, so this
// callback never saves request-time token snapshots over a concurrent refresh.
func (h *Host) callHostBPSDisable(ctx context.Context, request []byte) ([]byte, error) {
	if !ojson.ValidBytes(request) {
		return nil, errors.New("bps_disable_invalid_request")
	}
	doc := ojson.ParseBytes(request)
	if h.callbackCallerPluginID(ctx, doc.Get("host_callback_id").String()) != "bps" {
		return nil, errors.New("bps_disable_caller_forbidden")
	}
	id := strings.TrimSpace(doc.Get("auth_id").String())
	account := strings.TrimSpace(doc.Get("expected_account_id").String())
	subject := strings.TrimSpace(doc.Get("expected_subject").String())
	if id == "" || account == "" || subject == "" {
		return nil, errors.New("bps_disable_identity_required")
	}
	if doc.Get("reason_code").String() != "request_rejected" {
		return nil, errors.New("bps_disable_reason_not_supported")
	}
	detectedAt, errTime := time.Parse(time.RFC3339Nano, doc.Get("detected_at").String())
	if errTime != nil || detectedAt.IsZero() {
		return nil, errors.New("bps_disable_invalid_time")
	}
	requestID := doc.Get("request_id").String()
	if len(requestID) > 128 || strings.IndexFunc(requestID, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("-_.:", r))
	}) >= 0 {
		return nil, errors.New("bps_disable_invalid_request_id")
	}
	manager := h.currentAuthManager()
	if manager == nil {
		return nil, errors.New("bps_disable_auth_unavailable")
	}
	base, exists := manager.GetByID(id)
	if !exists || base == nil {
		return nil, errors.New("bps_disable_identity_changed")
	}
	updated, committed, errModify := manager.ModifyPersisted(ctx, id, base.RegistrationEpoch, func(current *coreauth.Auth) error {
		currentAccount, currentSubject := bpsProbeIdentity(current)
		if currentAccount != account || currentSubject != subject || coreauth.IsPluginVirtualAuth(current) {
			return errors.New("bps_disable_identity_changed")
		}
		apiKey, _ := current.Metadata["api_key"].(string)
		if apiKey != "" || current.Attributes["api_key"] != "" {
			return errors.New("bps_disable_oauth_required")
		}
		if current.Disabled && current.Status == coreauth.StatusDisabled && current.Metadata["bps_auto_disable_code"] == "request_rejected" {
			return errBPSAlreadyPolicyDisabled
		}
		current.Disabled = true
		current.Status = coreauth.StatusDisabled
		current.StatusMessage = bpsPolicyDisableReason
		current.Metadata["disabled"] = true
		current.Metadata["bps_auto_disable_code"] = "request_rejected"
		current.Metadata["bps_auto_disable_reason"] = bpsPolicyDisableReason
		current.Metadata["bps_auto_disabled_at"] = detectedAt.UTC().Format(time.RFC3339Nano)
		current.Metadata["bps_auto_disable_request_id"] = requestID
		return nil
	})
	if errors.Is(errModify, errBPSAlreadyPolicyDisabled) {
		return marshalRPCResult(map[string]any{"auth_id": id, "disabled": true, "already_disabled": true})
	}
	if errModify != nil {
		// The plugin keeps its independent durable guard when host synchronization
		// fails. Do not return arbitrary persistence errors or credential details.
		return nil, errors.New("bps_disable_update_failed")
	}
	if !committed || updated == nil || !updated.Disabled {
		return nil, errors.New("bps_disable_not_committed")
	}
	return marshalRPCResult(map[string]any{"auth_id": id, "disabled": true})
}
