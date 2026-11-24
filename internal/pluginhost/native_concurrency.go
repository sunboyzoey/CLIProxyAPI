package pluginhost

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"

	"github.com/MoeForge/moego/ojson"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
)

type nativeConcurrencyReference struct {
	AuthIndex         string `json:"auth_index"`
	ExpectedAuthID    string `json:"expected_auth_id"`
	ExpectedAccountID string `json:"expected_account_id"`
	ExpectedSubject   string `json:"expected_subject"`
	ExpectedIdentity  string `json:"expected_identity"`
}

func matchesNativeConcurrencyReference(auth *coreauth.Auth, ref nativeConcurrencyReference) bool {
	identity, account, subject := coreauth.NativeCodexIdentity(auth)
	return auth != nil && identity != "" && auth.ID == ref.ExpectedAuthID && auth.Index == ref.AuthIndex &&
		ref.ExpectedAccountID == account && ref.ExpectedSubject == subject &&
		(ref.ExpectedIdentity == "" || ref.ExpectedIdentity == identity)
}

func (h *Host) nativeConcurrencyAuth(ref nativeConcurrencyReference) (*coreauth.Auth, error) {
	if ref.AuthIndex == "" || ref.ExpectedAuthID == "" || ref.ExpectedAccountID == "" || ref.ExpectedSubject == "" {
		return nil, errors.New("native_concurrency_identity_required")
	}
	manager := h.currentAuthManager()
	if manager == nil {
		return nil, errors.New("native_concurrency_unavailable")
	}
	auth, exists := manager.GetByID(ref.ExpectedAuthID)
	if !exists || !matchesNativeConcurrencyReference(auth, ref) {
		return nil, errors.New("native_concurrency_identity_changed")
	}
	return auth, nil
}

func decodeNativeConcurrencyReference(raw []byte) (nativeConcurrencyReference, error) {
	var ref nativeConcurrencyReference
	if !ojson.ValidBytes(raw) {
		return ref, errors.New("native_concurrency_invalid_request")
	}
	doc := ojson.ParseBytes(raw)
	ref.AuthIndex = doc.Get("auth_index").String()
	ref.ExpectedAuthID = doc.Get("expected_auth_id").String()
	ref.ExpectedAccountID = doc.Get("expected_account_id").String()
	ref.ExpectedSubject = doc.Get("expected_subject").String()
	ref.ExpectedIdentity = doc.Get("expected_identity").String()
	ref.AuthIndex = strings.TrimSpace(ref.AuthIndex)
	ref.ExpectedAuthID = strings.TrimSpace(ref.ExpectedAuthID)
	ref.ExpectedAccountID = strings.TrimSpace(ref.ExpectedAccountID)
	ref.ExpectedSubject = strings.TrimSpace(ref.ExpectedSubject)
	ref.ExpectedIdentity = strings.TrimSpace(ref.ExpectedIdentity)
	return ref, nil
}

func (h *Host) callHostNativeConcurrency(ctx context.Context, raw []byte, set bool) ([]byte, error) {
	ref, err := decodeNativeConcurrencyReference(raw)
	if err != nil {
		return nil, err
	}
	manager := h.currentAuthManager()
	if manager == nil || manager.HomeEnabled() {
		return nil, errors.New("native_concurrency_unavailable")
	}
	auth, err := h.nativeConcurrencyAuth(ref)
	if err != nil {
		return nil, err
	}
	if set {
		caller := h.callbackCallerPluginID(ctx, ojson.GetBytes(raw, "host_callback_id").String())
		if caller != "bps" {
			return nil, errors.New("native_concurrency_caller_forbidden")
		}
		limitValue := ojson.GetBytes(raw, "max_concurrent")
		proxyValue := ojson.GetBytes(raw, "proxy_url")
		priorityValue := ojson.GetBytes(raw, "priority")
		if !limitValue.Exists() && !proxyValue.Exists() && !priorityValue.Exists() {
			return nil, errors.New("native_settings_fields_required")
		}
		limit := limitValue.Float()
		if limitValue.Exists() && (limitValue.Type != ojson.Number || limit < 0 || limit > 10_000 || math.Trunc(limit) != limit) {
			return nil, errors.New("native_concurrency_invalid_limit")
		}
		proxyURL := ""
		if proxyValue.Exists() {
			setting, errProxy := proxyutil.Parse(proxyValue.String())
			if proxyValue.Type != ojson.String || errProxy != nil {
				return nil, errors.New("native_settings_invalid_proxy")
			}
			proxyURL = setting.Raw
		}
		priority := priorityValue.Float()
		if priorityValue.Exists() && (priorityValue.Type != ojson.Number || priority < math.MinInt32 || priority > math.MaxInt32 || math.Trunc(priority) != priority) {
			return nil, errors.New("native_settings_invalid_priority")
		}
		updated, committed, errModify := manager.ModifyPersisted(ctx, auth.ID, auth.RegistrationEpoch, func(current *coreauth.Auth) error {
			if !matchesNativeConcurrencyReference(current, ref) {
				return errors.New("native_concurrency_identity_changed")
			}
			if limitValue.Exists() {
				current.Metadata["max_concurrent"] = int(limit)
			}
			if proxyValue.Exists() {
				current.ProxyURL = proxyURL
				current.Metadata["proxy_url"] = proxyURL
			}
			if priorityValue.Exists() {
				if current.Attributes == nil {
					current.Attributes = make(map[string]string)
				}
				current.Attributes["priority"] = strconv.Itoa(int(priority))
				current.Metadata["priority"] = int(priority)
			}
			return nil
		})
		if errModify != nil || !committed || updated == nil {
			return nil, errors.New("native_concurrency_update_failed")
		}
	}
	snapshot := manager.NativeConcurrency(auth.ID)
	if identity, _, _ := coreauth.NativeCodexIdentity(auth); snapshot.Identity != identity || !snapshot.Supported {
		return nil, errors.New("native_concurrency_identity_changed")
	}
	return marshalRPCResult(snapshot)
}

func (h *Host) callHostNativeConcurrencyList(_ context.Context, raw []byte) ([]byte, error) {
	var request struct {
		Accounts []nativeConcurrencyReference `json:"accounts"`
	}
	if !ojson.ValidBytes(raw) || !ojson.GetBytes(raw, "accounts").IsArray() || len(ojson.GetBytes(raw, "accounts").Array()) > 1000 {
		return nil, errors.New("native_concurrency_invalid_request")
	}
	for _, value := range ojson.GetBytes(raw, "accounts").Array() {
		ref, _ := decodeNativeConcurrencyReference([]byte(value.Raw))
		request.Accounts = append(request.Accounts, ref)
	}
	type item struct {
		coreauth.NativeConcurrencySnapshot
		Error string `json:"error,omitempty"`
	}
	manager := h.currentAuthManager()
	supported := manager != nil && !manager.HomeEnabled()
	authIDs := make([]string, 0, len(request.Accounts))
	for _, ref := range request.Accounts {
		authIDs = append(authIDs, ref.ExpectedAuthID)
	}
	snapshots := manager.NativeConcurrencies(authIDs)
	accounts := make([]item, 0, len(request.Accounts))
	for _, ref := range request.Accounts {
		entry := item{NativeConcurrencySnapshot: coreauth.NativeConcurrencySnapshot{AuthID: ref.ExpectedAuthID}}
		if !supported {
			entry.Error = "native_concurrency_unavailable"
		} else if auth, err := h.nativeConcurrencyAuth(ref); err != nil {
			entry.Error = err.Error()
		} else {
			entry.NativeConcurrencySnapshot = snapshots[auth.ID]
			identity, _, _ := coreauth.NativeCodexIdentity(auth)
			if entry.Identity != identity || !entry.Supported {
				entry = item{NativeConcurrencySnapshot: coreauth.NativeConcurrencySnapshot{AuthID: ref.ExpectedAuthID}, Error: "native_concurrency_identity_changed"}
			}
		}
		accounts = append(accounts, entry)
	}
	return marshalRPCResult(map[string]any{"supported": supported, "accounts": accounts})
}
