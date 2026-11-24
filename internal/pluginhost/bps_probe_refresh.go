package pluginhost

import (
	"context"
	"errors"
	"strings"

	"github.com/MoeForge/moego/ojson"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// A probe's fallback proxy belongs to this renewal, not the stored account.
// Apply it to every outgoing view, then restore only the proxy fields before
// the manager persists the refreshed token. Ordinary refreshes are unchanged.
func (h *Host) prepareBPSProbeRefresh(ctx context.Context, auth *coreauth.Auth, request *pluginapi.AuthRefreshRequest) (func(*pluginapi.AuthData) error, error) {
	proxyURL, probe := coreauth.BPSProbeProxyURL(ctx)
	if !probe {
		return nil, nil
	}
	if auth == nil || auth.Provider != "bps" || request == nil {
		return nil, errors.New("bps_probe_refresh_invalid_auth")
	}
	if strings.TrimSpace(auth.ProxyURL) != "" {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}
	if !coreauth.ValidBPSProbeProxyURL(proxyURL) {
		return nil, errors.New("bps_probe_proxy_invalid")
	}
	if !ojson.ValidBytes(request.StorageJSON) {
		return nil, errors.New("bps_probe_refresh_invalid_storage")
	}
	originalStorage := ojson.GetBytes(request.StorageJSON, "proxy_url")
	originalMetadata, hadMetadata := auth.Metadata["proxy_url"]
	doc := ojson.NewDoc(request.StorageJSON)
	if err := doc.Set("proxy_url", proxyURL); err != nil {
		return nil, errors.New("bps_probe_refresh_invalid_storage")
	}
	request.StorageJSON = doc.Bytes()
	request.Metadata = cloneAnyMap(request.Metadata)
	if request.Metadata == nil {
		request.Metadata = make(map[string]any)
	}
	request.Metadata["proxy_url"] = proxyURL
	transportAuth := auth.Clone()
	transportAuth.ProxyURL = proxyURL
	request.HTTPClient = h.newHTTPClient(transportAuth)
	return func(data *pluginapi.AuthData) error {
		if !ojson.ValidBytes(data.StorageJSON) {
			return errors.New("bps_probe_refresh_invalid_storage")
		}
		data.ProxyURL = auth.ProxyURL
		data.Metadata = cloneAnyMap(data.Metadata)
		if hadMetadata {
			if data.Metadata == nil {
				data.Metadata = make(map[string]any)
			}
			data.Metadata["proxy_url"] = originalMetadata
		} else {
			delete(data.Metadata, "proxy_url")
		}
		doc := ojson.NewDoc(data.StorageJSON)
		var err error
		if originalStorage.Exists() {
			err = doc.SetRaw("proxy_url", originalStorage.Raw)
		} else {
			err = doc.Delete("proxy_url")
		}
		if err != nil {
			return errors.New("bps_probe_refresh_invalid_storage")
		}
		data.StorageJSON = doc.Bytes()
		return nil
	}, nil
}
