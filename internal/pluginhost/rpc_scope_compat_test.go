package pluginhost

import (
	"errors"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

func TestRPCScopeCompatibilityAcrossHostVersions(t *testing.T) {
	tests := []struct {
		name                string
		detail              pluginabi.Error
		credential, request bool
	}{
		{"legacy request", pluginabi.Error{RequestScope: true}, false, true},
		{"upstream request", pluginabi.Error{Code: pluginabi.ErrorCodeRequestScoped}, false, true},
		{"legacy quota overrides upstream request", pluginabi.Error{CredentialScope: true, Code: pluginabi.ErrorCodeRequestScoped}, true, false},
		{"upstream quota overrides legacy request", pluginabi.Error{CredentialScoped: true, RequestScope: true}, true, false},
		{"quota code overrides legacy request", pluginabi.Error{Code: pluginabi.ErrorCodeCredentialQuota, RequestScope: true}, true, false},
		{"unclassified generation error", pluginabi.Error{Code: "bps_generation_error"}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.detail.Message = "scope compatibility"
			tt.detail.HTTPStatus = 429
			_, syncErr := decodeEnvelopeResult[rpcEmptyResponse](pluginabi.Envelope{Error: &tt.detail})
			for _, err := range []error{&tt.detail, syncErr, rpcStreamError("", &tt.detail)} {
				var scoped interface {
					IsCredentialScoped() bool
					IsRequestScoped() bool
				}
				if !errors.As(err, &scoped) {
					t.Fatalf("scope contract missing: %T", err)
				}
				if scoped.IsCredentialScoped() != tt.credential || scoped.IsRequestScoped() != tt.request {
					t.Fatalf("%T: credential=%v request=%v", err, scoped.IsCredentialScoped(), scoped.IsRequestScoped())
				}
			}
		})
	}
}
