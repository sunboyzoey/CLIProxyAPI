package openai

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
)

func TestBPSWebsocketErrorKeepsStatusAndRetryWithoutInternalDetails(t *testing.T) {
	original := errors.New("bps_account_quota_exhausted")
	msg := &interfaces.ErrorMessage{StatusCode: 429, Error: original, Addon: http.Header{"Retry-After": {"12"}, "X-Bps-Upstream-Protocol": {"private"}}}
	body, err := buildResponsesWebsocketErrorPayload(msg)
	if err != nil {
		t.Fatal(err)
	}
	if ojson.GetBytes(body, "status").Int() != 429 || ojson.GetBytes(body, "error.code").String() != "rate_limit_exceeded" {
		t.Fatalf("wrong error: %s", body)
	}
	if !strings.Contains(string(body), "12") || strings.Contains(strings.ToLower(string(body)), "bps") || strings.Contains(string(body), "private") {
		t.Fatalf("unexpected payload: %s", body)
	}
	if msg.Error != original || original.Error() != "bps_account_quota_exhausted" || len(msg.Addon) != 2 {
		t.Fatal("internal error or headers were changed")
	}
}
