package pluginhost

import (
	"context"
	"testing"

	coreusage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestNativeUsageAdapterPreservesIdentityPresenceAndOutcome(t *testing.T) {
	var received pluginapi.UsageRecord
	plugin := usagePluginFunc(func(_ context.Context, record pluginapi.UsageRecord) { received = record })
	host := newHostWithRecords(capabilityRecord{id: "native-usage", plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{UsagePlugin: plugin}}})
	adapter := &usageAdapter{host: host, pluginID: "native-usage"}
	zero := int64(0)
	record := coreusage.Record{Provider: "codex", AuthType: "oauth", AuthID: "native.json", AuthIdentity: "synthetic-stable-identity", RequestID: "execution-id", Supplemental: true, ResponseStatus: "incomplete", Failed: true, Fail: coreusage.Failure{Code: "context_canceled"}, Detail: coreusage.Detail{Observed: &coreusage.ObservedTokens{OutputTokens: &zero}}}
	adapter.HandleUsage(context.Background(), record)
	if received.AuthIdentity != record.AuthIdentity || received.ResponseStatus != "incomplete" || received.Failure.Code != "context_canceled" || received.RequestID != record.RequestID || !received.Supplemental {
		t.Fatal("identity or outcome lost at plugin boundary")
	}
	if received.Detail.Observed == nil || received.Detail.Observed.InputTokens != nil || received.Detail.Observed.OutputTokens == nil || *received.Detail.Observed.OutputTokens != 0 {
		t.Fatal("missing versus zero lost at plugin boundary")
	}
	zero = 9
	if *received.Detail.Observed.OutputTokens != 0 {
		t.Fatal("plugin counters alias mutable host data")
	}
	adapter.HandleUsage(context.Background(), coreusage.Record{})
	if received.Detail.Observed != nil || received.AuthIdentity != "" || received.ResponseStatus != "" || received.Failure.Code != "" {
		t.Fatal("legacy record gained fabricated measurement")
	}
}
