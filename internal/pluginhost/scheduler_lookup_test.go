package pluginhost

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestRPCSchedulerLookupScopeAndOptIn(t *testing.T) {
	var got pluginapi.SchedulerPickRequest
	p := validTestPlugin("lookup-scheduler")
	p.Capabilities.SchedulerLookupCandidates = true
	p.Capabilities.Scheduler = schedulerFunc(func(_ context.Context, req pluginapi.SchedulerPickRequest) (pluginapi.SchedulerPickResponse, error) {
		got = req
		return pluginapi.SchedulerPickResponse{Handled: true, AuthID: "cooling"}, nil
	})
	lookup := newTestSymbolLookup(&testPlugin{registerResult: p})
	registered, err := registerRPCPlugin(context.Background(), nil, "lookup", lookup, pluginabi.MethodPluginRegister, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newHostWithRecords(capabilityRecord{id: "lookup", plugin: registered})
	if !registered.Capabilities.SchedulerLookupCandidates || !h.SchedulerWantsLookupCandidates() {
		t.Fatal("lost lookup opt-in")
	}
	r := pluginapi.SchedulerPickRequest{LookupCandidatesProvided: true,
		Candidates:       []pluginapi.SchedulerAuthCandidate{{ID: "available"}},
		LookupCandidates: []pluginapi.SchedulerAuthCandidate{{ID: "cooling", UnavailableReason: "cooldown", RetryAfterSeconds: 7, Metadata: map[string]any{"keep": "value", "callback": func() {}}}},
	}
	_, handled, err := h.PickAuth(context.Background(), r)
	if err != nil || handled {
		t.Fatalf("selected lookup-only auth: handled=%v err=%v", handled, err)
	}
	if !got.LookupCandidatesProvided || len(got.LookupCandidates) != 1 || got.LookupCandidates[0].RetryAfterSeconds != 7 || got.LookupCandidates[0].UnavailableReason != "cooldown" {
		t.Fatalf("lost wire lookup scope: %+v", got)
	}
	if got.LookupCandidates[0].Metadata["keep"] != "value" || got.LookupCandidates[0].Metadata["callback"] != nil {
		t.Fatal("lookup metadata was not sanitized")
	}
}
