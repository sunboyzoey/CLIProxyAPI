package thinking_test

import (
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/thinking/provider/codex"
)

func TestHighEffortFallbackRequestAndSuffix(t *testing.T) {
	for _, effort := range []string{"xhigh", "max"} {
		for _, supported := range []bool{false, true} {
			for _, suffix := range []bool{false, true} {
				levels := []string{"low", "medium", "high"}
				want := "high"
				if supported {
					levels = append(levels, effort)
					want = effort
				}
				info := &registry.ModelInfo{ID: "bps-test", Type: "responses", Thinking: &registry.ThinkingSupport{Levels: levels}}
				model := "bps-test"
				body := []byte(`{"reasoning":{"effort":"` + effort + `"}}`)
				if suffix {
					model += "(" + effort + ")"
					body = []byte(`{"reasoning":{"effort":"low"}}`)
				}
				out, err := thinking.ApplyThinkingWithModelInfo(body, body, model, "codex", "codex", "bps", info)
				if err != nil {
					t.Fatalf("effort=%s supported=%v suffix=%v: %v", effort, supported, suffix, err)
				}
				if got := ojson.GetBytes(out, "reasoning.effort").String(); got != want {
					t.Fatalf("effort=%s supported=%v suffix=%v: got %q want %q", effort, supported, suffix, got, want)
				}
			}
		}
	}
	info := &registry.ModelInfo{ID: "strict", Thinking: &registry.ThinkingSupport{Levels: []string{"low", "medium", "high"}}}
	if _, err := thinking.ValidateConfig(thinking.ThinkingConfig{Mode: thinking.ModeLevel, Level: "invalid"}, info, "codex", "codex", false); err == nil {
		t.Fatal("unknown level must remain invalid")
	}
}
