package config

import (
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

func TestCodexHTTPWebsocketPoolV8Config(t *testing.T) {
	for _, source := range []string{
		"upstream:\n  codex:\n    http-websocket-pool-max-per-account: 3\n",
		"codex:\n  http-websocket-pool-max-per-account: 3\n",
		"oauth:\n  providers:\n    codex:\n      http-websocket-pool-max-per-account: 3\n",
	} {
		cfg, err := ParseConfigBytes([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Codex.HTTPWebsocketPoolMaxPerAccount != 3 {
			t.Fatalf("setting lost: %s", source)
		}
		serialized, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(serialized), "http-websocket-pool-max-per-account: 3") {
			t.Fatal("setting omitted from serialization")
		}
		again, err := ParseConfigBytes(serialized)
		if err != nil || again.Codex.HTTPWebsocketPoolMaxPerAccount != 3 {
			t.Fatalf("roundtrip: %v", err)
		}
	}
}
