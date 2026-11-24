package executor

import (
	"bytes"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// The peer supplies a synthetic opaque item. This checks lossless forwarding
// and client-managed history replacement, not upstream summarization quality.
func TestCodexHTTPWebsocketPoolCompactionToolRoundTrip(t *testing.T) {
	history := "EARLY-CONSTRAINT" + strings.Repeat(" original history;", 18000) + "LATE-CONSTRAINT"
	toolResult := "lookup-result:" + strings.Repeat("verified;", 16000)
	capsule := map[string]any{"id": "cmp_native", "type": "compaction", "encrypted_content": "gAAAAABsynthetic-native-compaction-state"}
	var turns atomic.Int32
	server := newPoolMockServer(t, func(conn *websocket.Conn, id, turn int, body []byte) bool {
		n := turns.Add(1)
		input := ojson.GetBytes(body, "input").Array()
		if n <= 2 && !bytes.Contains(body, []byte(history)) {
			t.Error("long history was truncated before explicit compaction")
		}
		if ojson.GetBytes(body, "previous_response_id").Exists() {
			t.Error("pool injected a continuation ID")
		}
		if ojson.GetBytes(body, "instructions").String() != "Keep the early constraints." {
			t.Error("instructions changed during compaction roundtrip")
		}
		if n == 2 {
			found := false
			for _, item := range input {
				if item.Get("type").String() == "function_call_output" && item.Get("call_id").String() == "call_before" && item.Get("output").String() == toolResult {
					found = true
				}
			}
			if !found || len(input) == 0 || input[len(input)-1].Get("type").String() != "compaction_trigger" {
				t.Error("compaction trigger or tool result was lost")
			}
		}
		if n >= 3 {
			found := false
			for _, item := range input {
				if item.Get("type").String() == "compaction" && item.Get("encrypted_content").String() == capsule["encrypted_content"] {
					found = true
				}
			}
			if !found || bytes.Contains(body, []byte("EARLY-CONSTRAINT")) || bytes.Contains(body, []byte("call_before")) {
				t.Error("native compaction corrupted or old history resurrected")
			}
		}
		if n == 4 {
			found := false
			for _, item := range input {
				if item.Get("type").String() == "function_call_output" && item.Get("call_id").String() == "call_after" && item.Get("output").String() == "result-after-compaction" {
					found = true
				}
			}
			if !found {
				t.Error("post-compaction tool result was lost")
			}
		}
		var output []any
		switch n {
		case 1, 3:
			callID := "call_before"
			if n == 3 {
				callID = "call_after"
			}
			args := ojson.NewDocString("{}")
			args.Set("key", "known")
			output = []any{map[string]any{"id": "fc_" + callID, "type": "function_call", "name": "lookup", "call_id": callID, "arguments": args.String(), "status": "completed"}}
		case 2:
			output = []any{capsule}
		default:
			output = []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": "OK"}}}}
		}
		done := ojson.NewDocString("{}")
		done.Set("type", "response.output_item.done")
		done.Set("output_index", 0)
		done.Set("item", output[0])
		if errWrite := conn.WriteMessage(websocket.TextMessage, done.Bytes()); errWrite != nil {
			return false
		}
		completed := ojson.NewDocString("{}")
		completed.Set("type", "response.completed")
		completed.Set("response.id", fmt.Sprintf("resp_compact_%d", n))
		completed.Set("response.status", "completed")
		completed.Set("response.output", output)
		return conn.WriteMessage(websocket.TextMessage, completed.Bytes()) == nil
	})
	exec := poolTestExecutor(t, &config.Config{})
	req, opts := httpWSRequest()
	a := httpWSAuth(server.url)
	input := []any{map[string]any{"type": "message", "role": "user", "content": history}}
	for n := 1; n <= 4; n++ {
		doc := ojson.NewDocString("{}")
		doc.Set("model", req.Model)
		doc.Set("stream", true)
		doc.Set("instructions", "Keep the early constraints.")
		doc.Set("input", input)
		doc.Set("tools", []any{map[string]any{"type": "function", "name": "lookup", "parameters": map[string]any{"type": "object", "properties": map[string]any{"key": map[string]any{"type": "string"}}}}})
		req.Payload = doc.Bytes()
		stream, err := exec.ExecuteStream(t.Context(), a, req, opts)
		if err != nil {
			t.Fatal(err)
		}
		var output []ojson.Result
		for chunk := range stream.Chunks {
			if chunk.Err != nil {
				t.Fatal(chunk.Err)
			}
			// Executor chunks carry events; the HTTP handler adds SSE separators.
			for _, line := range strings.Split(string(chunk.Payload), "\n") {
				if !strings.HasPrefix(line, "data: ") {
					continue
				}
				event := ojson.Parse(strings.TrimPrefix(line, "data: "))
				if event.Get("type").String() == "response.completed" {
					output = event.Get("response.output").Array()
				}
			}
		}
		if len(output) != 1 {
			t.Fatalf("turn %d did not complete with one output item", n)
		}
		switch n {
		case 1, 3:
			if output[0].Get("type").String() != "function_call" || output[0].Get("name").String() != "lookup" {
				t.Fatal("tool call changed")
			}
			result := toolResult
			if n == 3 {
				result = "result-after-compaction"
			}
			input = append(input, output[0].Value(), map[string]any{"type": "function_call_output", "call_id": output[0].Get("call_id").String(), "output": result})
			if n == 1 {
				input = append(input, map[string]any{"type": "compaction_trigger"})
			}
		case 2:
			if output[0].Get("encrypted_content").String() != capsule["encrypted_content"] {
				t.Fatal("opaque capsule changed")
			}
			input = []any{output[0].Value(), map[string]any{"type": "message", "role": "user", "content": "Continue and call lookup again."}}
		}
	}
	if server.upgrades.Load() != 1 || server.posts.Load() != 0 || turns.Load() != 4 {
		t.Fatalf("upgrades=%d posts=%d turns=%d", server.upgrades.Load(), server.posts.Load(), turns.Load())
	}
}
