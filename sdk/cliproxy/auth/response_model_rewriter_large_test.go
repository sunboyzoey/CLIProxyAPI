package auth

import (
	"bytes"
	"testing"

	"github.com/MoeForge/moego/ojson"
)

func TestStreamRewriter_OversizedCompletePayload(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix string
		suffix string
		header string
	}{
		{name: "raw_json"},
		{name: "responses_sse", prefix: "event: response.completed\ndata: ", suffix: "\n\n"},
		{name: "data_without_space", prefix: "data:", suffix: "\n\n"},
		{name: "data_without_newline", prefix: "data: "},
		{name: "buffered_event_header", header: "event: response.completed\n", prefix: "data: ", suffix: "\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := ojson.NewDocString(`{"type":"response.completed","response":{"model":"gpt-6.1-sol","status":"completed","usage":{"input_tokens":290021,"output_tokens":719}}}`)
			if err := doc.Set("response.output", string(bytes.Repeat([]byte("literal gpt-6.1-sol "), maxPendingBufSize/19+1))); err != nil {
				t.Fatal(err)
			}
			raw := doc.Bytes()
			payload := append([]byte(tc.prefix), raw...)
			payload = append(payload, tc.suffix...)
			if len(payload) <= maxPendingBufSize {
				t.Fatal("fixture must exceed the pending buffer limit")
			}
			r := NewStreamRewriter(StreamRewriteOptions{RewriteModel: "gpt-6.2-sol"})
			if tc.header != "" && len(rewriteForceMappedStreamChunk(r, []byte(tc.header))) != 0 {
				t.Fatal("event header should remain buffered")
			}
			got := rewriteForceMappedStreamChunk(r, payload)
			got = append(got, finishForceMappedStreamChunks(r)...)
			if err := doc.Set("response.model", "gpt-6.2-sol"); err != nil {
				t.Fatal(err)
			}
			want := append([]byte(tc.header+tc.prefix), doc.Bytes()...)
			want = append(want, tc.suffix...)
			if !bytes.Equal(got, want) {
				t.Fatalf("oversized response must rewrite only the model field; got %d bytes, want %d", len(got), len(want))
			}
			if len(r.pendingBuf) != 0 {
				t.Fatalf("complete payload left %d buffered bytes", len(r.pendingBuf))
			}
		})
	}
}

func TestStreamRewriter_OversizedBatch(t *testing.T) {
	frame := []byte("data: {\"model\":\"gpt-6.1-sol\",\"choices\":[]}\n\n")
	wantFrame := []byte("data: {\"model\":\"gpt-6.2-sol\",\"choices\":[]}\n\n")
	n := maxPendingBufSize/len(frame) + 1
	payload := append(bytes.Repeat(frame, n), []byte("data: [DONE]\n\n")...)
	want := append(bytes.Repeat(wantFrame, n), []byte("data: [DONE]\n\n")...)
	r := NewStreamRewriter(StreamRewriteOptions{RewriteModel: "gpt-6.2-sol"})
	got := rewriteForceMappedStreamChunk(r, payload)
	got = append(got, finishForceMappedStreamChunks(r)...)
	if !bytes.Equal(got, want) {
		t.Fatal("every event in an oversized batch must be rewritten without changing framing")
	}
}

func TestStreamRewriter_OversizedIncompletePayloadRemainsBounded(t *testing.T) {
	payload := append([]byte(`data: {"response":{"output":"`), bytes.Repeat([]byte("x"), maxPendingBufSize)...)
	r := NewStreamRewriter(StreamRewriteOptions{RewriteModel: "gpt-6.2-sol"})
	if got := r.RewriteChunk(payload); !bytes.Equal(got, payload) {
		t.Fatal("oversized incomplete data must retain existing passthrough behavior")
	}
	if len(r.pendingBuf) != 0 {
		t.Fatalf("oversized incomplete payload retained %d bytes", len(r.pendingBuf))
	}
}

func TestStreamRewriter_OversizedPayloadWithoutMapping(t *testing.T) {
	payload := bytes.Repeat([]byte(`data: {"model":"gpt-6.1-sol"}`), maxPendingBufSize/30+1)
	r := NewStreamRewriter(StreamRewriteOptions{})
	if !bytes.Equal(r.RewriteChunk(payload), payload) {
		t.Fatal("disabled mapping must preserve oversized payloads")
	}
}
