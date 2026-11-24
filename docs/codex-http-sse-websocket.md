# Codex OAuth HTTP SSE over upstream WebSocket

A client can continue using HTTP `POST /v1/responses` with `stream: true` while
CPA sends the request to the native Codex OAuth upstream using WebSocket. The
client receives incremental Responses SSE events and needs no transport change.
This is a transport option, not a guarantee of lower latency.

## Account configuration

Add this top-level boolean to only the native Codex OAuth account files that
should use this transport:

```json
{
  "type": "codex",
  "http_sse_websockets": true
}
```

Merge the field into the existing credential file; do not replace its tokens.
The default is false. The existing `websockets` flag controls client WebSocket
requests independently and is not required for this HTTP streaming option.
The credential watcher loads the metadata; the server must run a binary with
this feature. Disable by setting the boolean to false or removing it.

## Scope and connection lifetime

- Native OAuth accounts only; API keys, SIWC and BPS executors are excluded.
- Responses-format streaming requests only. Chat/Claude protocol bridges,
  nonstreaming requests, compact requests and nonempty `previous_response_id`
  requests keep their existing transport.
- Each eligible request owns an isolated upstream WebSocket. It closes on
  completion, failure or client cancellation; there is no connection pool or
  cross-request WS continuation in this initial implementation.
- Tool follow-ups must send full input history, including call IDs and tool
  outputs. Incremental continuations remain on the existing HTTP path.
- If a payload rule inserts a nonempty `previous_response_id`, the isolated
  bridge rejects it before sending rather than overriding that configured value.

## Error and replay policy

Before sending `response.create`, a failed handshake with no HTTP response or
status 400/404/405/426/502/503/504 can fall back to HTTP once. Cancellation and
401/403/429 do not trigger HTTP fallback. Fallback is disabled when an execution
lifecycle owns the attempt. Each transport prepares its payload from the
original request and evaluates payload rules once for that attempt.

Once the WS write is attempted, the request must not be replayed: a failed write
may still have reached the upstream and executed a tool. Send errors, missing
first events, quota/auth errors received over WS and disconnects stop retries
across credentials, model pools, credential refresh and handler bootstrap. User
continue rules cannot override this protection. Status codes and retry hints
remain available to existing accounting/cooldown handling.

A close before a terminal event, including close code 1000, produces a 502
`upstream_stream_incomplete` error. Existing HTTP Responses error framing is
retained: before output this is an HTTP error, after output it is a terminal SSE
error (Codex clients receive `response.failed`). Cancellation closes the owned
connection. No post-connection request timeout is added.

## Events and payloads

The bridge reuses CPA's existing Codex WS preparation, payload finalizer, tool
normalization, usage reporter and Responses translator. Payload rules remain
the last semantic request mutation; only WS framing and read-only validation
follow. It bypasses WS bootstrap buffering so metadata/tool events can arrive
before completion. Function/custom tool events, call IDs, argument deltas,
reasoning, image events and extension events follow the existing Responses
translation behavior. Completion normalization and usage detail enrichment
remain unchanged. The bridge cannot add tool capabilities absent upstream.

## Reference and verification

The HTTP SSE acceleration behavior was reviewed in ranxi2001/sub2api at
`1dcd7628743701918f331b26c85aaceb16201b10`, especially its separate opt-in,
pre-send fallback and no-replay-after-send rules. Wei-Shaw/sub2api at
`2af3f1e15c98c893a89255a037f551046883b8c0` keeps HTTP ingress on HTTP upstream.
CPA's implementation reuses its own executor; it does not copy the fork's pool,
WS-mode router or tool execution implementation.

Offline tests use local synthetic upstreams. They cover incremental delivery,
function/custom calls and tool results, image/reasoning/extension events, payload
rule ordering, handshake fallback, auth/quota failures, incomplete streams,
cancellation, and retry suppression through model selection and HTTP handlers.
They do not establish real-account performance or upstream tool availability.

## Optional after-auth transport policy

A compatible plugin may return `upstream_transport: "http"` or `"websocket"`
from after-auth interception. The host advertises
`codex_http_websocket_policy_version: 1` during registration and reconfiguration.
The selected provider and account ID are supplied as `Provider` and `AuthID`;
plugins do not need account credentials or request bodies to choose a policy.

The hint is propagated as typed executor options, never in business JSON or a
forwarded header. A valid hint overrides the legacy account opt-in. An empty or
invalid result abstains and must not inherit another attempt's selection.
Before-auth hints are ignored. Native eligibility, final payload rules and sent
request protection remain mandatory regardless of plugin decisions.

The separate `codex-ws-plugin/` directory in GPT-BPS contains the policy plugin,
its configuration example, and a version-checked host patch. Set
`CPA_CODEX_WS_POLICY_PLUGIN` to its built library and run
`go test -run TestCodexWSPolicyPluginHTTPIntegration ./test` for the real ABI / HTTP
handler / native upstream transport integration test with local synthetic data.
