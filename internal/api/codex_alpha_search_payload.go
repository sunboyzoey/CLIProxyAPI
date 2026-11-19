package api

import (
	"net/http"
	"strings"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
)

func sanitizeCodexAlphaSearchDoc(doc *ojson.Doc) {
	for _, field := range []string{"prompt_cache_key", "prompt_cache_retention", "store"} {
		_ = doc.Delete(field)
	}
}

func rewriteCodexAlphaSearchModelDoc(doc *ojson.Doc, upstreamModel string) {
	if model := strings.TrimSpace(upstreamModel); model != "" && doc.Get("model").Exists() {
		_ = doc.Set("model", model)
	}
}

// prepareCodexAlphaSearchBody is shared by OAuth, API-key and Home dispatch.
// Search is an independent protocol: Responses-only payload rules must not
// inject generation parameters into it. Unscoped rules still apply by design.
func prepareCodexAlphaSearchBody(cfg *config.Config, body []byte, upstreamModel, requestedModel, requestPath string, headers http.Header) []byte {
	if !ojson.ValidBytes(body) || !ojson.ParseBytes(body).IsObject() {
		return body
	}
	doc := ojson.NewDoc(body)
	sanitizeCodexAlphaSearchDoc(doc)
	rewriteCodexAlphaSearchModelDoc(doc, upstreamModel)
	// User configuration is the final semantic barrier. Serialize exactly once;
	// do not restore removed fields or overwrite configured models afterwards.
	helps.ApplyPayloadConfigWithRequestForExecutorDoc(cfg, "codex", upstreamModel, codexAlphaSearchSourceFormat, codexAlphaSearchSourceFormat, "", doc, body, requestedModel, requestPath, headers)
	return doc.Bytes()
}

// These small wrappers retain existing package-level compatibility tests.
func sanitizeCodexAlphaSearchBody(body []byte) []byte {
	if !ojson.ValidBytes(body) || !ojson.ParseBytes(body).IsObject() {
		return body
	}
	doc := ojson.NewDoc(body)
	sanitizeCodexAlphaSearchDoc(doc)
	return doc.Bytes()
}

func rewriteCodexAlphaSearchModel(body []byte, upstreamModel string) []byte {
	if !ojson.ValidBytes(body) || !ojson.ParseBytes(body).IsObject() {
		return body
	}
	doc := ojson.NewDoc(body)
	rewriteCodexAlphaSearchModelDoc(doc, upstreamModel)
	return doc.Bytes()
}
