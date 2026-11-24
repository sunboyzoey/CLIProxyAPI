package handlers

import (
	"strings"

	"github.com/MoeForge/moego/ojson"
	claudemodels "github.com/router-for-me/CLIProxyAPI/v8/internal/client/claude/models"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

func (h *BaseAPIHandler) filterOAuthGroupModels(body []byte, group, format string, hidePrefixes bool) []byte {
	var clients map[string]bool
	if group != "" {
		clients = h.AuthManager.OAuthGroupClientIDs(group)
	}
	routes := registry.GetGlobalRegistry().DirectoryModelRoutes(clients)
	decodeClaude := format == constant.Claude && h.AuthManager.OAuthModelDirectoryEnabled()
	doc := ojson.NewDoc(body)
	for _, field := range []string{"data", "models"} {
		items := doc.Get(field)
		if !items.IsArray() {
			continue
		}
		list := ojson.NewDocString("[]")
		first, last := "", ""
		removed := false
		for _, item := range items.Array() {
			id := item.Get("id").String()
			if id == "" {
				id = item.Get("slug").String()
			}
			if id == "" {
				id = strings.TrimPrefix(item.Get("name").String(), "models/")
			}
			if _, ok := routes[id]; !ok && decodeClaude {
				id = claudemodels.ResolveClaudeModelIDPrefix(id)
			}
			route := routes[id]
			if (group != "" && !route.Allowed) || (hidePrefixes && route.Allowed && !route.Listed) {
				removed = true
				continue
			}
			_ = list.SetRawBytes("-1", []byte(item.Raw))
			last = item.Get("id").String()
			if first == "" {
				first = last
			}
		}
		if removed {
			_ = doc.SetRawBytes(field, list.Bytes())
			if field == "data" && doc.Get("first_id").Exists() && doc.Get("last_id").Exists() {
				_ = doc.Set("first_id", first)
				_ = doc.Set("last_id", last)
			}
		}
	}
	return doc.Bytes()
}
