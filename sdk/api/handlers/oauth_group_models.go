package handlers

import (
	"strings"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

func (h *BaseAPIHandler) filterOAuthGroupModels(body []byte, group string) []byte {
	allowed := make(map[string]bool)
	if h.AuthManager != nil {
		for _, a := range h.AuthManager.List() {
			if a.Disabled || !a.InOAuthGroup(group) {
				continue
			}
			for _, m := range registry.GetGlobalRegistry().GetModelsForClient(a.ID) {
				if m != nil {
					allowed[m.ID] = true
				}
			}
		}
	}
	doc := ojson.NewDoc(body)
	for _, field := range []string{"data", "models"} {
		if items := doc.Get(field); items.IsArray() {
			list := ojson.NewDocString("[]")
			for _, item := range items.Array() {
				id := item.Get("id").String()
				if id == "" {
					id = item.Get("slug").String()
				}
				if id == "" {
					id = strings.TrimPrefix(item.Get("name").String(), "models/")
				}
				if allowed[id] {
					_ = list.SetRawBytes("-1", []byte(item.Raw))
				}
			}
			_ = doc.SetRawBytes(field, list.Bytes())
		}
	}
	return doc.Bytes()
}
