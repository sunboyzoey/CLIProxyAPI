package auth

import (
	"context"
	"errors"
	"strings"
)

type requireAuthPersistKey struct{}

// ModifyPersisted applies an atomic edit to the latest credential only when its
// backing store also accepts the change. Unlike ordinary Modify, persistence
// errors are fatal and the failed edit is not published to runtime readers.
func (m *Manager) ModifyPersisted(ctx context.Context, id string, expectedEpoch uint64, edit func(*Auth) error) (*Auth, bool, error) {
	if m == nil {
		return nil, false, errors.New("auth persistence unavailable")
	}
	m.mu.RLock()
	hasStore := m.store != nil
	m.mu.RUnlock()
	if !hasStore {
		return nil, false, errors.New("auth persistence unavailable")
	}
	ctx = context.WithValue(WithoutSkipPersist(ctx), requireAuthPersistKey{}, true)
	if edit == nil {
		return nil, false, errors.New("auth edit required")
	}
	return m.Modify(ctx, id, expectedEpoch, func(current *Auth) error {
		if errEdit := edit(current); errEdit != nil {
			return errEdit
		}
		if current.Metadata == nil || IsConfigAPIKeyAuth(current) || IsPluginVirtualAuth(current) || strings.EqualFold(strings.TrimSpace(current.Attributes["runtime_only"]), "true") {
			return errors.New("auth does not support durable modification")
		}
		return nil
	})
}

func requireAuthPersist(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	required, _ := ctx.Value(requireAuthPersistKey{}).(bool)
	return required
}
