package auth

import (
	"context"
	"testing"
)

func TestShouldAutoRemoveAuth_401(t *testing.T) {
	auth := &Auth{ID: "test-401", Provider: "codex"}
	if !shouldAutoRemoveAuth(auth, 401) {
		t.Error("401 should trigger auto-remove")
	}
}

func TestShouldAutoRemoveAuth_403_Banned(t *testing.T) {
	auth := &Auth{ID: "test-403", Provider: "codex", StatusMessage: "account banned"}
	if !shouldAutoRemoveAuth(auth, 403) {
		t.Error("403 with banned should trigger auto-remove")
	}
}

func TestShouldAutoRemoveAuth_403_Normal(t *testing.T) {
	auth := &Auth{ID: "test-403-normal", Provider: "codex", StatusMessage: "some other error"}
	if shouldAutoRemoveAuth(auth, 403) {
		t.Error("403 without banned/suspended should NOT trigger auto-remove")
	}
}

func TestShouldAutoRemoveAuth_429_Free(t *testing.T) {
	auth := &Auth{
		ID:       "test-429-free",
		Provider: "codex",
		Metadata: map[string]any{"chatgpt_plan_type": "free"},
	}
	if !shouldAutoRemoveAuth(auth, 429) {
		t.Error("429 on free account should trigger auto-remove")
	}
}

func TestShouldAutoRemoveAuth_429_FreeMissingPlan(t *testing.T) {
	// No plan_type = treated as free
	auth := &Auth{
		ID:       "test-429-no-plan",
		Provider: "codex",
		Metadata: map[string]any{"email": "test@example.com"},
	}
	if !shouldAutoRemoveAuth(auth, 429) {
		t.Error("429 on account without plan_type should trigger auto-remove (default=free)")
	}
}

func TestShouldAutoRemoveAuth_429_Plus(t *testing.T) {
	auth := &Auth{
		ID:       "test-429-plus",
		Provider: "codex",
		Metadata: map[string]any{"chatgpt_plan_type": "plus"},
	}
	if shouldAutoRemoveAuth(auth, 429) {
		t.Error("429 on plus account should NOT trigger auto-remove")
	}
}

func TestShouldAutoRemoveAuth_429_Team(t *testing.T) {
	auth := &Auth{
		ID:       "test-429-team",
		Provider: "codex",
		Metadata: map[string]any{"chatgpt_plan_type": "team"},
	}
	if shouldAutoRemoveAuth(auth, 429) {
		t.Error("429 on team account should NOT trigger auto-remove")
	}
}

func TestShouldAutoRemoveAuth_429_PlusNested(t *testing.T) {
	// plan_type nested in JWT auth info
	auth := &Auth{
		ID:       "test-429-plus-nested",
		Provider: "codex",
		Metadata: map[string]any{
			"https://api.openai.com/auth": map[string]any{
				"chatgpt_plan_type": "plus",
			},
		},
	}
	if shouldAutoRemoveAuth(auth, 429) {
		t.Error("429 on plus account (nested JWT) should NOT trigger auto-remove")
	}
}

func TestShouldAutoRemoveAuth_500(t *testing.T) {
	auth := &Auth{ID: "test-500", Provider: "codex"}
	if shouldAutoRemoveAuth(auth, 500) {
		t.Error("500 should NOT trigger auto-remove (transient)")
	}
}

func TestShouldAutoRemoveAuth_502(t *testing.T) {
	auth := &Auth{ID: "test-502", Provider: "codex"}
	if shouldAutoRemoveAuth(auth, 502) {
		t.Error("502 should NOT trigger auto-remove (transient)")
	}
}

func TestIsFreeAccount(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]any
		wantFree bool
	}{
		{"nil metadata", nil, true},
		{"empty metadata", map[string]any{}, true},
		{"free", map[string]any{"chatgpt_plan_type": "free"}, true},
		{"empty plan", map[string]any{"chatgpt_plan_type": ""}, true},
		{"plus", map[string]any{"chatgpt_plan_type": "plus"}, false},
		{"team", map[string]any{"chatgpt_plan_type": "team"}, false},
		{"enterprise", map[string]any{"chatgpt_plan_type": "enterprise"}, false},
		{"Plus uppercase", map[string]any{"chatgpt_plan_type": "Plus"}, false},
		{"resolved_plan_type plus", map[string]any{"resolved_plan_type": "plus"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &Auth{Metadata: tt.metadata}
			got := isFreeAccount(auth)
			if got != tt.wantFree {
				t.Errorf("isFreeAccount() = %v, want %v", got, tt.wantFree)
			}
		})
	}
}

func TestAutoRemoveAuth(t *testing.T) {
	ctx := context.Background()
	store := &mockStore{auths: map[string]*Auth{}}

	m := &Manager{
		store: store,
		auths: map[string]*Auth{},
	}

	auth := &Auth{
		ID:       "test-remove",
		Provider: "codex",
		FileName: "test@example.com.json",
		Status:   StatusActive,
		Metadata: map[string]any{"email": "test@example.com"},
	}
	m.auths[auth.ID] = auth
	store.auths[auth.ID] = auth

	m.autoRemoveAuth(ctx, auth, "test removal")

	// Should be removed from in-memory map
	if _, exists := m.auths[auth.ID]; exists {
		t.Error("auth should be removed from in-memory map")
	}

	// Should be deleted from store
	if !store.deleted[auth.ID] {
		t.Error("auth should be deleted from store")
	}
}

// mockStore implements Store for testing
type mockStore struct {
	auths   map[string]*Auth
	deleted map[string]bool
}

func (s *mockStore) List(_ context.Context) ([]*Auth, error) {
	result := make([]*Auth, 0, len(s.auths))
	for _, a := range s.auths {
		result = append(result, a)
	}
	return result, nil
}

func (s *mockStore) Save(_ context.Context, auth *Auth) (string, error) {
	s.auths[auth.ID] = auth
	return auth.ID, nil
}

func (s *mockStore) Delete(_ context.Context, id string) error {
	if s.deleted == nil {
		s.deleted = map[string]bool{}
	}
	s.deleted[id] = true
	delete(s.auths, id)
	return nil
}
