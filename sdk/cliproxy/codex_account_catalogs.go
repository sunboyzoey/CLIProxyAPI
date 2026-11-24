package cliproxy

import (
	"context"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func usesCodexAccountCatalog(cfg *config.Config) bool {
	return cfg != nil && !cfg.Home.Enabled && coreauth.OAuthModelDirectoryEnabledForConfig(cfg)
}

func codexAccountCatalogModels(ids []string) []*ModelInfo {
	models := make([]*ModelInfo, 0, len(ids))
	for _, id := range ids {
		info := registry.LookupStaticModelInfoByChannel(id, "codex")
		if info == nil {
			info = &ModelInfo{ID: id, Object: "model", OwnedBy: "openai", Type: "openai", DisplayName: id}
		}
		models = append(models, info)
	}
	return models
}

func (s *Service) wakeCodexAccountCatalogs() {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	select {
	case s.codexCatalogWake <- struct{}{}:
	default:
	}
}

type codexCatalogJob struct {
	id      string
	checked time.Time
	known   bool
}

func (s *Service) runCodexAccountCatalogs(ctx context.Context, wake <-chan struct{}) {
	if s.coreManager == nil {
		return
	}
	// Only the coordinator touches the queue. Slow accounts occupy at most one
	// worker each and do not delay the next refresh of other accounts.
	jobs := make(chan codexCatalogJob)
	done := make(chan codexCatalogJob)
	var workers sync.WaitGroup
	for range 3 {
		workers.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case job := <-jobs:
					job.checked = s.refreshCodexAccountCatalog(ctx, job)
					select {
					case done <- job:
					case <-ctx.Done():
						return
					}
				}
			}
		})
	}
	defer workers.Wait()

	// Management force-refreshes also populate the discovery cache.
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	applied := make(map[string]time.Time)
	queued := make(map[string]bool)
	var pending []codexCatalogJob
	enqueue := func() {
		if !usesCodexAccountCatalog(s.currentConfig()) {
			clear(applied)
			return
		}
		present := make(map[string]bool)
		for _, id := range s.coreManager.IDsByProvider("codex") {
			present[id] = true
			if !queued[id] {
				checked, known := applied[id]
				pending = append(pending, codexCatalogJob{id, checked, known})
				queued[id] = true
			}
		}
		for id := range applied {
			if !present[id] {
				delete(applied, id)
			}
		}
	}

	enqueue()
	for ctx.Err() == nil {
		var send chan<- codexCatalogJob
		var next codexCatalogJob
		if len(pending) > 0 {
			send, next = jobs, pending[0]
		}
		select {
		case <-ctx.Done():
			return
		case send <- next:
			pending = pending[1:]
		case job := <-done:
			delete(queued, job.id)
			applied[job.id] = job.checked
		case <-wake:
			enqueue()
		case <-ticker.C:
			enqueue()
		}
	}
}

func (s *Service) refreshCodexAccountCatalog(ctx context.Context, job codexCatalogJob) time.Time {
	cfg := s.currentConfig()
	if !usesCodexAccountCatalog(cfg) || ctx.Err() != nil {
		return time.Time{}
	}
	a, _ := s.coreManager.GetByID(job.id)
	if a == nil || a.Disabled || a.Status == coreauth.StatusDisabled || a.OAuthAccountGroup() == "" {
		return time.Time{}
	}
	tiers, ok := helps.CachedCodexAccountTiersForConfig(cfg, a)
	if !ok {
		// Drop an expired or replaced grant before network I/O.
		if !job.known || !job.checked.IsZero() {
			s.completeModelRegistrationForAuth(ctx, a)
		}
		prepared, err := s.coreManager.NativeProbeAuth(ctx, a.ID, a.RegistrationEpoch)
		if err != nil || prepared == nil || prepared.Disabled || prepared.Status == coreauth.StatusDisabled || prepared.OAuthAccountGroup() == "" {
			return time.Time{}
		}
		tiers, err = helps.DiscoverCodexAccountTiers(ctx, cfg, prepared, false)
		if err != nil {
			return time.Time{}
		}
	}
	if !job.known || !job.checked.Equal(tiers.CheckedAt) {
		// Completion reads the latest manager/config snapshot and checks the
		// current credential's cache again under the publication fence.
		s.completeModelRegistrationForAuth(ctx, a)
	}
	return tiers.CheckedAt
}
