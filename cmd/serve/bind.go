package main

import (
	"context"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const nvidiaProvider = "nvidia"

// bindNvidiaRuntime re-asserts our custom executor, model catalog, and scheduler
// entries. CLIProxyAPI's watcher path replaces unknown providers with
// OpenAICompatExecutor and UnregisterClient's models we registered — this heals both.
func bindNvidiaRuntime(core *coreauth.Manager, exec coreauth.ProviderExecutor, models []*cliproxy.ModelInfo) int {
	if core == nil || exec == nil {
		return 0
	}
	core.RegisterExecutor(exec)
	n := 0
	for _, a := range core.List() {
		if a == nil || !strings.EqualFold(a.Provider, nvidiaProvider) {
			continue
		}
		cliproxy.GlobalModelRegistry().RegisterClient(a.ID, nvidiaProvider, models)
		core.RefreshSchedulerEntry(a.ID)
		n++
	}
	if n == 0 {
		cliproxy.GlobalModelRegistry().RegisterClient(nvidiaAuthFileName, nvidiaProvider, models)
	}
	return n
}

// ensureNvidiaAuth registers an in-memory auth when AuthDir load produced none.
func ensureNvidiaAuth(core *coreauth.Manager) {
	if core == nil {
		return
	}
	for _, a := range core.List() {
		if a != nil && strings.EqualFold(a.Provider, nvidiaProvider) {
			return
		}
	}
	if _, err := core.Register(coreauth.WithSkipPersist(context.Background()), &coreauth.Auth{
		ID:       nvidiaAuthFileName,
		Provider: nvidiaProvider,
		Status:   coreauth.StatusActive,
	}); err != nil {
		log.Printf("warning: register nvidia auth: %v", err)
	}
}

// startNvidiaReconciler heals races with watcher model/executor registration.
// Fast for the first 90s after startup, then a slow heartbeat forever.
// catalog is read on every tick so live-refreshed models stay rebound.
func startNvidiaReconciler(ctx context.Context, core *coreauth.Manager, exec coreauth.ProviderExecutor, catalog *modelCatalog) {
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		slow := false
		fastUntil := time.Now().Add(90 * time.Second)
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				ensureNvidiaAuth(core)
				bindNvidiaRuntime(core, exec, catalog.get())
				if !slow && now.After(fastUntil) {
					ticker.Reset(5 * time.Second)
					slow = true
				}
			}
		}
	}()
}

// modelCatalog is the shared, atomically-swapped model list. live registry
// refreshes (fetch.go) replace it, and every (re)binding path reads the
// latest snapshot.
type modelCatalog struct {
	v atomic.Value // []*cliproxy.ModelInfo
}

func newModelCatalog(models []*cliproxy.ModelInfo) *modelCatalog {
	c := &modelCatalog{}
	c.set(models)
	return c
}

func (c *modelCatalog) get() []*cliproxy.ModelInfo {
	if c == nil {
		return nil
	}
	m, _ := c.v.Load().([]*cliproxy.ModelInfo)
	return m
}

func (c *modelCatalog) set(models []*cliproxy.ModelInfo) {
	c.v.Store(models)
}

// nvidiaAuthHook restores executor+models whenever cliproxy registers/updates nvidia auth.
type nvidiaAuthHook struct {
	coreauth.NoopHook
	core    *coreauth.Manager
	exec    coreauth.ProviderExecutor
	catalog *modelCatalog
}

func (h *nvidiaAuthHook) OnAuthRegistered(_ context.Context, auth *coreauth.Auth) {
	h.rebind(auth)
}

func (h *nvidiaAuthHook) OnAuthUpdated(_ context.Context, auth *coreauth.Auth) {
	h.rebind(auth)
}

func (h *nvidiaAuthHook) rebind(auth *coreauth.Auth) {
	if h == nil || auth == nil || !strings.EqualFold(auth.Provider, nvidiaProvider) {
		return
	}
	if h.exec != nil && h.core != nil {
		h.core.RegisterExecutor(h.exec)
	}
	if models := h.catalog.get(); len(models) > 0 {
		cliproxy.GlobalModelRegistry().RegisterClient(auth.ID, nvidiaProvider, models)
	}
	if h.core != nil {
		h.core.RefreshSchedulerEntry(auth.ID)
	}
}

// nvidiaModelHook restores catalog when registerModelsForAuth UnregisterClient's nvidia.
type nvidiaModelHook struct {
	core    *coreauth.Manager
	exec    coreauth.ProviderExecutor
	catalog *modelCatalog
}

func (h *nvidiaModelHook) OnModelsRegistered(context.Context, string, string, []*cliproxy.ModelInfo) {
}

func (h *nvidiaModelHook) OnModelsUnregistered(_ context.Context, provider, clientID string) {
	if h == nil || len(h.catalog.get()) == 0 || clientID == "" {
		return
	}
	if provider != "" && !strings.EqualFold(provider, nvidiaProvider) {
		return
	}
	if h.exec != nil && h.core != nil {
		h.core.RegisterExecutor(h.exec)
	}
	cliproxy.GlobalModelRegistry().RegisterClient(clientID, nvidiaProvider, h.catalog.get())
	if h.core != nil {
		h.core.RefreshSchedulerEntry(clientID)
	}
}
