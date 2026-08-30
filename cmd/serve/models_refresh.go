package main

// Live model-catalog refresh: periodically re-scrapes build.nvidia.com for
// the playground model list (internal/models/fetch.go) and hot-swaps the
// gateway catalog (modelCatalog). The compiled-in snapshot is only a
// bootstrap/fallback; a failed refresh keeps the current catalog.

import (
	"context"
	"log"
	"time"

	"glm52-nvidia/internal/models"
	"glm52-nvidia/internal/provider/nvidia"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// startModelRefresher performs an initial foreground refresh only when
// syncBootstrap is false; use syncBootstrap=true to block startup until the
// live catalog is fetched (falling back to the compiled-in snapshot on
// failure). It then keeps the registry fresh every interval.
func startModelRefresher(ctx context.Context, catalog *modelCatalog, core *coreauth.Manager, exec coreauth.ProviderExecutor, interval time.Duration) {
	go func() {
		refreshModels(ctx, catalog, core, exec)
		if interval <= 0 {
			return
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refreshModels(ctx, catalog, core, exec)
			}
		}
	}()
}

func refreshModels(ctx context.Context, catalog *modelCatalog, core *coreauth.Manager, exec coreauth.ProviderExecutor) {
	// nil selects the package client: the browser-fingerprint (tls-client)
	// instance when cmd/serve installed one, else the proxied standard client.
	res, err := models.Refresh(ctx, nil)
	if err != nil {
		log.Printf("model catalog refresh failed (keeping previous %d models): %v", len(models.All()), err)
		return
	}
	catalog.set(nvidia.RegistryModels())
	n := bindNvidiaRuntime(core, exec, catalog.get())
	log.Printf("model catalog refreshed: %d/%d playground models (%d skipped; auth-bound=%d)",
		len(res.Models), res.Total, len(res.Skipped), n)
}
