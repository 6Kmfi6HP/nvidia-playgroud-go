// JSON cache for the live-scraped model registry.
//
// Every successful Refresh atomically rewrites the cache file with the fresh
// registry, so the last-known-good catalog survives restarts and network
// outages: cmd/serve restores it at startup (LoadCache) and can serve model
// ids immediately, without waiting for (or failing on) the first live fetch.
// A failed refresh never touches the file — the previous copy stays valid.
//
// File format:
//
//	{
//	  "fetched_at": "2026-08-30T12:00:00Z",
//	  "models": {
//	    "moonshotai/kimi-k3": {
//	      "slug": "kimi-k3",
//	      "namespace": "qc69jvmznzxy",
//	      "function_id": "1586112a-925c-48af-8631-7c815dbd749c"
//	    }
//	  }
//	}
//
// Writes go to a temp file in the same directory followed by rename, so a
// crash mid-write never corrupts the previous copy.

package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// cacheFile is the path of the registry JSON cache; empty disables caching.
// Set via SetCacheFile (cmd/serve) before any Fetch/Refresh starts.
var cacheFile string

// saveMu serializes cache writes (cmd/serve refreshes on one goroutine, but
// tests and embedders may call Refresh concurrently).
var saveMu sync.Mutex

// cacheData is the on-disk cache format.
type cacheData struct {
	FetchedAt time.Time            `json:"fetched_at"`
	Models    map[string]ModelInfo `json:"models"`
}

// SetCacheFile enables automatic registry persistence to path (JSON). Empty
// disables it. After every successful Refresh the fresh registry is written
// to the file, and LoadCache restores it at startup.
func SetCacheFile(path string) { cacheFile = path }

// LoadCache restores the registry snapshot stored by Refresh's auto-save.
// It returns fs.ErrNotExist when no cache has been written yet (first run);
// callers then keep the compiled-in snapshot. Any other error means the file
// exists but is unusable (corrupt/empty) — fall back and log, don't fail.
func LoadCache() (map[string]ModelInfo, error) {
	if cacheFile == "" {
		return nil, errors.New("models: cache disabled (SetCacheFile not called)")
	}
	return loadCacheFrom(cacheFile)
}

// loadCacheFrom reads and parses the cache at path.
func loadCacheFrom(path string) (map[string]ModelInfo, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err // os.IsNotExist(err) => first run, not an error
	}
	var c cacheData
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("models: parse cache %s: %w", path, err)
	}
	if len(c.Models) == 0 {
		return nil, fmt.Errorf("models: cache %s holds no models", path)
	}
	return c.Models, nil
}

// saveCache writes reg to the configured cache file; no-op when caching is
// disabled or the registry is empty (an empty registry is never cached).
func saveCache(reg map[string]ModelInfo) error {
	if cacheFile == "" || len(reg) == 0 {
		return nil
	}
	return saveCacheTo(cacheFile, reg)
}

// saveCacheTo atomically writes reg to path: temp file in the same
// directory, fsync, then rename — a crash leaves the previous cache intact.
func saveCacheTo(path string, reg map[string]ModelInfo) error {
	saveMu.Lock()
	defer saveMu.Unlock()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("models: cache dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".models-cache-*.tmp")
	if err != nil {
		return fmt.Errorf("models: cache temp file: %w", err)
	}
	tmpName := tmp.Name()
	// Remove is a no-op after the successful rename; on error paths it is a
	// best-effort cleanup of the leftover temp file.
	defer func() {
		if err := os.Remove(tmpName); err != nil {
			_ = err
		}
	}()

	b, err := json.MarshalIndent(cacheData{FetchedAt: time.Now().UTC(), Models: reg}, "", "  ")
	if err != nil {
		bestEffortClose(tmp)
		return fmt.Errorf("models: encode cache: %w", err)
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		bestEffortClose(tmp)
		return fmt.Errorf("models: write cache: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		bestEffortClose(tmp)
		return fmt.Errorf("models: chmod cache: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		bestEffortClose(tmp)
		return fmt.Errorf("models: sync cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("models: close cache: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("models: install cache %s: %w", path, err)
	}
	return nil
}

// bestEffortClose closes c on a path where the primary error is already being
// reported; a close failure cannot improve the returned error.
func bestEffortClose(c io.Closer) {
	if err := c.Close(); err != nil {
		_ = err
	}
}
