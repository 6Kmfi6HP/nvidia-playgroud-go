package models

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCacheRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "models-cache.json")
	reg := map[string]ModelInfo{
		"moonshotai/kimi-k3": {Slug: "kimi-k3", Namespace: Namespace, FunctionID: "1586112a-925c-48af-8631-7c815dbd749c"},
		"nvidia/nemotron-3-ultra-550b-a55b": {
			Slug: "nemotron-3-ultra-550b-a55b", Namespace: Namespace, FunctionID: "948fe171-ce7a-4332-8bc0-5e14e90259f9",
			Capability: &ModelCapability{ToolCalling: true, Vision: true},
		},
	}
	if err := saveCacheTo(path, reg); err != nil {
		t.Fatalf("saveCacheTo: %v", err)
	}
	got, err := loadCacheFrom(path)
	if err != nil {
		t.Fatalf("loadCacheFrom: %v", err)
	}
	if len(got) != len(reg) {
		t.Fatalf("loaded %d models, want %d", len(got), len(reg))
	}
	for id, want := range reg {
		if !reflect.DeepEqual(got[id], want) {
			t.Fatalf("%s: got %+v want %+v", id, got[id], want)
		}
	}
}

func TestLoadCacheMissing(t *testing.T) {
	_, err := loadCacheFrom(filepath.Join(t.TempDir(), "nope.json"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("want fs.ErrNotExist, got %v", err)
	}
}

func TestLoadCacheCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCacheFrom(path); err == nil {
		t.Fatal("corrupt cache parsed without error")
	}
}

// TestRefreshWritesCache exercises the automatic persistence: a successful
// Refresh writes the fresh registry to the configured cache file (creating
// the directory), and the file round-trips through loadCacheFrom.
func TestRefreshWritesCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moonshotai/kimi-k3/playground" {
			writeTestBody(t, w, []byte(`<html>"nvcfFunctionId":"1586112a-925c-48af-8631-7c815dbd749c","namespace":"qc69jvmznzxy"</html>`))
			return
		}
		writeTestBody(t, w, []byte(catalogHTML("moonshotai/kimi-k3")))
	}))
	defer srv.Close()

	origF, origB := ModelsURL, FallbackModelsURL
	ModelsURL, FallbackModelsURL = srv.URL, srv.URL
	defer func() { ModelsURL, FallbackModelsURL = origF, origB }()

	origRegistry := All()
	defer Replace(origRegistry)
	origCache := cacheFile
	// Subdirectory does not exist yet: the save must create it.
	cacheFile = filepath.Join(t.TempDir(), "sub", "cache.json")
	defer func() { cacheFile = origCache }()

	res, err := Refresh(context.Background(), http.DefaultClient)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	got, err := loadCacheFrom(cacheFile)
	if err != nil {
		t.Fatalf("load cached registry: %v", err)
	}
	if len(got) != len(res.Models) {
		t.Fatalf("cache holds %d models, want %d", len(got), len(res.Models))
	}
	for id, info := range res.Models {
		if !reflect.DeepEqual(got[id], info) {
			t.Fatalf("%s cached mismatch: %+v vs %+v", id, got[id], info)
		}
	}
	// A failed refresh must not touch the cache file.
	ModelsURL, FallbackModelsURL = "http://127.0.0.1:1", "http://127.0.0.1:1"
	if _, err := Refresh(context.Background(), http.DefaultClient); err == nil {
		t.Fatal("refresh against dead endpoint succeeded")
	}
	after, err := loadCacheFrom(cacheFile)
	if err != nil {
		t.Fatalf("cache lost after failed refresh: %v", err)
	}
	if !reflect.DeepEqual(after, got) {
		t.Fatal("failed refresh modified the cache")
	}
}

// writeTestBody writes b from an httptest handler; a write failure cannot
// fail the test directly, so it is reported and the handler continues.
func writeTestBody(t *testing.T, w http.ResponseWriter, b []byte) {
	t.Helper()
	if _, err := w.Write(b); err != nil {
		t.Errorf("write test response: %v", err)
	}
}
