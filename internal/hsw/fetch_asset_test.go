package hsw

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestFetchAssetWarmupAndSRI(t *testing.T) {
	const body = "hsw-bytes"
	sum := sha256.Sum256([]byte(body))
	sri := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		switch r.URL.Path {
		case "/asset.js":
			if r.Header.Get("Referer") == "" {
				t.Errorf("asset request %d missing referer", n)
			}
			if n == 1 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(body))
		case "/warmup.html":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	old := hswClient
	hswClient = srv.Client()
	defer func() { hswClient = old }()

	got, err := FetchAsset(context.Background(), srv.URL+"/asset.js", srv.URL+"/warmup.html", sri, "ua")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("body = %q", got)
	}
	if hits.Load() != 3 {
		t.Fatalf("hits = %d, want asset, warmup, asset", hits.Load())
	}

	_, err = FetchAsset(context.Background(), srv.URL+"/asset.js", srv.URL+"/warmup.html", "sha256-aaaa", "ua")
	if err == nil || !strings.Contains(err.Error(), "SRI mismatch") {
		t.Fatalf("err = %v, want SRI mismatch", err)
	}
}
