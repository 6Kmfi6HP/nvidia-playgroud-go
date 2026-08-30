package models

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// catalogHTML renders a minimal catalog page: flight-data resource ids plus
// href links for each id.
func catalogHTML(ids ...string) string {
	var sb strings.Builder
	sb.WriteString(`<html><body>`)
	for _, id := range ids {
		pub, slug := splitID(id)
		sb.WriteString(`<a href="/` + pub + `/` + slug + `">` + slug + `</a>`)
		sb.WriteString(`<script>{"resourceId":"qc69jvmznzxy/` + slug + `"}</script>`)
	}
	sb.WriteString(`</body></html>`)
	return sb.String()
}

// challengeHTML mirrors the AWS WAF JS challenge page.
func challengeHTML() string {
	return `<html><body><script>window.gokuProps = {"key":"x"}</script></body></html>`
}

func TestFetchCatalogIDsFallback(t *testing.T) {
	filtered := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(challengeHTML()))
	}))
	defer filtered.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(catalogHTML("moonshotai/kimi-k3", "nvidia/nemotron-3-ultra-550b-a55b")))
	}))
	defer fallback.Close()

	origF, origB := ModelsURL, FallbackModelsURL
	ModelsURL, FallbackModelsURL = filtered.URL, fallback.URL
	defer func() { ModelsURL, FallbackModelsURL = origF, origB }()

	ids, err := fetchCatalogIDs(context.Background(), http.DefaultClient)
	if err != nil {
		t.Fatalf("fetchCatalogIDs: %v", err)
	}
	if len(ids) != 2 || ids[0] != "moonshotai/kimi-k3" || ids[1] != "nvidia/nemotron-3-ultra-550b-a55b" {
		t.Fatalf("unexpected ids after fallback: %v", ids)
	}
}

func TestGetSendsCatalogCookieSessionsAndHostScoping(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Cookie"))
		w.Header().Set("Set-Cookie", "ak_bmsc=session123; Path=/")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	origHost := ModelsHost
	defer func() { ModelsHost = origHost }()

	// 1. SetCatalogCookie seeds the jar for the catalog host only.
	ModelsHost = "127.0.0.1"
	SetCatalogCookie("aws-waf-token=abc")
	defer SetCatalogCookie("")

	if _, err := get(context.Background(), srv.Client(), srv.URL); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(seen) != 1 || seen[0] != "aws-waf-token=abc" {
		t.Fatalf("catalog fetch cookies = %v, want [aws-waf-token=abc]", seen)
	}

	// 2. Set-Cookie from the response is absorbed and replayed.
	if _, err := get(context.Background(), srv.Client(), srv.URL); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(seen) != 2 || !strings.Contains(seen[1], "aws-waf-token=abc") || !strings.Contains(seen[1], "ak_bmsc=session123") {
		t.Fatalf("second fetch cookies = %v, want both seeded token and absorbed session", seen)
	}

	// 3. A different host does not send the catalog cookies.
	ModelsHost = "example.com"
	SetCatalogCookie("aws-waf-token=abc")
	seen = nil
	if _, err := get(context.Background(), srv.Client(), srv.URL); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(seen) != 1 || seen[0] != "" {
		t.Fatalf("non-catalog fetch cookies = %v, want empty", seen)
	}
}

func TestHTTPStatusChallenge(t *testing.T) {
	if !httpStatusChallenge([]byte(challengeHTML())) {
		t.Fatal("challenge page not detected")
	}
	if httpStatusChallenge([]byte(catalogHTML("a/b"))) {
		t.Fatal("catalog page misdetected as challenge")
	}
}
