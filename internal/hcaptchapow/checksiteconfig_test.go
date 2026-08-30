package hcaptchapow

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestCheckSiteConfig(t *testing.T) {
	const (
		sitekey = "a5f74b19-9e45-40e0-b45d-47ff91b7a6c2"
		host    = "accounts.hcaptcha.com"
		v       = "540c361"
		wantReq = "eyJhbGciOiJub25lIn0.eyJzIjoyfQ.sig"
	)
	queryCh := make(chan url.Values, 1)
	headersCh := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		queryCh <- r.URL.Query()
		headersCh <- r.Header
		w.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprint(w, `{"c":{"req":"`+wantReq+`","key":"0xdeadbeef"},"pass":true}`); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer srv.Close()
	oldURL := checksiteconfigURL
	checksiteconfigURL = srv.URL + "/checksiteconfig"
	t.Cleanup(func() { checksiteconfigURL = oldURL })

	got, err := CheckSiteConfig(context.Background(), sitekey, host, v)
	if err != nil {
		t.Fatalf("CheckSiteConfig: %v", err)
	}
	if got != wantReq {
		t.Errorf("req = %q, want %q", got, wantReq)
	}

	q := <-queryCh
	for key, want := range map[string]string{
		"sitekey": sitekey, "host": host, "v": v,
		"sc": "1", "swa": "1", "spst": "1",
	} {
		if q.Get(key) != want {
			t.Errorf("query %s = %q, want %q", key, q.Get(key), want)
		}
	}
	h := <-headersCh
	if ct := h.Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if accept := h.Get("Accept"); accept != "application/json" {
		t.Errorf("Accept = %q, want application/json", accept)
	}
}

func TestCheckSiteConfigErrors(t *testing.T) {
	t.Run("missing params", func(t *testing.T) {
		if _, err := CheckSiteConfig(context.Background(), "", "host", "v"); err == nil {
			t.Error("empty sitekey succeeded, want error")
		}
	})

	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusInternalServerError)
		}))
		defer srv.Close()
		oldURL := checksiteconfigURL
		checksiteconfigURL = srv.URL
		t.Cleanup(func() { checksiteconfigURL = oldURL })
		if _, err := CheckSiteConfig(context.Background(), "k", "h", "v"); err == nil {
			t.Error("500 response succeeded, want error")
		}
	})

	t.Run("missing c.req", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := fmt.Fprint(w, `{"c":{"key":"k"}}`); err != nil {
				t.Errorf("write response: %v", err)
			}
		}))
		defer srv.Close()
		oldURL := checksiteconfigURL
		checksiteconfigURL = srv.URL
		t.Cleanup(func() { checksiteconfigURL = oldURL })
		if _, err := CheckSiteConfig(context.Background(), "k", "h", "v"); err == nil {
			t.Error("response without c.req succeeded, want error")
		}
	})
}
