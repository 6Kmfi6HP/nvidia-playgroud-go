package main

import (
	"net/http"
	"net/url"
	"testing"
)

func TestBypassHostProxyDirect(t *testing.T) {
	pf := func(req *http.Request) (*url.URL, error) {
		return url.Parse("socks5://127.0.0.1:1090")
	}
	bypass := bypassHostProxy(pf, "https://buildapi.ngc.nvidia.com")

	// predict host -> direct (nil proxy)
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: "buildapi.ngc.nvidia.com", Path: "/v2/predict/models/x"}}
	got, err := bypass(req)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("buildapi should bypass proxy, got %v", got)
	}

	// other host -> proxied
	req2 := &http.Request{URL: &url.URL{Scheme: "https", Host: "checksiteconfig.hcaptcha.com"}}
	got2, err := bypass(req2)
	if err != nil {
		t.Fatal(err)
	}
	if got2 == nil || got2.Host != "127.0.0.1:1090" {
		t.Fatalf("non-predict host should use proxy, got %v", got2)
	}
}

func TestBypassHostProxyInvalidBase(t *testing.T) {
	// invalid base URL should not panic and keep original func
	called := false
	pf := func(req *http.Request) (*url.URL, error) {
		called = true
		return nil, nil
	}
	bypass := bypassHostProxy(pf, "://bad")
	_, _ = bypass(&http.Request{URL: &url.URL{Host: "anything.example"}})
	if !called {
		t.Fatal("original proxy func should still be called")
	}
}
