package captchatls

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// TestChromeTransportHandshake pins the two properties the captcha exchange
// depends on: the uTLS handshake completes against a normal TLS server, and
// ALPN is HTTP/1.1 even across several fresh connections (the hello spec is
// rebuilt per handshake, so a shared mutated spec cannot regress it).
func TestChromeTransportHandshake(t *testing.T) {
	var protos []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protos = append(protos, r.TLS.NegotiatedProtocol)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	base := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	tr, err := New(base, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	client := &http.Client{Transport: tr}
	for i := 0; i < 3; i++ {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("request %d read: %v", i+1, err)
		}
		if string(body) != "ok" {
			t.Fatalf("request %d body = %q", i+1, body)
		}
	}
	if len(protos) != 3 {
		t.Fatalf("server saw %d handshakes, want 3", len(protos))
	}
	for i, p := range protos {
		if p != "http/1.1" {
			t.Errorf("handshake %d ALPN = %q, want http/1.1", i+1, p)
		}
	}
}

func TestChromeSpecALPN(t *testing.T) {
	spec, err := chromeSpec()
	if err != nil {
		t.Fatalf("chromeSpec: %v", err)
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			if len(alpn.AlpnProtocols) != 1 || alpn.AlpnProtocols[0] != "http/1.1" {
				t.Fatalf("ALPN = %v, want [http/1.1]", alpn.AlpnProtocols)
			}
			return
		}
	}
	t.Fatal("chromeSpec has no ALPN extension")
}
