// Package captchatls builds the HTTP transport used for hCaptcha traffic.
//
// The hCaptcha edge inspects the TLS ClientHello before it decides whether to
// serve a challenge, so this transport mimics a current desktop Chrome with
// uTLS instead of Go's fingerprint. Proxying is handled here as well because
// net/http only calls DialTLSContext for direct connections.
package captchatls

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	xproxy "golang.org/x/net/proxy"
)

// New clones base and replaces its TLS dialer with a Chrome-fingerprinted
// uTLS handshake. proxyURL, when non-nil, is used for every connection
// (http/https CONNECT or socks5/socks5h); base.Proxy is ignored.
func New(base *http.Transport, proxyURL *url.URL) (*http.Transport, error) {
	tr := base.Clone()
	tr.Proxy = nil
	tr.ForceAttemptHTTP2 = false

	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}

	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := dialTarget(ctx, dialer, proxyURL, network, addr)
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			raw.Close()
			return nil, err
		}
		cfg := &utls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if base.TLSClientConfig != nil {
			cfg.InsecureSkipVerify = base.TLSClientConfig.InsecureSkipVerify
			cfg.RootCAs = base.TLSClientConfig.RootCAs
			cfg.ServerName = firstNonEmpty(base.TLSClientConfig.ServerName, host)
		}
		spec, serr := chromeSpec()
		if serr != nil {
			raw.Close()
			return nil, serr
		}
		conn := utls.UClient(raw, cfg, utls.HelloCustom)
		if err := conn.ApplyPreset(&spec); err != nil {
			raw.Close()
			return nil, fmt.Errorf("captchatls: apply hello: %w", err)
		}
		if err := conn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("captchatls: handshake: %w", err)
		}
		return conn, nil
	}
	return tr, nil
}

// chromeSpec returns Chrome's ClientHello with ALPN pinned to HTTP/1.1: the
// transport writes HTTP/1.1 frames, so advertising h2 would corrupt them.
func chromeSpec() (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		return utls.ClientHelloSpec{}, fmt.Errorf("captchatls: hello spec: %w", err)
	}
	found := false
	for i, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
			spec.Extensions[i] = alpn
			found = true
		}
	}
	if !found {
		spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
	}
	return spec, nil
}

func dialTarget(ctx context.Context, d *net.Dialer, proxyURL *url.URL, network, addr string) (net.Conn, error) {
	if proxyURL == nil {
		return d.DialContext(ctx, network, addr)
	}
	switch strings.ToLower(proxyURL.Scheme) {
	case "socks5", "socks5h":
		auth := &xproxy.Auth{}
		if proxyURL.User != nil {
			auth.User = proxyURL.User.Username()
			auth.Password, _ = proxyURL.User.Password()
		}
		cd, err := xproxy.SOCKS5("tcp", proxyURL.Host, auth, d)
		if err != nil {
			return nil, fmt.Errorf("captchatls: socks5: %w", err)
		}
		return cd.Dial(network, addr)
	case "http", "https":
		return dialHTTPProxy(ctx, d, proxyURL, addr)
	default:
		return nil, fmt.Errorf("captchatls: unsupported proxy scheme %q", proxyURL.Scheme)
	}
}

func dialHTTPProxy(ctx context.Context, d *net.Dialer, proxyURL *url.URL, addr string) (net.Conn, error) {
	conn, err := d.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("captchatls: proxy dial: %w", err)
	}
	if strings.EqualFold(proxyURL.Scheme, "https") {
		tc := tls.Client(conn, &tls.Config{ServerName: proxyURL.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("captchatls: proxy tls: %w", err)
		}
		conn = tc
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		pass, _ := proxyURL.User.Password()
		creds := proxyURL.User.Username() + ":" + pass
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("captchatls: proxy connect write: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("captchatls: proxy connect read: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("captchatls: proxy connect: %s", resp.Status)
	}
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

var _ io.Reader = (*bufferedConn)(nil)
