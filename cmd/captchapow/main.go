// captchapow solves an hCaptcha challenge end-to-end for a sitekey/host and
// prints the resulting P1_ passcode.
//
// Pipeline: checksiteconfig -> PoW JWT -> fingerprint (with a minted hashcash
// stamp) -> hsw (V8) solve -> getcaptcha submission (several parameter
// variants) -> P1_ token.
//
//	go run ./cmd/captchapow -sitekey 0c6a1e45-75d7-43cc-b836-a0c9d886b8ee -host build.nvidia.com
//	go run ./cmd/captchapow -sitekey ... -host ... -v        # per-stage + per-variant diagnostics
//	go run ./cmd/captchapow -sitekey ... -host ... -raw      # full getcaptcha response bodies
//	go run ./cmd/captchapow -sitekey ... -host ... -verify   # send one upstream request with the token
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
	"unicode/utf8"

	nvidia "nvidia-playgroud-go"
	"nvidia-playgroud-go/internal/captchatls"
	"nvidia-playgroud-go/internal/hcaptcha"
	"nvidia-playgroud-go/internal/hsw"
)

// defaultSitekey and defaultHost are the build.nvidia.com playground widget
// parameters the hCaptcha token is issued for.
const (
	defaultSitekey = "0c6a1e45-75d7-43cc-b836-a0c9d886b8ee"
	defaultHost    = "build.nvidia.com"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// run executes the solve; keeping it here lets the deferred cancel run before
// main exits.
func run() error {
	sitekey := flag.String("sitekey", defaultSitekey, "hCaptcha sitekey")
	host := flag.String("host", defaultHost, "host the captcha is served for")
	verbose := flag.Bool("v", false, "print per-stage and per-variant diagnostics")
	raw := flag.Bool("raw", false, "print full getcaptcha response bodies")
	verify := flag.Bool("verify", false, "after obtaining a token, send one upstream request with it")
	proxy := flag.String("proxy", "", "proxy URL (socks5:// or http://) routing checksiteconfig, hsw.js downloads and getcaptcha submissions")
	pinLocation := flag.String("pin-location", "", "solve with this hsw.js bundle location instead of the challenge JWT's assigned one (cross-variant compatibility test)")
	timeout := flag.Duration("timeout", 180*time.Second, "total timeout")
	flag.Parse()

	// Wire the whole captcha pipeline through -proxy when given: the exit
	// IP decides which hsw bundle location checksiteconfig assigns, so
	// diagnosing datacenter delivery requires the proxy on every stage.
	// MaxConnsPerHost 1 mirrors cmd/serve's sticky captcha transport: rotating
	// proxy pools give each new TCP connection a fresh exit IP, and a solve
	// drifting across exits mid-flow is rejected as a foreign submission.
	// The uTLS transport presents Chrome's ClientHello; hCaptcha's edge
	// classifies bare Go TLS as a bot before it issues a solvable challenge.
	var proxyURL *url.URL
	if *proxy != "" {
		u, perr := url.Parse(*proxy)
		if perr != nil {
			return fmt.Errorf("parse proxy url: %w", perr)
		}
		proxyURL = u
	}
	base := &http.Transport{
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		MaxConnsPerHost:       1,
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	tr, terr := captchatls.New(base, proxyURL)
	if terr != nil {
		return fmt.Errorf("captcha transport: %w", terr)
	}
	client := &http.Client{Timeout: 60 * time.Second, Transport: tr}
	hcaptcha.SetHTTPClient(client)
	hsw.SetHTTPClient(client)
	if *pinLocation != "" {
		hcaptcha.SetPinnedBundleLocation(*pinLocation)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if !*verbose && !*raw {
		token, err := hcaptcha.CaptchaToken(ctx, *sitekey, *host)
		if err != nil {
			return err
		}
		fmt.Println(token)
		if *verify {
			verifyUpstream(ctx, token)
		}
		return nil
	}

	solve, attempts, err := hcaptcha.CaptchaAttempts(ctx, *sitekey, *host)
	if err != nil {
		return err
	}
	fmt.Printf("stage: checksiteconfig=%dms jwt_len=%d location=%q key=%q\n",
		solve.Elapsed.Milliseconds(), len(solve.JWT), solve.Location, solve.Key)
	fmt.Printf("stage: fingerprint_len=%d n_len=%d n_prefix=%q\n",
		len(solve.Fingerprint), len(solve.N), clip(solve.N, 40))

	token := ""
	for _, a := range attempts {
		fmt.Printf("getcaptcha %s: status=%d elapsed=%s", a.Name, a.Status, a.Elapsed.Round(time.Millisecond))
		if a.Err != nil {
			fmt.Printf(" err=%v", a.Err)
		}
		if a.Token != "" {
			token = a.Token
			fmt.Printf(" TOKEN=%s…", clip(a.Token, 24))
		}
		fmt.Println()
		if *raw {
			if !isText(a.Body) {
				fmt.Printf("--- %s raw body (len %d, binary) ---\n", a.Name, len(a.Body))
			} else {
				fmt.Printf("--- %s raw body (len %d) ---\n%s\n--- end raw body ---\n", a.Name, len(a.Body), string(a.Body))
			}
		} else {
			fmt.Printf("    body: %s\n", bodyPreview(a.Body, 500))
		}
		if token != "" {
			break
		}
	}

	if token == "" {
		return fmt.Errorf("no P1_ passcode in any getcaptcha variant; see per-variant status/body above")
	}
	fmt.Println(token)
	if *verify {
		verifyUpstream(ctx, token)
	}
	return nil
}

// verifyUpstream sends one small chat request through the repo's client with
// the captcha token, mirroring what build.nvidia.com's playground does.
// Upstream acceptance is informational: a rejection here does not invalidate
// the token's own lifecycle.
func verifyUpstream(ctx context.Context, token string) {
	client := nvidia.New(
		nvidia.WithCaptchaToken(token),
		nvidia.WithThinking(false),
		nvidia.WithDefaults(8, 42, 1.0, 1.0),
	)
	apiCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	resp, err := client.Chat(apiCtx, []nvidia.Message{{Role: "user", Content: "ping"}})
	if err != nil {
		fmt.Fprintf(os.Stderr, "upstream verify failed: %v\n", err)
		return
	}
	if resp == nil || len(resp.Choices) == 0 {
		fmt.Fprintln(os.Stderr, "upstream verify: empty response")
		return
	}
	fmt.Printf("upstream verify ok: choices=%d content=%q\n",
		len(resp.Choices), clip(resp.Choices[0].Message.Content, 80))
}

// clip truncates a string to n runes-ish bytes for compact diagnostic output.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// clipBytes renders b as a string truncated to n bytes with a size note.
func clipBytes(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return fmt.Sprintf("%s…(+%d bytes)", string(b[:n]), len(b)-n)
}

// bodyPreview summarizes a response body for diagnostics, substituting a size
// note for binary (non-UTF-8) payloads like encrypted getcaptcha answers.
func bodyPreview(b []byte, n int) string {
	if len(b) == 0 {
		return ""
	}
	if !isText(b) {
		return fmt.Sprintf("(binary body, %d bytes)", len(b))
	}
	return clipBytes(b, n)
}

// isText reports whether b is valid UTF-8 with no control bytes that break
// terminal output.
func isText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, c := range b {
		if c < 0x20 && c != '\n' && c != '\t' && c != '\r' {
			return false
		}
	}
	return true
}
