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
	"os"
	"time"
	"unicode/utf8"

	glm52 "glm52-nvidia"
	"glm52-nvidia/internal/hcaptcha"
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
	timeout := flag.Duration("timeout", 180*time.Second, "total timeout")
	flag.Parse()

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
	client := glm52.New(
		glm52.WithCaptchaToken(token),
		glm52.WithThinking(false),
		glm52.WithDefaults(8, 42, 1.0, 1.0),
	)
	apiCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	resp, err := client.Chat(apiCtx, []glm52.Message{{Role: "user", Content: "ping"}})
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
