package hcaptcha

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"nvidia-playgroud-go/internal/hcaptchapow"
	"nvidia-playgroud-go/internal/hsw"
)

// runWidgetAttempt mirrors the reference minter (nvidia-playground.mjs):
//
//	checksiteconfig challenge
//	-> hsw solve (PoW n)
//	-> wasm-encrypt msgpack{v, sitekey, host, hl, motionData, n, e:null}
//	-> POST msgpack([{"type":"hsw","req":jwt}, ext18(cipher)])
//	-> wasm-decrypt the answer and read generated_pass_UUID
//
// The widget flow submits the checksiteconfig challenge directly instead of
// claiming a second challenge from getcaptcha, and it carries the fields the
// browser widget sends (motionData and e). That combination is what the live
// frontend accepts; the older claim-based encrypted path is kept as a
// fallback.
func runWidgetAttempt(ctx context.Context, sitekey, host, jwt, location string) (at CaptchaAttempt, info SolveInfo) {
	v := AssetVersion(ctx)
	at = CaptchaAttempt{Name: "widget"}
	t0 := time.Now()
	defer func() { at.Elapsed = time.Since(t0) }()

	spec := fmt.Sprintf(`{"type":"hsw","req":%s}`, mustJSONString(jwt))
	for round := 1; round <= maxEncryptedRounds; round++ {
		if round > 1 {
			at.Name = fmt.Sprintf("widget-r%d", round)
		}
		if ctx.Err() != nil {
			at.Err = fmt.Errorf("hcaptcha: widget: context done: %w", ctx.Err())
			return
		}
		if location == "" {
			var perr error
			location, perr = hsw.LocationFromJWT(jwt)
			if perr != nil {
				at.Err = fmt.Errorf("hcaptcha: widget: location: %w", perr)
				return
			}
		}
		solver, perr := solverFor(ctx, location)
		if perr != nil {
			at.Err = fmt.Errorf("hcaptcha: widget: load solver: %w", perr)
			return
		}
		pow, perr := hcaptchapow.ParsePow(jwt)
		if perr != nil {
			at.Err = fmt.Errorf("hcaptcha: widget: parse pow: %w", perr)
			return
		}
		fpB64, perr := BuildFingerprint(pow)
		if perr != nil {
			at.Err = fmt.Errorf("hcaptcha: widget: build fingerprint: %w", perr)
			return
		}
		n, perr := solver.SolveN(ctx, jwt, fpB64)
		if perr != nil {
			markBundleBroken(location, perr)
			at.Err = fmt.Errorf("hcaptcha: widget: solve: %w", perr)
			return
		}
		info = SolveInfo{JWT: jwt, Location: location, Fingerprint: fpB64, N: n}

		params := map[string]any{
			"v":          v,
			"sitekey":    sitekey,
			"host":       host,
			"hl":         "en",
			"motionData": "{}",
			"n":          n,
			"e":          nil,
		}
		at.Params = map[string]string{
			"v": v, "sitekey": sitekey, "host": host, "hl": "en",
			"motionData": "{}", "n": n,
		}
		plain := msgpackEncodeMapAny(params)
		cipher, perr := solver.Crypto(ctx, 1, plain)
		if perr != nil {
			markBundleBroken(location, perr)
			at.Err = fmt.Errorf("hcaptcha: widget: encrypt: %w", perr)
			return
		}
		body := msgpackEncodeWire(spec, cipher)
		status, resp, perr := postGetCaptchaOctetFn(ctx, sitekey, body)
		at.Status, at.Body = status, resp
		if perr != nil {
			at.Err = fmt.Errorf("hcaptcha: widget: %w", perr)
			return
		}
		if at.Token = FindP1Token(resp); at.Token != "" {
			return
		}

		// A 200 answer to an encrypted submission is wasm-encrypted; decrypt
		// (mode 0) before looking for the passcode or a re-issued challenge.
		dec := resp
		if !isTextBody(resp) {
			dec, perr = solver.Crypto(ctx, 0, resp)
			if perr != nil {
				at.Err = fmt.Errorf("hcaptcha: widget: decrypt: %w", perr)
				return
			}
		}
		if at.Token = FindP1Token(dec); at.Token != "" {
			return
		}
		if spec2, jwt2, ctype2, ok := reissuedChallenge(dec); ok {
			if ctype2 != "" && ctype2 != "hsw" {
				at.Err = fmt.Errorf("hcaptcha: widget: server re-issued %q challenge", ctype2)
				return
			}
			spec, jwt = spec2, jwt2
			location = ""
			continue
		}
		// The decrypted answer is msgpack; a re-issued challenge can be a map
		// value inside it.
		if msg, rest, merr := msgpackDecode(dec); merr == nil && len(rest) == 0 {
			if j, jerr := json.Marshal(msg); jerr == nil {
				if spec2, jwt2, ctype2, ok := reissuedChallenge(j); ok {
					if ctype2 != "" && ctype2 != "hsw" {
						at.Err = fmt.Errorf("hcaptcha: widget: server re-issued %q challenge", ctype2)
						return
					}
					spec, jwt = spec2, jwt2
					location = ""
					continue
				}
			}
		}
		at.Err = fmt.Errorf("hcaptcha: widget: encrypted response carries no passcode")
		return
	}
	at.Err = fmt.Errorf("hcaptcha: widget: proof rejected %d times", maxEncryptedRounds)
	return
}
