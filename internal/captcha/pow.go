package captcha

// Pure-Go captcha path: no browser, no Chromium. Solves hCaptcha's PoW
// challenge for the build.nvidia.com playground sitekey via the embedded V8
// hsw solver (see internal/hcaptcha + internal/hcaptcha/hsw), then exchanges
// the solution at getcaptcha for a one-shot P1_ token.
//
// This is the default gateway extractor — Chrome stays available behind
// -captcha-solver=browser as a fallback debugging path.

import (
	"context"

	"glm52-nvidia/internal/hcaptcha"
)

const (
	// PlaygroundSitekey and PlaygroundHost identify the hCaptcha widget the
	// build.nvidia.com playground registers; the issued token is only valid
	// for this (sitekey, host) pair.
	PlaygroundSitekey = "0c6a1e45-75d7-43cc-b836-a0c9d886b8ee"
	PlaygroundHost    = "build.nvidia.com"
)

// PowExtract returns an ExtractFunc compatible with Pool. Each call performs
// a full solve (a few hundred ms CPU + one fixture download, cached in
// process lifetime via the hsw solver cache) and returns a fresh one-shot
// token. Safe for concurrent use; V8 isolates are serialized internally.
func PowExtract() ExtractFunc {
	return func(ctx context.Context) (string, error) {
		return hcaptcha.CaptchaToken(ctx, PlaygroundSitekey, PlaygroundHost)
	}
}
