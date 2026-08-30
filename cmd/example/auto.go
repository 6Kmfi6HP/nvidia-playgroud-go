package main

import (
	"context"

	"glm52-nvidia/internal/captcha"
)

// extractCaptchaToken mints a fresh one-shot token with the pure-Go
// hCaptcha PoW solver (no browser): it solves the PoW challenge for the
// NVIDIA Playground sitekey and exchanges it for a P1_ token.
func extractCaptchaToken(baseCtx context.Context) (string, error) {
	return captcha.PowExtract()(baseCtx)
}
