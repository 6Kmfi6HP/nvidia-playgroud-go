package hcaptcha

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"nvidia-playgroud-go/internal/hcaptchapow"
)

// TestExportLiveFingerprint fetches a live challenge and dumps the JWT plus
// the real rendered fingerprint to HSW_EXPORT_DIR for external driver runs.
// Enable with HSW_LIVE=1 and set HSW_EXPORT_DIR.
func TestExportLiveFingerprint(t *testing.T) {
	if !strings.EqualFold(os.Getenv("HSW_LIVE"), "1") {
		t.Skip("set HSW_LIVE=1")
	}
	dir := os.Getenv("HSW_EXPORT_DIR")
	if dir == "" {
		t.Skip("set HSW_EXPORT_DIR")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	jwt, location, _, _, err := fetchChecksiteLive(ctx, "0c6a1e45-75d7-43cc-b836-a0c9d886b8ee", "build.nvidia.com")
	if err != nil {
		t.Fatalf("fetchChecksiteLive: %v", err)
	}
	t.Logf("location=%s jwt_len=%d", location, len(jwt))

	pow, err := hcaptchapow.ParsePow(jwt)
	if err != nil {
		t.Fatalf("ParsePow: %v", err)
	}
	fp, err := BuildFingerprint(pow)
	if err != nil {
		t.Fatalf("BuildFingerprint: %v", err)
	}
	if err := os.WriteFile(dir+"/challenge.json", []byte(`{"jwt":"`+jwt+`","fpB64":"`+fp+`"}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Logf("fp_len=%d dumped to %s", len(fp), dir)
}
