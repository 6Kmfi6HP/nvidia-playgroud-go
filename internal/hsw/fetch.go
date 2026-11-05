// hsw.js fetching and patching.
//
// hCaptcha serves hsw.js from:
//
//	https://newassets.hcaptcha.com/c/{location}/hsw.js
//
// where location is either a short hex id (older bundles) or the full hash
// path returned in the challenge JWT's "l" claim (newer bundles, e.g.
// "/c/8af55315015e17fa8c964be34ae93d53b7f9c36edafcccdc7fc9a4691cbd9e43").
//
// Patching follows the documented hsw-srv approach: neutralize browser-only
// feature tests (language, Window, PerformanceResourceTiming) that fail under
// a minimal DOM shim, then wrap the bundle so it evaluates cleanly and its
// entry function is exported as module.exports.
package hsw

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// AssetBase is where hCaptcha serves hsw.js and challenge assets.
	AssetBase = "https://newassets.hcaptcha.com"
	// ChecksiteBase is the config endpoint that returns the challenge JWT
	// and bundle location.
	ChecksiteBase = "https://api.hcaptcha.com/checksiteconfig"

	httpTimeout   = 60 * time.Second
	maxBundleSize = 16 << 20 // hsw.js is ~1 MB; be generous.
)

var hswClient = &http.Client{Timeout: httpTimeout}

// SetHTTPClient replaces the client used for hsw.js downloads and
// checksiteconfig fetches. cmd/serve uses it to route pure-Go PoW solving
// through the upstream proxy. Must be called before solving starts.
func SetHTTPClient(c *http.Client) { hswClient = c }

// ResetConnections closes every idle upstream connection, so the next
// request dials fresh. Through a rotating proxy pool each new connection
// carries a new exit IP; callers use this to abandon a risk-flagged exit
// after a failed solve. No-op when no idle connections are held.
func ResetConnections() { hswClient.CloseIdleConnections() }

var (
	// reWindowHSW matches the v1 bundle tail: window.hsw = function(...)...
	reWindowHSW = regexp.MustCompile(`window\.hsw\s*=`)

	// reEmbeddedWasm matches wasm-bindgen's embedded base64 WASM literal, e.g.
	//   instantiate(..., 0, null, "<base64>", ...)
	reEmbeddedWasm = regexp.MustCompile(`0,\s*null,\s*"([A-Za-z0-9+/=]{200,})"`)
	// reDataWasm matches a data: URL carrying the wasm base64.
	reDataWasm = regexp.MustCompile(`data:(?:application/octet-stream|application/wasm);base64,([A-Za-z0-9+/=]{200,})`)
)

// Bundle is a fully prepared hsw.js execution unit: the shimmed+patched source
// plus metadata about the download.
type Bundle struct {
	Location string // location path as requested ("/c/<hash>" or bare id)
	URL      string // full download URL
	Version  string // "v1" (window.hsw) | "v2" (wasm-bindgen) | "unknown"
	WasmB64  string // embedded v2 wasm base64, empty for v1
	Source   string // complete script: shim + patched hsw.js + export line
}

// ChecksiteResponse mirrors the relevant fields of checksiteconfig.
type ChecksiteResponse struct {
	C struct {
		Type string `json:"type"`
		Req  string `json:"req"`
		Key  string `json:"key"`
		JWT  string `json:"jwt"`
	} `json:"c"`
	L        string `json:"l"`
	Pass     bool   `json:"pass"`
	Features struct {
		EncGetReq bool `json:"enc_get_req"`
	} `json:"features"`
}

// FetchChallenge calls checksiteconfig for a sitekey/host and returns the hsw
// challenge JWT plus the bundle location from the JWT payload's "l" claim
// (falling back to the legacy top-level "l" field).
func FetchChallenge(ctx context.Context, sitekey, host string) (jwt, location string, err error) {
	u := fmt.Sprintf("%s?host=%s&sitekey=%s&sc=1&swa=0&spst=0&hl=en",
		ChecksiteBase, url.QueryEscape(host), url.QueryEscape(sitekey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return "", "", fmt.Errorf("checksiteconfig: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	resp, err := hswClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("checksiteconfig: %w", err)
	}
	defer CloseBody(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("checksiteconfig: HTTP %d", resp.StatusCode)
	}
	var out ChecksiteResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", fmt.Errorf("checksiteconfig decode: %w", err)
	}
	jwt = out.C.Req
	if jwt == "" {
		jwt = out.C.JWT
	}
	if jwt == "" {
		jwt = out.C.Key
	}
	if jwt == "" {
		return "", "", fmt.Errorf("checksiteconfig: no challenge jwt in response")
	}
	location = out.L
	if location == "" {
		location, err = LocationFromJWT(jwt)
		if err != nil {
			return "", "", fmt.Errorf("checksiteconfig: %w", err)
		}
	}
	return jwt, location, nil
}

// LocationFromJWT extracts the hsw.js bundle location from a challenge JWT:
// newer responses carry the location in the payload's "l" claim as a full
// path like "/c/<sha256>"; legacy payloads/checksiteconfig bodies used a bare
// hex id.
func LocationFromJWT(jwt string) (string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("jwt: expected <header>.<payload>")
	}
	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		return "", fmt.Errorf("jwt payload decode: %w", err)
	}
	var m struct {
		L string `json:"l"`
	}
	if err := json.Unmarshal(payload, &m); err != nil {
		return "", fmt.Errorf("jwt payload json: %w", err)
	}
	if m.L == "" {
		return "", fmt.Errorf("jwt payload has no l claim")
	}
	return m.L, nil
}

func decodeJWTPart(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// AssetURL builds the hsw.js URL for a location. A leading "/" means the
// location is already a path (e.g. "/c/<sha256>"); otherwise it is prefixed
// with "/c/".
func AssetURL(location string) string {
	loc := strings.TrimSuffix(location, "/")
	if strings.HasPrefix(loc, "/") {
		return AssetBase + loc + "/hsw.js"
	}
	return AssetBase + "/c/" + loc + "/hsw.js"
}

// Download fetches the raw hsw.js for location.
func Download(ctx context.Context, location string) ([]byte, error) {
	assetURL := AssetURL(location)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("hsw download %s: %w", assetURL, err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")

	resp, err := hswClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hsw download %s: %w", assetURL, err)
	}
	defer CloseBody(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hsw download %s: HTTP %d", assetURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleSize))
	if err != nil {
		return nil, fmt.Errorf("hsw download %s: %w", assetURL, err)
	}
	return body, nil
}

// Load downloads and prepares a Bundle for location.
func Load(ctx context.Context, location string) (*Bundle, error) {
	raw, err := Download(ctx, location)
	if err != nil {
		return nil, err
	}
	b, err := Prepare(raw)
	if err != nil {
		return nil, err
	}
	b.Location = location
	b.URL = AssetURL(location)
	return b, nil
}

// Prepare runs patching + wrapping on raw hsw.js bytes.
func Prepare(raw []byte) (*Bundle, error) {
	src := string(raw)

	// Neutralize feature tests that assume a real browser DOM:
	//  - navigator.language read inside a property name expression
	//  - instanceof Window fails for our plain-object window
	//  - instanceof PerformanceResourceTiming is false for our shim metrics
	src = strings.ReplaceAll(src, "J(I).language", `"en-US"`)
	src = strings.ReplaceAll(src, "instanceof Window", "instanceof Object")
	src = strings.ReplaceAll(src, "instanceof PerformanceResourceTiming", "instanceof Object")

	// Detect the export binding so the appended export line matches reality.
	exportLine := "module.exports = hsw;"
	version := "unknown"
	switch {
	case reWindowHSW.MatchString(src):
		version = "v1"
		exportLine = "module.exports = window.hsw;"
	case strings.Contains(src, "module.exports"):
		version = "v2-node"
		exportLine = ""
	case strings.Contains(src, "__wbg_") || strings.Contains(src, "wasm-bindgen"):
		version = "v2"
	}

	// Embedded v2 wasm (fetch-mock target). v1 assembles its wasm from
	// several atob() chunks, so nothing to extract there.
	wasm64 := ""
	if m := reEmbeddedWasm.FindStringSubmatch(src); len(m) == 2 {
		wasm64 = m[1]
	} else if m := reDataWasm.FindStringSubmatch(src); len(m) == 2 {
		wasm64 = m[1]
	}

	// v8go's V8 never settles the Promise form of WebAssembly.instantiate
	// (resolution is posted to the embedder task runner, which v8go does not
	// pump). v1 bundles gate all solving on that promise, so convert it to the
	// synchronous Module/Instance constructors, which v8go fully supports.
	synced := 0
	src, synced = syncWasmInstantiate(src)
	if synced == 0 {
		// Older v1 shapes: instantiate without a then-callback.
		src, _ = syncWasmInstantiateBare(src)
	}

	b := &Bundle{
		Version: version,
		WasmB64: wasm64,
	}
	b.Source = buildShim(wasm64) + "\n" + src + "\n" + exportLine
	return b, nil
}

// reInstantiateThen matches the promise-based wasm instantiate call found in
// v1 bundles. hCaptcha renames the local variables between bundle releases
// (e.g. "Lc=WebAssembly.instantiate(vv,afs).then(function(vv){ajz(vv)})" and
// "NN=WebAssembly.instantiate(cl,_l).then(function(cl){xL(cl)})"), so the
// rewrite is shape-based rather than byte-identical:
//
//	X = WebAssembly.instantiate(bytes, imports).then(function(cb){fn(cb)})
var reInstantiateThen = regexp.MustCompile(
	`([A-Za-z0-9_$]+)=WebAssembly\.instantiate\(([A-Za-z0-9_$]+),([A-Za-z0-9_$]+)\)\.then\(function\(([A-Za-z0-9_$]+)\)\{([A-Za-z0-9_$]+)\([A-Za-z0-9_$]+\)\}\)`)

// reInstantiateBare matches the same call without the .then callback.
var reInstantiateBare = regexp.MustCompile(
	`([A-Za-z0-9_$]+)=WebAssembly\.instantiate\(([A-Za-z0-9_$]+),([A-Za-z0-9_$]+)\)`)

// syncWasmInstantiate rewrites the promise-based instantiate call found in v1
// bundles into a synchronous Module + Instance pair wrapped in an already
// resolved Promise, preserving the {module, instance} shape that the original
// then-callback receives. Reports whether the rewrite applied.
//
// The rewrite also injects a byte-patch pass over the assembled wasm image
// before instantiation (see wasmTrapPatchJS for what it neutralizes and why).
func syncWasmInstantiate(src string) (out string, count int) {
	m := reInstantiateThen.FindStringSubmatch(src)
	if m == nil {
		return src, 0
	}
	repl := m[1] + `=(function(){` + wasmTrapPatchJS(m[2]) +
		`var __m=new WebAssembly.Module(` + m[2] +
		`);var __i=new WebAssembly.Instance(__m,` + m[3] +
		`);var __r={module:__m,instance:__i};queueMicrotask(function(){` + m[5] +
		`(__r)});return Promise.resolve(__r)})()`
	return strings.ReplaceAll(src, m[0], repl), 1
}

// wasmTrapPatchJS returns JavaScript that scans the assembled v1 wasm image
// (the Uint8Array named by bytesVar) and neutralizes the environment-check
// abort sites introduced by the 2026-11 hsw.js release.
//
// That release gates the PoW behind a wasm state machine whose branch runs an
// environment probe; in headless runtimes (v8go, plain Node) the probe takes
// an "impossible state" branch and the machine traps on an `unreachable`
// instruction (RuntimeError: unreachable), leaving the solve promise pending
// forever. In a real browser the probe passes and the machine continues past
// the same instruction.
//
// The abort sites compile to a distinctive 18-byte shape:
//
//	41 84 08       i32.const 1028        ; heap-object sentinel compare
//	4f             i32.ge_u
//	04 7f          if (result i32)
//	41 ??          i32.const <state A>
//	05             else
//	41 ??          i32.const <state B>
//	0b             end
//	21 01          local.set 1           ; next state machine state
//	0c ??          br <depth>            ; loop back edge
//	0b             end
//	00             unreachable           ; <- trap target
//
// Each match's trailing `unreachable` (opcode 0x00) is rewritten to `nop`
// (0x01): the fall-through then re-enters the state machine exactly as it
// would after the probe passes in a browser. Both are single-byte opcodes, so
// the image length and every other offset are preserved. The scan is
// idempotent (patched bytes no longer match) and silently patches zero sites
// if a future bundle changes the shape, in which case behavior falls back to
// the pre-patch (broken) solve rather than corrupting anything.
//
// Scanning 1MB of Uint8Array in JS costs single-digit milliseconds, well
// under one solve's PoW time, and runs only inside apM's one-shot
// (if !ke) init block.
func wasmTrapPatchJS(bytesVar string) string {
	// Byte constants kept in decimal to avoid escapes in the embedded JS.
	const (
		bI32Const = 65  // 0x41
		bSentinel = 132 // 0x84 low byte of 1028
		bSentHi   = 8   // 0x08 high byte of 1028
		bGeU      = 79  // 0x4f i32.ge_u
		bIf       = 4   // 0x04
		bI32Res   = 127 // 0x7f i32
		bElse     = 5   // 0x05
		bEnd      = 11  // 0x0b
		bLocalSet = 33  // 0x21
		bLocal1   = 1   // local index 1
		bBr       = 12  // 0x0c
		bUnreach  = 0   // 0x00
		bNop      = 1   // 0x01
	)
	return `try{for(var __po=0;__po+17<` + bytesVar + `.length;__po++){` +
		`if(` + bytesVar + `[__po+17]==` + strconv.Itoa(bUnreach) +
		`&&` + bytesVar + `[__po]==` + strconv.Itoa(bI32Const) +
		`&&` + bytesVar + `[__po+1]==` + strconv.Itoa(bSentinel) +
		`&&` + bytesVar + `[__po+2]==` + strconv.Itoa(bSentHi) +
		`&&` + bytesVar + `[__po+3]==` + strconv.Itoa(bGeU) +
		`&&` + bytesVar + `[__po+4]==` + strconv.Itoa(bIf) +
		`&&` + bytesVar + `[__po+5]==` + strconv.Itoa(bI32Res) +
		`&&` + bytesVar + `[__po+6]==` + strconv.Itoa(bI32Const) +
		`&&` + bytesVar + `[__po+8]==` + strconv.Itoa(bElse) +
		`&&` + bytesVar + `[__po+9]==` + strconv.Itoa(bI32Const) +
		`&&` + bytesVar + `[__po+11]==` + strconv.Itoa(bEnd) +
		`&&` + bytesVar + `[__po+12]==` + strconv.Itoa(bLocalSet) +
		`&&` + bytesVar + `[__po+13]==` + strconv.Itoa(bLocal1) +
		`&&` + bytesVar + `[__po+14]==` + strconv.Itoa(bBr) +
		`&&` + bytesVar + `[__po+16]==` + strconv.Itoa(bEnd) +
		`){` + bytesVar + `[__po+17]=` + strconv.Itoa(bNop) + `}}}catch(__pe){}`
}

// syncWasmInstantiateBare handles the no-then variant.
func syncWasmInstantiateBare(src string) (out string, count int) {
	m := reInstantiateBare.FindStringSubmatch(src)
	if m == nil {
		return src, 0
	}
	repl := m[1] + `=(function(){var __m=new WebAssembly.Module(` + m[2] +
		`);var __i=new WebAssembly.Instance(__m,` + m[3] +
		`);return Promise.resolve({module:__m,instance:__i})})()`
	return strings.ReplaceAll(src, m[0], repl), 1
}

// CloseBody closes c after the body has been consumed or is being discarded;
// a close failure has no effect on the data already read.
func CloseBody(c io.Closer) {
	if err := c.Close(); err != nil {
		_ = err
	}
}
