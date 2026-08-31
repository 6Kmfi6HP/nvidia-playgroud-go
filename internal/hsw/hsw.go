// Package hsw runs hCaptcha's hsw proof-of-work inside an embedded V8
// (v8go) isolate.
//
// The hsw.js bundle is downloaded from newassets.hcaptcha.com (see fetch.go),
// patched and wrapped with a minimal browser shim (see shimjs.go), then
// executed as module.exports(jwt, fingerprintBase64), which returns a Promise
// resolving to the proof-of-work value n.
//
// v1 bundles (window.hsw) are self-contained: they assemble a WASM module
// from atob() chunks and call WebAssembly.instantiate directly. v2 bundles
// are wasm-bindgen output that go through the shim's fetch mock. Both are
// resolved by draining V8's microtask queue with PerformMicrotaskCheckpoint.
package hsw

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	v8 "github.com/tommie/v8go"
)

const (
	// DefaultSolveTimeout bounds how long a single SolveN/Crypto execution
	// may wait for V8 promise fulfillment before giving up.
	DefaultSolveTimeout = 10 * time.Second

	// poolInterval is how frequently we yield the Go runtime between V8
	// microtask checkpoints while waiting for promise fulfillment.
	poolInterval = 5 * time.Millisecond
)

// Solver encapsulates an isolate running a prepared hsw bundle.
type Solver struct {
	mu       sync.Mutex
	bundle   *Bundle
	iso      *v8.Isolate
	vctx     *v8.Context
	fnSolve  *v8.Function
	fnCrypto *v8.Function
}

// New constructs a Solver from a prepared Bundle. The V8 isolate and context
// are initialized and the bundle evaluated once so that subsequent calls to
// SolveN and Crypto execute directly against pre-compiled function exports.
func New(b *Bundle) (*Solver, error) {
	if b == nil || b.Source == "" {
		return nil, fmt.Errorf("hsw: empty bundle")
	}
	s := &Solver{
		bundle: b,
	}
	if err := s.init(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// init initializes the persistent V8 isolate, context, and pre-resolves exported functions.
func (s *Solver) init() error {
	if s.iso != nil && s.vctx != nil && s.fnSolve != nil {
		return nil
	}

	if s.iso == nil {
		s.iso = v8.NewIsolate()
	}
	if s.vctx == nil {
		s.vctx = v8.NewContext(s.iso)
	}

	if err := injectBase64(s.vctx, s.iso); err != nil {
		return fmt.Errorf("hsw: inject atob/btoa: %w", err)
	}

	name := s.bundle.Location
	if name == "" {
		name = "hsw.js"
	}
	if _, err := s.vctx.RunScript(s.bundle.Source, name); err != nil {
		return fmt.Errorf("hsw: eval %s: %w", name, jsErr(err))
	}

	modVal, err := s.vctx.Global().Get("module")
	if err != nil {
		return fmt.Errorf("hsw: module lookup: %w", err)
	}
	if !modVal.IsObject() {
		return fmt.Errorf("hsw: module is not an object: %w", err)
	}
	exportsVal, err := modVal.Object().Get("exports")
	if err != nil {
		return fmt.Errorf("hsw: module.exports lookup: %w", err)
	}
	if exportsVal.IsUndefined() {
		return fmt.Errorf("hsw: module.exports is undefined (bundle variant %q unsupported?)", s.bundle.Version)
	}
	fnSolve, err := exportsVal.AsFunction()
	if err != nil {
		return fmt.Errorf("hsw: module.exports is not a function (variant %q): %w", s.bundle.Version, err)
	}
	s.fnSolve = fnSolve

	fnCryptoVal, err := s.vctx.RunScript(hccryptoAdapter, "hccrypto-adapter.js")
	if err == nil && fnCryptoVal.IsFunction() {
		s.fnCrypto, _ = fnCryptoVal.AsFunction()
	}
	return nil
}

// Close releases the underlying V8 context and isolate.
func (s *Solver) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.fnSolve = nil
	s.fnCrypto = nil
	if s.vctx != nil {
		s.vctx.Close()
		s.vctx = nil
	}
	if s.iso != nil {
		s.iso.Close()
		s.iso = nil
	}
}

// LoadSolver downloads, prepares, and instantiates a Solver for location.
func LoadSolver(ctx context.Context, location string) (*Solver, error) {
	b, err := Load(ctx, location)
	if err != nil {
		return nil, err
	}
	return New(b)
}

// SolveN runs module.exports(jwt, fpB64) and returns the resolved n.
// The caller-provided context is honored for cancellation; a hard timeout of
// DefaultSolveTimeout always applies.
func (s *Solver) SolveN(ctx context.Context, jwt, fpB64 string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.bundle == nil || s.bundle.Source == "" {
		return "", fmt.Errorf("hsw: empty bundle")
	}
	if s.vctx == nil || s.fnSolve == nil {
		if err := s.init(); err != nil {
			return "", err
		}
	}

	deadline, cancel := context.WithTimeout(ctx, DefaultSolveTimeout)
	defer cancel()

	jwtVal, err := v8.NewValue(s.iso, jwt)
	if err != nil {
		return "", fmt.Errorf("hsw: jwt arg: %w", err)
	}
	fpVal, err := v8.NewValue(s.iso, fpB64)
	if err != nil {
		return "", fmt.Errorf("hsw: fingerprint arg: %w", err)
	}

	res, err := s.fnSolve.Call(s.vctx.Global(), jwtVal, fpVal)
	if err != nil {
		return "", fmt.Errorf("hsw: call module.exports: %w", jsErr(err))
	}

	if !res.IsPromise() {
		// Non-promise variants that resolve synchronously return the n string.
		return res.String(), nil
	}
	p, err := res.AsPromise()
	if err != nil {
		return "", fmt.Errorf("hsw: result is not a promise: %w", err)
	}

	for p.State() == v8.Pending {
		if deadline.Err() != nil {
			return "", fmt.Errorf("hsw: solve timed out after %s", DefaultSolveTimeout)
		}
		s.vctx.PerformMicrotaskCheckpoint()
		if p.State() == v8.Pending {
			select {
			case <-deadline.Done():
			case <-time.After(poolInterval):
			}
		}
	}

	if p.State() == v8.Fulfilled {
		return p.Result().String(), nil
	}

	// Rejected: surface the JS error's message if available.
	errVal := p.Result()
	msg := errVal.String()
	if errVal.IsObject() {
		if m, e := errVal.Object().Get("message"); e == nil && !m.IsUndefined() {
			msg = m.String()
		}
	}
	return "", fmt.Errorf("hsw: solve rejected: %s", msg)
}

// hccryptoAdapter wraps window.hsw's crypto modes (1 = encrypt, 0 = decrypt)
// behind a base64-string interface so Go never has to build typed arrays: the
// input arrives as base64, is turned into a Uint8Array with the native atob,
// handed to hsw, and the resolved bytes are base64-encoded back.
const hccryptoAdapter = `
(function () {
  if (window.__hccrypto) return window.__hccrypto;
  function b64ToBytes(b64) {
    var bin = atob(b64);
    var u = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }
  function bytesToB64(u8) {
    if (!u8 || typeof u8.length !== "number") {
      return btoa(String(u8 || ""));
    }
    var out = [];
    for (var i = 0; i < u8.length; i += 0x8000) {
      out.push(String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)));
    }
    return btoa(out.join(''));
  }
  window.__hccrypto = function (mode, b64) {
    return window.hsw(mode, b64ToBytes(b64)).then(function (r) {
      return bytesToB64(r);
    });
  };
  return window.__hccrypto;
})();
`

// Crypto runs one of the hsw bundle's crypto modes inside the same V8
// isolate: mode 1 encrypts data, mode 0 decrypts it. The bundle's
// window.hsw(1|0, bytes) entry performs AES-style request/response
// encryption with the key embedded in its WASM; Go exchanges bytes as
// base64 through a small JS adapter. Returns the raw result bytes.
func (s *Solver) Crypto(ctx context.Context, mode int, data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.bundle == nil || s.bundle.Source == "" {
		return nil, fmt.Errorf("hsw: empty bundle")
	}
	if s.vctx == nil || s.fnCrypto == nil {
		if err := s.init(); err != nil {
			return nil, err
		}
	}
	if s.fnCrypto == nil {
		return nil, fmt.Errorf("hsw: crypto adapter unavailable")
	}

	deadline, cancel := context.WithTimeout(ctx, DefaultSolveTimeout)
	defer cancel()

	modeVal, err := v8.NewValue(s.iso, int32(mode))
	if err != nil {
		return nil, fmt.Errorf("hsw: crypto mode arg: %w", err)
	}
	dataVal, err := v8.NewValue(s.iso, base64.StdEncoding.EncodeToString(data))
	if err != nil {
		return nil, fmt.Errorf("hsw: crypto data arg: %w", err)
	}

	res, err := s.fnCrypto.Call(s.vctx.Global(), modeVal, dataVal)
	if err != nil {
		return nil, fmt.Errorf("hsw: call crypto mode %d: %w", mode, jsErr(err))
	}
	if !res.IsPromise() {
		return nil, fmt.Errorf("hsw: crypto mode %d did not return a promise", mode)
	}
	p, err := res.AsPromise()
	if err != nil {
		return nil, fmt.Errorf("hsw: crypto result is not a promise: %w", err)
	}

	for p.State() == v8.Pending {
		if deadline.Err() != nil {
			return nil, fmt.Errorf("hsw: crypto mode %d timed out after %s", mode, DefaultSolveTimeout)
		}
		s.vctx.PerformMicrotaskCheckpoint()
		if p.State() == v8.Pending {
			select {
			case <-deadline.Done():
			case <-time.After(poolInterval):
			}
		}
	}

	if p.State() == v8.Rejected {
		errVal := p.Result()
		msg := errVal.String()
		if errVal.IsObject() {
			if m, e := errVal.Object().Get("message"); e == nil && !m.IsUndefined() {
				msg = m.String()
			}
		}
		return nil, fmt.Errorf("hsw: crypto mode %d rejected: %s", mode, msg)
	}

	b64 := p.Result().String()
	return base64.StdEncoding.DecodeString(b64)
}

// injectBase64 installs native atob/btoa on the context global, backed by the
// standard library. The shim's JS fallback stays as a safety net; the native
// versions are used when present.
//
// atob is deliberately lenient: it tolerates whitespace, unpadded input and
// base64url characters (- / _), which hCaptcha tokens and wasm chunks use in
// various combinations.
func injectBase64(ctx *v8.Context, iso *v8.Isolate) error {
	atob := v8.NewFunctionTemplateWithError(iso, func(info *v8.FunctionCallbackInfo) (*v8.Value, error) {
		s := ""
		if len(info.Args()) > 0 && !info.Args()[0].IsUndefined() && !info.Args()[0].IsNull() {
			s = info.Args()[0].String()
		}
		raw, err := lenientBase64Decode(s)
		if err != nil {
			return nil, fmt.Errorf("atob: %w", err)
		}
		// Latin-1 string: JavaScript characters 0..255 matching byte values.
		// v8.NewValue interprets Go strings as UTF-8, so build a UTF-8 string
		// whose rune values match each input byte.
		runes := make([]rune, len(raw))
		for i, b := range raw {
			runes[i] = rune(b)
		}
		return v8.NewValue(iso, string(runes))
	})
	if err := ctx.Global().Set("atob", atob.GetFunction(ctx)); err != nil {
		return err
	}

	btoa := v8.NewFunctionTemplateWithError(iso, func(info *v8.FunctionCallbackInfo) (*v8.Value, error) {
		s := ""
		if len(info.Args()) > 0 && !info.Args()[0].IsUndefined() && !info.Args()[0].IsNull() {
			s = info.Args()[0].String()
		}
		raw, err := fromBinaryString(s)
		if err != nil {
			return nil, fmt.Errorf("btoa: %w", err)
		}
		return v8.NewValue(iso, base64.StdEncoding.EncodeToString(raw))
	})
	return ctx.Global().Set("btoa", btoa.GetFunction(ctx))
}

// lenientBase64Decode strips whitespace and pads missing '=' before decoding.
// Also translates base64url characters (- / _) to standard (+ / /).
func lenientBase64Decode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if rem := len(s) % 4; rem != 0 {
		s += strings.Repeat("=", 4-rem)
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// fromBinaryString maps a JS binary string (where each rune is expected in
// 0..255) back to []byte. Returns an error if any rune is outside that range,
// matching DOMException "InvalidCharacterError".
func fromBinaryString(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xff {
			return nil, fmt.Errorf("character U+%04X out of latin1 range", r)
		}
		out = append(out, byte(r))
	}
	return out, nil
}

// jsErr unwraps a v8go JS error for readable messages.
func jsErr(err error) error {
	if err == nil {
		return nil
	}
	var je *v8.JSError
	if errors.As(err, &je) {
		if je.Message != "" {
			return fmt.Errorf("%s (at %s)", je.Message, je.Location)
		}
	}
	return err
}

// Bundle returns the prepared bundle metadata.
func (s *Solver) Bundle() *Bundle {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bundle
}
