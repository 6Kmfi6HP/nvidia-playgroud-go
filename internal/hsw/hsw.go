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

	// poolInterval caps how long one wait-for-promise iteration sleeps between
	// V8 microtask checkpoints. The wait backs off from spin to this cap so a
	// fast-resolving promise (the common case) is noticed within microseconds
	// while a stuck one does not burn CPU.
	poolInterval  = 5 * time.Millisecond
	spinInterval  = 50 * time.Microsecond
	backoffFactor = 2
)

// Solver encapsulates an isolate running a prepared hsw bundle.
type Solver struct {
	mu       sync.Mutex
	bundle   *Bundle
	iso      *v8.Isolate
	vctx     *v8.Context
	global   *v8.Object // cached context global (v8go allocates a tracked value per Global() call)
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

	// Hold the global object handle for the solver's lifetime: every v8go
	// Global() call registers a new tracked value in the context, so
	// re-fetching it per solve leaks one handle per call.
	global := s.vctx.Global()
	s.global = global

	modVal, err := global.Get("module")
	if err != nil {
		return fmt.Errorf("hsw: module lookup: %w", err)
	}
	defer modVal.Release()
	if !modVal.IsObject() {
		return fmt.Errorf("hsw: module is not an object: %w", err)
	}
	exportsVal, err := modVal.Object().Get("exports")
	if err != nil {
		return fmt.Errorf("hsw: module.exports lookup: %w", err)
	}
	if exportsVal.IsUndefined() {
		exportsVal.Release()
		return fmt.Errorf("hsw: module.exports is undefined (bundle variant %q unsupported?)", s.bundle.Version)
	}
	if !exportsVal.IsFunction() {
		exportsVal.Release()
		return fmt.Errorf("hsw: module.exports is not a function (variant %q)", s.bundle.Version)
	}
	// AsFunction aliases the same underlying handle as exportsVal: the
	// handle's ownership transfers to s.fnSolve (released in Close), so
	// exportsVal itself must not be released here.
	s.fnSolve = &v8.Function{Value: exportsVal}

	fnCryptoVal, err := s.vctx.RunScript(hccryptoAdapter, "hccrypto-adapter.js")
	if err != nil {
		// The crypto adapter is optional; the solve path still works.
		return nil
	}
	if !fnCryptoVal.IsFunction() {
		fnCryptoVal.Release()
		return nil
	}
	// Same aliasing rule: the handle moves into s.fnCrypto.
	s.fnCrypto = &v8.Function{Value: fnCryptoVal}
	return nil
}

// Close releases the underlying V8 context and isolate.
func (s *Solver) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.fnSolve != nil {
		s.fnSolve.Release()
		s.fnSolve = nil
	}
	if s.fnCrypto != nil {
		s.fnCrypto.Release()
		s.fnCrypto = nil
	}
	if s.global != nil {
		s.global.Release()
		s.global = nil
	}
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
//
// Every v8go value created here (arguments, call result, promise result) is
// registered in the context's tracked-value table and kept alive until
// explicitly released. On a long-lived cached Solver an unreleased value is a
// permanent V8-heap leak, so all values are released before returning.
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
	defer jwtVal.Release()
	fpVal, err := v8.NewValue(s.iso, fpB64)
	if err != nil {
		return "", fmt.Errorf("hsw: fingerprint arg: %w", err)
	}
	defer fpVal.Release()

	res, err := s.fnSolve.Call(s.global, jwtVal, fpVal)
	if err != nil {
		return "", fmt.Errorf("hsw: call module.exports: %w", jsErr(err))
	}
	defer res.Release()

	if !res.IsPromise() {
		// Non-promise variants that resolve synchronously return the n string.
		return res.String(), nil
	}
	p, err := res.AsPromise()
	if err != nil {
		return "", fmt.Errorf("hsw: result is not a promise: %w", err)
	}

	if p.State() == v8.Pending {
		s.vctx.PerformMicrotaskCheckpoint()
	}

	if p.State() == v8.Pending {
		timer := time.NewTimer(spinInterval)
		defer timer.Stop()
		wait := spinInterval
		for p.State() == v8.Pending {
			if deadline.Err() != nil {
				return "", fmt.Errorf("hsw: solve timed out after %s", DefaultSolveTimeout)
			}
			s.vctx.PerformMicrotaskCheckpoint()
			if p.State() == v8.Pending {
				select {
				case <-deadline.Done():
				case <-timer.C:
					wait *= backoffFactor
					if wait > poolInterval {
						wait = poolInterval
					}
					timer.Reset(wait)
				}
			}
		}
	}

	resultVal := p.Result()
	defer resultVal.Release()
	if p.State() == v8.Fulfilled {
		return resultVal.String(), nil
	}

	// Rejected: surface the JS error's message if available.
	msg := resultVal.String()
	if resultVal.IsObject() {
		if m, e := resultVal.Object().Get("message"); e == nil && !m.IsUndefined() {
			msg = m.String()
			m.Release()
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
	defer modeVal.Release()
	dataVal, err := v8.NewValue(s.iso, base64.StdEncoding.EncodeToString(data))
	if err != nil {
		return nil, fmt.Errorf("hsw: crypto data arg: %w", err)
	}
	defer dataVal.Release()

	res, err := s.fnCrypto.Call(s.global, modeVal, dataVal)
	if err != nil {
		return nil, fmt.Errorf("hsw: call crypto mode %d: %w", mode, jsErr(err))
	}
	defer res.Release()
	if !res.IsPromise() {
		return nil, fmt.Errorf("hsw: crypto mode %d did not return a promise", mode)
	}
	p, err := res.AsPromise()
	if err != nil {
		return nil, fmt.Errorf("hsw: crypto result is not a promise: %w", err)
	}

	if p.State() == v8.Pending {
		s.vctx.PerformMicrotaskCheckpoint()
	}

	if p.State() == v8.Pending {
		timer := time.NewTimer(spinInterval)
		defer timer.Stop()
		wait := spinInterval
		for p.State() == v8.Pending {
			if deadline.Err() != nil {
				return nil, fmt.Errorf("hsw: crypto mode %d timed out after %s", mode, DefaultSolveTimeout)
			}
			s.vctx.PerformMicrotaskCheckpoint()
			if p.State() == v8.Pending {
				select {
				case <-deadline.Done():
				case <-timer.C:
					wait *= backoffFactor
					if wait > poolInterval {
						wait = poolInterval
					}
					timer.Reset(wait)
				}
			}
		}
	}

	resultVal := p.Result()
	defer resultVal.Release()

	if p.State() == v8.Rejected {
		msg := resultVal.String()
		if resultVal.IsObject() {
			if m, e := resultVal.Object().Get("message"); e == nil && !m.IsUndefined() {
				msg = m.String()
				m.Release()
			}
		}
		return nil, fmt.Errorf("hsw: crypto mode %d rejected: %s", mode, msg)
	}

	b64 := resultVal.String()
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
	// deferredRelease holds the previous callback return value. v8go's C++
	// glue reads the returned handle after the Go callback returns, so a
	// value cannot be released in the call that produced it; releasing the
	// previous one instead bounds the leak to one handle per function.
	var atobPrev, btoaPrev *v8.Value

	atob := v8.NewFunctionTemplateWithError(iso, func(info *v8.FunctionCallbackInfo) (*v8.Value, error) {
		// this/args are copied into the C++ glue before the callback runs;
		// releasing them here is safe and prevents per-call handle leaks.
		defer info.Release()
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
		val, err := v8.NewValue(iso, latin1ToUTF8(raw))
		if err != nil {
			return nil, fmt.Errorf("atob: %w", err)
		}
		if atobPrev != nil {
			atobPrev.Release()
		}
		atobPrev = val
		return val, nil
	})
	if err := ctx.Global().Set("atob", atob.GetFunction(ctx)); err != nil {
		return err
	}

	btoa := v8.NewFunctionTemplateWithError(iso, func(info *v8.FunctionCallbackInfo) (*v8.Value, error) {
		defer info.Release()
		s := ""
		if len(info.Args()) > 0 && !info.Args()[0].IsUndefined() && !info.Args()[0].IsNull() {
			s = info.Args()[0].String()
		}
		raw, err := fromBinaryString(s)
		if err != nil {
			return nil, fmt.Errorf("btoa: %w", err)
		}
		val, err := v8.NewValue(iso, base64.StdEncoding.EncodeToString(raw))
		if err != nil {
			return nil, fmt.Errorf("btoa: %w", err)
		}
		if btoaPrev != nil {
			btoaPrev.Release()
		}
		btoaPrev = val
		return val, nil
	})
	return ctx.Global().Set("btoa", btoa.GetFunction(ctx))
}

// latin1ToUTF8 maps latin-1 bytes (0..255) to a UTF-8 string whose rune values
// match each input byte, the representation v8.NewValue expects.
func latin1ToUTF8(raw []byte) string {
	ascii := true
	for _, b := range raw {
		if b >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return string(raw)
	}
	buf := make([]byte, 0, len(raw)*2)
	for _, b := range raw {
		if b < 0x80 {
			buf = append(buf, b)
		} else {
			buf = append(buf, 0xC0|(b>>6), 0x80|(b&0x3F))
		}
	}
	return string(buf)
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

// HeapStats returns the isolate's current V8 heap statistics. Diagnostic only;
// callers must not hold SolveN/Crypto results across calls.
func (s *Solver) HeapStats() v8.HeapStatistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.iso == nil {
		return v8.HeapStatistics{}
	}
	return s.iso.GetHeapStatistics()
}

// RetainedValueCount returns how many v8go values are currently pinned by the
// solver's context. Values accumulate when callers forget Release; the number
// is a leak indicator.
func (s *Solver) RetainedValueCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vctx == nil {
		return 0
	}
	return s.vctx.RetainedValueCount()
}
