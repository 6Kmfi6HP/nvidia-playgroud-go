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
	// DefaultSolveTimeout bounds one hsw solve (wasm PoW can be slow).
	DefaultSolveTimeout = 60 * time.Second

	poolInterval = 2 * time.Millisecond
)

// Solver owns a V8 isolate and executes hsw bundles on demand.
// An isolate is single-threaded: SolveN serializes access with a mutex.
type Solver struct {
	mu     sync.Mutex
	iso    *v8.Isolate
	bundle *Bundle
}

// New creates a Solver from a prepared bundle. The isolate is created lazily
// on first use so tests that only exercise Prepare never pay the cgo cost.
func New(b *Bundle) (*Solver, error) {
	if b == nil || b.Source == "" {
		return nil, fmt.Errorf("hsw: empty bundle")
	}
	return &Solver{bundle: b}, nil
}

// LoadSolver downloads, patches and wraps hsw.js for location, then returns a
// ready-to-use Solver.
func LoadSolver(ctx context.Context, location string) (*Solver, error) {
	b, err := Load(ctx, location)
	if err != nil {
		return nil, err
	}
	return New(b)
}

// Close disposes the V8 isolate, releasing its memory. Safe to call multiple
// times; no-op before the isolate was created.
func (s *Solver) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.iso != nil {
		s.iso.Dispose()
		s.iso = nil
	}
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
	if s.iso == nil {
		s.iso = v8.NewIsolate()
	}

	deadline, cancel := context.WithTimeout(ctx, DefaultSolveTimeout)
	defer cancel()

	vctx := v8.NewContext(s.iso)
	defer vctx.Close()

	if err := injectBase64(vctx, s.iso); err != nil {
		return "", fmt.Errorf("hsw: inject atob/btoa: %w", err)
	}

	name := "hsw.js"
	if s.bundle.Location != "" {
		name = s.bundle.Location + "/hsw.js"
	}
	if _, err := vctx.RunScript(s.bundle.Source, name); err != nil {
		return "", fmt.Errorf("hsw: eval %s: %w", name, jsErr(err))
	}

	modVal, err := vctx.Global().Get("module")
	if err != nil {
		return "", fmt.Errorf("hsw: module lookup: %w", err)
	}
	modObj, err := modVal.AsObject()
	if err != nil {
		return "", fmt.Errorf("hsw: module is not an object: %w", err)
	}
	exportsVal, err := modObj.Get("exports")
	if err != nil {
		return "", fmt.Errorf("hsw: module.exports lookup: %w", err)
	}
	if exportsVal.IsUndefined() || exportsVal.IsNull() {
		return "", fmt.Errorf("hsw: module.exports is undefined (bundle variant %q unsupported?)", s.bundle.Version)
	}
	fn, err := exportsVal.AsFunction()
	if err != nil {
		return "", fmt.Errorf("hsw: module.exports is not a function (variant %q): %w", s.bundle.Version, err)
	}

	jwtVal, err := v8.NewValue(s.iso, jwt)
	if err != nil {
		return "", fmt.Errorf("hsw: jwt arg: %w", err)
	}
	fpVal, err := v8.NewValue(s.iso, fpB64)
	if err != nil {
		return "", fmt.Errorf("hsw: fingerprint arg: %w", err)
	}

	res, err := fn.Call(vctx.Global(), jwtVal, fpVal)
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
		vctx.PerformMicrotaskCheckpoint()
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
    if (u8 && u8.buffer instanceof ArrayBuffer && !(u8 instanceof Uint8Array)) {
      u8 = new Uint8Array(u8.buffer, u8.byteOffset, u8.byteLength);
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
	if s.iso == nil {
		s.iso = v8.NewIsolate()
	}
	deadline, cancel := context.WithTimeout(ctx, DefaultSolveTimeout)
	defer cancel()

	vctx := v8.NewContext(s.iso)
	defer vctx.Close()

	if err := injectBase64(vctx, s.iso); err != nil {
		return nil, fmt.Errorf("hsw: inject atob/btoa: %w", err)
	}
	name := "hsw.js"
	if s.bundle.Location != "" {
		name = s.bundle.Location + "/hsw.js"
	}
	if _, err := vctx.RunScript(s.bundle.Source, name); err != nil {
		return nil, fmt.Errorf("hsw: eval %s: %w", name, jsErr(err))
	}
	fnVal, err := vctx.RunScript(hccryptoAdapter, "hccrypto-adapter.js")
	if err != nil {
		return nil, fmt.Errorf("hsw: eval crypto adapter: %w", err)
	}
	fn, err := fnVal.AsFunction()
	if err != nil {
		return nil, fmt.Errorf("hsw: crypto adapter is not a function: %w", err)
	}
	modeVal, err := v8.NewValue(s.iso, int32(mode))
	if err != nil {
		return nil, fmt.Errorf("hsw: crypto mode arg: %w", err)
	}
	dataVal, err := v8.NewValue(s.iso, base64.StdEncoding.EncodeToString(data))
	if err != nil {
		return nil, fmt.Errorf("hsw: crypto data arg: %w", err)
	}
	res, err := fn.Call(vctx.Global(), modeVal, dataVal)
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
		vctx.PerformMicrotaskCheckpoint()
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
		if len(info.Args()) > 0 {
			s = info.Args()[0].String()
		}
		dec, err := lenientBase64Decode(s)
		if err != nil {
			return nil, fmt.Errorf("atob: %w", err)
		}
		return v8.NewValue(iso, binaryString(dec))
	})
	btoa := v8.NewFunctionTemplateWithError(iso, func(info *v8.FunctionCallbackInfo) (*v8.Value, error) {
		if len(info.Args()) < 1 {
			return v8.NewValue(iso, "")
		}
		b, err := fromBinaryString(info.Args()[0].String())
		if err != nil {
			return nil, fmt.Errorf("btoa: %w", err)
		}
		return v8.NewValue(iso, base64.StdEncoding.EncodeToString(b))
	})

	if err := ctx.Global().Set("atob", atob.GetFunction(ctx)); err != nil {
		return err
	}
	return ctx.Global().Set("btoa", btoa.GetFunction(ctx))
}

// lenientBase64Decode decodes base64 accepting whitespace, missing padding
// and the url-safe alphabet's - and _ characters.
func lenientBase64Decode(s string) ([]byte, error) {
	t := s
	// Drop whitespace.
	clean := make([]byte, 0, len(t))
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '-':
			clean = append(clean, '+')
		case '_':
			clean = append(clean, '/')
		default:
			clean = append(clean, c)
		}
	}
	// Drop padding (we re-add later if needed).
	for len(clean) > 0 && clean[len(clean)-1] == '=' {
		clean = clean[:len(clean)-1]
	}
	if len(clean)%4 == 1 {
		return nil, fmt.Errorf("invalid base64 length")
	}
	b, err := base64.RawStdEncoding.DecodeString(string(clean))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// binaryString converts decoded bytes into a Go string that v8go maps back to
// a JS string with charCodeAt(i) == byte i. v8go treats Go strings as UTF-8,
// so naive string(dec) corrupts every byte >= 0x80 into U+FFFD; encoding each
// byte as its own rune (U+0000..U+00FF) round-trips exactly.
func binaryString(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

// fromBinaryString reverses binaryString: each JS char (rune) is a byte.
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
