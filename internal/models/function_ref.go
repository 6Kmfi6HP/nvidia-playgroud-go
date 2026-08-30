package models

// Per-request NVCF function-id targeting.
//
// Every playground model resolves to one predict endpoint
// (namespace/slug) plus one nv-function-id header value. NVIDIA aliases
// several backend versions onto a single slug, so the same endpoint can be
// served by more than one NVCF function. Two inbound forms pin the function
// explicitly instead of taking the registry value:
//
//	{"model": "<function-id>@<publisher>/<slug>"}   body pin
//	nv-function-id: <function-id>                   header pin
//
// The body form keeps the model id readable and travels with the payload
// (useful for curl one-offs and for clients that cannot set headers); the
// header form leaves the model id untouched. When both are present the body
// pin wins, because it names the endpoint in the same place the model is
// chosen.
//
// SplitFunctionRef/ValidateFunctionRef are shared by the gateway middleware
// (which normalizes the body pin into the header before model routing) and
// the provider executor (which applies the pin to the resolved ModelInfo).
//
// A pinned model the registry does not list is still callable: NVIDIA serves
// functions that never appear in the playground catalog (no playground page,
// but the predict backend answers when the namespace/slug/function-id triple
// is known). SynthesizeFunctionRef builds the invocation data for those, so a
// pin can reach any NVCF function behind the shared namespace.

import (
	"fmt"
	"strings"
)

// FunctionRefSeparator separates a pinned function id from the model id in
// the "<function-id>@<model-id>" request form. Model ids never contain it,
// so the first occurrence is the split point.
const FunctionRefSeparator = "@"

// MaxFunctionIDLen bounds a pinned function id. NVCF ids are 36-char UUIDs;
// the slack covers ids NVIDIA may hand out in another shape.
const MaxFunctionIDLen = 128

// SplitFunctionRef splits an optional function-id pin off a model id.
// hasPin is true when the separator is present; pin and base are the trimmed
// halves and either may be empty for malformed input, which
// ValidateFunctionRef reports. Without a separator pin is "" and base is
// model unchanged.
func SplitFunctionRef(model string) (pin, base string, hasPin bool) {
	i := strings.Index(model, FunctionRefSeparator)
	if i < 0 {
		return "", model, false
	}
	return strings.TrimSpace(model[:i]), strings.TrimSpace(model[i+1:]), true
}

// ValidFunctionID reports whether id is safe to send as the nv-function-id
// header value: non-empty, bounded, and limited to characters that appear in
// NVCF ids (so header injection and quoting surprises are impossible).
func ValidFunctionID(id string) bool {
	if id == "" || len(id) > MaxFunctionIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return true
}

// ValidateFunctionRef checks the two halves of a split "<pin>@<base>" model
// id. It is the caller-facing form of ValidFunctionRef: it names the offending
// piece so the gateway can return one actionable 400.
func ValidateFunctionRef(pin, base string) error {
	if !ValidFunctionID(pin) {
		return InvalidFunctionIDError(pin)
	}
	if base == "" {
		return fmt.Errorf("missing model id after %q in the model field", FunctionRefSeparator)
	}
	return nil
}

// InvalidFunctionIDError is the shared 400 text for a rejected function id,
// whether it arrived in a model field or in the nv-function-id header.
func InvalidFunctionIDError(id string) error {
	return fmt.Errorf("invalid nv-function-id %q: use 1-%d characters from [A-Za-z0-9._-]", id, MaxFunctionIDLen)
}

// LookupPinned resolves a model id that may carry a "<function-id>@" pin. It
// returns the invocation data (registry values with a pinned FunctionID
// applied) and the canonical registry model id to send upstream, so callers
// can strip the pin from the request body.
func LookupPinned(model string) (info ModelInfo, canonical string, err error) {
	pin, base, hasPin := SplitFunctionRef(model)
	if hasPin {
		if err := ValidateFunctionRef(pin, base); err != nil {
			return ModelInfo{}, "", err
		}
		model = base
	}
	info, err = Lookup(model)
	if err != nil {
		return ModelInfo{}, "", err
	}
	if hasPin {
		info.FunctionID = pin
	}
	return info, model, nil
}

// SynthesizeFunctionRef builds invocation data for a pinned target the
// registry does not list. slugRef may be "<publisher>/<slug>" or the bare
// slug; only the last segment is used in the predict URL. An empty namespace
// falls back to Namespace (every known playground function shares it).
// Capability stays zero: unlisted endpoints get no thinking/vision hints
// until someone verifies them.
func SynthesizeFunctionRef(pin, slugRef, namespace string) ModelInfo {
	slug := slugRef
	if i := strings.LastIndex(slugRef, "/"); i >= 0 {
		slug = slugRef[i+1:]
	}
	if namespace == "" {
		namespace = Namespace
	}
	return ModelInfo{Slug: slug, Namespace: namespace, FunctionID: pin}
}

// ValidSlugRef reports whether ref can name a predict slug: non-empty and
// free of characters that would corrupt the URL path or the JSON body model
// field (whitespace, '@', quotes, control chars). "<publisher>/<slug>" form
// is allowed; the slash is the only separator.
func ValidSlugRef(ref string) bool {
	if ref == "" || len(ref) > 256 {
		return false
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == '/':
		default:
			return false
		}
	}
	return true
}
