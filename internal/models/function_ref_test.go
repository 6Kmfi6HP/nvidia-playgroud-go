package models

import (
	"errors"
	"strings"
	"testing"
)

func TestSplitFunctionRef(t *testing.T) {
	cases := []struct {
		in     string
		pin    string
		base   string
		hasPin bool
	}{
		{in: "moonshotai/kimi-k3", base: "moonshotai/kimi-k3"},
		{in: "", base: ""},
		{in: "1586112a-925c-48af-8631-7c815dbd749c@moonshotai/kimi-k3", pin: "1586112a-925c-48af-8631-7c815dbd749c", base: "moonshotai/kimi-k3", hasPin: true},
		// A function id never contains "@", so the first one is the split point.
		{in: "fid@pub/deep@weird", pin: "fid", base: "pub/deep@weird", hasPin: true},
		{in: "  fid@pub/slug  ", pin: "fid", base: "pub/slug", hasPin: true},
		{in: "@pub/slug", pin: "", base: "pub/slug", hasPin: true},
		{in: "fid@", pin: "fid", base: "", hasPin: true},
	}
	for _, tc := range cases {
		pin, base, hasPin := SplitFunctionRef(tc.in)
		if pin != tc.pin || base != tc.base || hasPin != tc.hasPin {
			t.Errorf("SplitFunctionRef(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.in, pin, base, hasPin, tc.pin, tc.base, tc.hasPin)
		}
	}
}

func TestValidFunctionID(t *testing.T) {
	ok := []string{
		"1586112a-925c-48af-8631-7c815dbd749c",
		"abc_DEF.123",
		strings.Repeat("a", MaxFunctionIDLen),
	}
	for _, id := range ok {
		if !ValidFunctionID(id) {
			t.Errorf("ValidFunctionID(%q) = false, want true", id)
		}
	}

	bad := []string{
		"",
		" ",
		"has space",
		"a\nb",
		"x\r\nInjected: 1",
		"tab\there",
		"uuid;drop",
		"quote\"id",
		"\u00fcn\u00efcode",
		"UPPER@mixed",
		strings.Repeat("a", MaxFunctionIDLen+1),
	}
	for _, id := range bad {
		if ValidFunctionID(id) {
			t.Errorf("ValidFunctionID(%q) = true, want false", id)
		}
	}
}

func TestValidateFunctionRef(t *testing.T) {
	if err := ValidateFunctionRef("1586112a-925c-48af-8631-7c815dbd749c", "moonshotai/kimi-k3"); err != nil {
		t.Fatalf("valid ref rejected: %v", err)
	}
	if err := ValidateFunctionRef("bad id", "moonshotai/kimi-k3"); err == nil || !strings.Contains(err.Error(), "nv-function-id") {
		t.Fatalf("bad pin error = %v", err)
	}
	if err := ValidateFunctionRef("good-id", ""); err == nil || !strings.Contains(err.Error(), "missing model id") {
		t.Fatalf("empty base error = %v", err)
	}
}

func TestLookupPinned(t *testing.T) {
	reg, err := Lookup(DefaultModel)
	if err != nil {
		t.Fatal(err)
	}
	info, canonical, err := LookupPinned("4f1a2b3c-0000-4000-8000-000000000001@" + DefaultModel)
	if err != nil {
		t.Fatal(err)
	}
	if canonical != DefaultModel {
		t.Fatalf("canonical = %q, want %q", canonical, DefaultModel)
	}
	if info.FunctionID != "4f1a2b3c-0000-4000-8000-000000000001" {
		t.Fatalf("function id = %q, want the pinned value", info.FunctionID)
	}
	if info.Slug != reg.Slug || info.Namespace != reg.Namespace {
		t.Fatalf("pinned lookup changed the endpoint: %+v vs %+v", info, reg)
	}
}

func TestLookupPinnedUnpinnedMatchesLookup(t *testing.T) {
	info, canonical, err := LookupPinned(DefaultModel)
	if err != nil {
		t.Fatal(err)
	}
	want, err := Lookup(DefaultModel)
	if err != nil {
		t.Fatal(err)
	}
	if canonical != DefaultModel || info != want {
		t.Fatalf("got (%q, %+v), want (%q, %+v)", canonical, info, DefaultModel, want)
	}
}

func TestLookupPinnedErrors(t *testing.T) {
	if _, _, err := LookupPinned("bad id@" + DefaultModel); err == nil {
		t.Fatal("expected invalid function id error")
	}
	if _, _, err := LookupPinned("1586112a-925c-48af-8631-7c815dbd749c@"); err == nil {
		t.Fatal("expected missing model id error")
	}
	_, _, err := LookupPinned("1586112a-925c-48af-8631-7c815dbd749c@acme/not-in-registry")
	var unknown *ErrUnknownModel
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want *ErrUnknownModel", err)
	}
	if unknown.Model != "acme/not-in-registry" {
		t.Fatalf("error names %q, want the bare model id without the pin", unknown.Model)
	}
}
