package models

import "testing"

func TestLookupDefault(t *testing.T) {
	info, err := Lookup("")
	if err != nil {
		t.Fatalf("Lookup(\"\"): %v", err)
	}
	if info.Slug != "kimi-k3" {
		t.Fatalf("default slug = %q want kimi-k3", info.Slug)
	}
	if info.FunctionID != "1586112a-925c-48af-8631-7c815dbd749c" {
		t.Fatalf("default function id = %q want the known Kimi-K3 id", info.FunctionID)
	}
}

func TestLookupKnown(t *testing.T) {
	cases := map[string]string{
		"moonshotai/kimi-k3":                "kimi-k3",
		"deepseek-ai/deepseek-v4-pro-0813":  "deepseek-v4-pro-0813",
		"nvidia/nemotron-3-ultra-550b-a55b": "nemotron-3-ultra-550b-a55b",
	}
	for model, wantSlug := range cases {
		info, err := Lookup(model)
		if err != nil {
			t.Errorf("Lookup(%q): %v", model, err)
			continue
		}
		if info.Slug != wantSlug {
			t.Errorf("Lookup(%q) slug = %q want %q", model, info.Slug, wantSlug)
		}
		if info.Namespace != Namespace {
			t.Errorf("Lookup(%q) namespace = %q want %q", model, info.Namespace, Namespace)
		}
	}
}

func TestLookupUnknown(t *testing.T) {
	_, err := Lookup("no-such-org/no-such-model")
	if err == nil {
		t.Fatal("expected error for unknown model")
	}
	uerr, ok := err.(*ErrUnknownModel)
	if !ok {
		t.Fatalf("error type = %T want *ErrUnknownModel", err)
	}
	if uerr.Model != "no-such-org/no-such-model" {
		t.Errorf("err model = %q", uerr.Model)
	}
}

func TestPredictEndpoint(t *testing.T) {
	info, _ := Lookup("moonshotai/kimi-k3")
	want := PredictBase + "/v2/predict/models/" + Namespace + "/kimi-k3"
	if got := info.PredictEndpoint(); got != want {
		t.Fatalf("PredictEndpoint() = %q want %q", got, want)
	}
}

// Registry invariants: every entry has a UUID-shaped function id and the
// shared namespace. Function ids are *usually* unique per model, but NVIDIA
// does alias some backend versions to the same NVCF function (e.g. the
// ising-calibration variants share 499210d3…). We log duplicates instead of
// failing so a legit alias is not mistaken for a scrape bug; the endpoint
// path (namespace/slug) is what actually distinguishes models, and that IS
// unique per registry key.
func TestRegistryInvariants(t *testing.T) {
	seen := map[string]string{} // functionID -> first model
	for model, info := range Models {
		if info.FunctionID == "" || !uuid42(info.FunctionID) {
			t.Errorf("%q: bad function id %q", model, info.FunctionID)
		}
		if info.Namespace != Namespace {
			t.Errorf("%q: namespace = %q want %q", model, info.Namespace, Namespace)
		}
		if info.Slug == "" {
			t.Errorf("%q: empty slug", model)
		}
		if prev, dup := seen[info.FunctionID]; dup {
			t.Logf("note: %q and %q share function id %q (likely an alias)", prev, model, info.FunctionID)
		} else {
			seen[info.FunctionID] = model
		}
	}

	// Slugs within the shared namespace must be unique — otherwise two
	// models would collide on the predict URL path.
	slugSeen := map[string]string{}
	for model, info := range Models {
		if prev, dup := slugSeen[info.Slug]; dup {
			t.Errorf("duplicate slug %q for %q and %q (predict URL collision)", info.Slug, prev, model)
		} else {
			slugSeen[info.Slug] = model
		}
	}
}

func uuid42(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
	}
	return true
}
