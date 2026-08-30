package hcaptchapow

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Real hCaptcha PoW JWT captured in the reference harness (fp_build__main.go).
// Claims: f=0, s=16, t="w", d=<pow data>, l=<asset location>,
// i=sha256-*.e=1712552328, n="hsw", c=1000.
const realPowJWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmIjowLCJzIjoxNiwidCI6InciLCJkIjoiWjNRWGE5RkFoZUx1Q3VoaUFJM0oxMlVzWkFjRXZhVjlDaXc0dHlhbzVwL3NCVnVKTWs2KzBBaWZVbjhKUjVoMlQ5WlErU3VjVEdnS2RLcGFFdytkdk56cmRqczgwNFlidmNiQjhOOGFkV0xoL1lpZktxS1ZQb2phRi85and2NEpua3p2NEJvMENrV01rcElhS1FwYUdZYmdKckxUV3V1OFZJdmVMSmoyVVlINXhiSFBFZW1qbjZId0tLTHRNLzRoU0tUYTRNUkJvdzlmR1VVRUtCelRvTnV6ODFQaGxiWlo3VmdSZVUwSjF5Yy90VkxjUEE9PWNQNlVicktBQitIRmRWUDAiLCJsIjoiaHR0cHM6Ly9uZXdhc3NldHMuaGNhcHRjaGEuY29tL2MvMjgyZDBmZiIsImkiOiJzaGEyNTYtNlNtVlFhT0RmKy9hcCtXV3lDWW02eWJWZDBKenNUb2xrTXRLY1lSWWdQVT0iLCJlIjoxNzEyNTUyMzI4LCJuIjoiaHN3IiwiYyI6MTAwMH0.1uRoU1htMWn_cTHrD93tSMnvHSneOuy6X1PzWq6XUTc"

func TestParsePowRealJWT(t *testing.T) {
	p, err := ParsePow(realPowJWT)
	if err != nil {
		t.Fatalf("ParsePow: %v", err)
	}
	if p.FingerprintType != 0 {
		t.Errorf("FingerprintType = %v, want 0", p.FingerprintType)
	}
	if p.Difficulty != 16 {
		t.Errorf("Difficulty = %v, want 16", p.Difficulty)
	}
	if p.Type != "w" {
		t.Errorf("Type = %q, want %q", p.Type, "w")
	}
	if !strings.HasPrefix(p.PowData, "Z3QXa9FAheLuCuhiAI3J12UsZAcEvaV9") {
		t.Errorf("PowData = %.20q..., want Z3QXa9FAheLuCuhiAI3J12UsZAcEvaV9 prefix", p.PowData)
	}
	if p.Location != "https://newassets.hcaptcha.com/c/282d0ff" {
		t.Errorf("Location = %q, want https://newassets.hcaptcha.com/c/282d0ff", p.Location)
	}
	if !strings.HasPrefix(p.Signature, "sha256-") {
		t.Errorf("Signature = %.16q..., want sha256- prefix", p.Signature)
	}
	if p.Timestamp != 1712552328 {
		t.Errorf("Timestamp = %v, want 1712552328", p.Timestamp)
	}
	if p.N != "hsw" {
		t.Errorf("N = %q, want %q", p.N, "hsw")
	}
	if p.Timeout != 1000 {
		t.Errorf("Timeout = %v, want 1000", p.Timeout)
	}
}

// makePowJWT builds a PoW JWT with the given payload claims.
func makePowJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc(header) + "." + enc(payload) + ".sig"
}

func TestParsePowSynthetic(t *testing.T) {
	token := makePowJWT(t, map[string]any{
		"f": 1.5, "s": 2, "t": "w",
		"d": "data", "l": "loc", "i": "sig",
		"e": 1707359970.25, "n": "hsw", "c": 1000,
	})
	p, err := ParsePow(token)
	if err != nil {
		t.Fatalf("ParsePow: %v", err)
	}
	if p.FingerprintType != 1.5 || p.Difficulty != 2 || p.PowData != "data" ||
		p.Location != "loc" || p.Signature != "sig" || p.Timestamp != 1707359970.25 ||
		p.N != "hsw" || p.Timeout != 1000 {
		t.Errorf("unexpected parse: %+v", p)
	}
}

func TestParsePowErrors(t *testing.T) {
	valid := map[string]any{
		"f": 0, "s": 2, "t": "w", "d": "d", "l": "l", "i": "i",
		"e": 1, "n": "hsw", "c": 1000,
	}
	tests := []struct {
		name  string
		token string
	}{
		{"one part", "not-a-jwt"},
		{"two parts", "a.b"},
		{"bad base64 payload", "e30.!!!.sig"},
		{"bad payload json", "e30.e30.sig"},
		{"missing d", makePowJWT(t, without(valid, "d"))},
		{"empty t", makePowJWT(t, with(valid, "t", ""))},
		{"zero s", makePowJWT(t, with(valid, "s", 0))},
		{"missing e", makePowJWT(t, without(valid, "e"))},
		{"zero c", makePowJWT(t, with(valid, "c", 0))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParsePow(tt.token); err == nil {
				t.Errorf("ParsePow(%q) succeeded, want error", tt.token)
			}
		})
	}
}

func without(m map[string]any, key string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k != key {
			out[k] = v
		}
	}
	return out
}

func with(m map[string]any, key string, value any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	out[key] = value
	return out
}
