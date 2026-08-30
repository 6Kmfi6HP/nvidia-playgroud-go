package hcaptchapow

import (
	"strconv"
	"strings"
	"testing"
)

// Official xxHash64 test vectors (seed 0) plus vectors from an independently
// implemented Go oracle (cespare/xxhash) covering the streaming (>=32B) and
// 31-byte-tail paths.
func TestXXH64Vectors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		seed uint64
		want uint64
	}{
		{"empty", "", 0, 0xef46db3751d8e999},
		{"a", "a", 0, 0xd24ec4f1a98c6e5b},
		{"abc", "abc", 0, 0x44bc2cf5ad770999},
		// 43 bytes: streaming path with tail
		{"fox 43B seed 0", "The quick brown fox jumps over the lazy dog", 0, 0x0b242d361fda71bc},
		{"fox 43B app seed", "The quick brown fox jumps over the lazy dog", XXHSeed, 0xc919deaca81fbc83},
		// 36 bytes: streaming path
		{"alnum 36B app seed", "abcdefghijklmnopqrstuvwxyz0123456789", XXHSeed, 0x6f4d93ee5ed504d3},
		// 63 bytes: streaming path with full 31-byte tail
		{"a*63 app seed", strings.Repeat("a", 63), XXHSeed, 0x8119d3dd0eff894a},
		// 64 bytes: exactly two 32-byte blocks, no tail
		{"a*64 app seed", strings.Repeat("a", 64), XXHSeed, 0x9a47ea458523a5d3},
		// 100 bytes: multiple blocks plus tail
		{"a*100 app seed", strings.Repeat("a", 100), XXHSeed, 0x3b4c0748db37afa3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := XXH64([]byte(tt.in), tt.seed); got != tt.want {
				t.Errorf("XXH64(%q, %d) = %#x, want %#x", tt.in, tt.seed, got, tt.want)
			}
		})
	}
}

// TestHashStringDecimal checks the decimal-string form used inside the
// fingerprint JSON for the canonical seed.
func TestHashStringDecimal(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"abc", "687765810606407781"},
		{"The quick brown fox jumps over the lazy dog", "14490858109177674883"},
		{"abcdefghijklmnopqrstuvwxyz0123456789", "8020229163419239635"},
	}
	for _, tt := range tests {
		if got := HashString([]byte(tt.in)); got != tt.want {
			t.Errorf("HashString(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
	// Cross-check decimal against strconv.
	// Cross-check decimal against strconv.
	if got := HashString([]byte("abc")); got != strconv.FormatUint(XXH64([]byte("abc"), XXHSeed), 10) {
		t.Errorf("HashString not the decimal form of XXH64: %s", got)
	}
}
