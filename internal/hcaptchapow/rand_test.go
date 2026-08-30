package hcaptchapow

import (
	"hash/crc32"
	"math"
	"testing"
)

// Vectors computed with an independent CRC-32 (IEEE 802.3, Python zlib) on
// the input bytes; rand is crc/2^32. The last vector is a fingerprint JSON
// with its "rand" entry removed.
func TestRandHashVectors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		crc  uint32
		rand float64
	}{
		{"empty", "", 0, 0},
		{"a", "a", 3904355907, 0.909053698880598},
		{"abc", "abc", 891568578, 0.20758448587730527},
		{"hello world", "hello world", 222957957, 0.05191144463606179},
		{"fingerprint sans rand", `{"a":1,"b":"x"}`, 4068419412, 0.9472527103498578},
	}
	const scale = 2.3283064365386963e-10
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crc, randVal := RandHash([]byte(tt.in))
			if crc != tt.crc {
				t.Errorf("crc = %d, want %d", crc, tt.crc)
			}
			if randVal != float64(tt.crc)*scale {
				t.Errorf("rand formula mismatch: %v != %v * %v", randVal, tt.crc, scale)
			}
			if math.Abs(randVal-tt.rand) > 1e-16 {
				t.Errorf("rand = %.17g, want %.17g", randVal, tt.rand)
			}
		})
	}
}

// TestRandHashDeterministic checks the same input yields the same output and
// that the reversed-polynomial table matches the canonical IEEE table.
func TestRandHashDeterministic(t *testing.T) {
	in := []byte(`{"proof_spec":{"difficulty":2},"components":{}}`)
	crc1, rand1 := RandHash(in)
	crc2, rand2 := RandHash(in)
	if crc1 != crc2 || rand1 != rand2 {
		t.Errorf("non-deterministic: (%d,%v) vs (%d,%v)", crc1, rand1, crc2, rand2)
	}
	if crc1 != crc32.ChecksumIEEE(in) {
		t.Errorf("crc = %d, want ChecksumIEEE %d (reversed 0x04C11DB7 == IEEE)", crc1, crc32.ChecksumIEEE(in))
	}
	if rand1 < 0 || rand1 >= 1 {
		t.Errorf("rand %v out of [0,1)", rand1)
	}
}
