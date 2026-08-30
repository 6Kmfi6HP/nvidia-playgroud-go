package hcaptchapow

import (
	"encoding/binary"
	"math/bits"
	"strconv"
)

// XXH64 primes from the xxHash64 specification.
const (
	xxhPrime1 uint64 = 0x9E3779B185EBCA87
	xxhPrime2 uint64 = 0xC2B2AE3D27D4EB4F
	xxhPrime3 uint64 = 0x165667B19E3779F9
	xxhPrime4 uint64 = 0x85EBCA77C2B2AE63
	xxhPrime5 uint64 = 0x27D4EB2F165667C5
)

// XXHSeed is the seed used by hCaptcha for fingerprint component hashes
// (web_gl_hash, canvas_hash, ...).
const XXHSeed uint64 = 5575352424011909552

// HashString returns the decimal string used inside fingerprint JSON, hashing
// content with XXHSeed.
func HashString(content []byte) string {
	return strconv.FormatUint(XXH64(content, XXHSeed), 10)
}

// XXH64 implements the xxHash64 algorithm (64-bit variant). It reads the
// input little-endian and returns the hash for the given seed.
func XXH64(data []byte, seed uint64) uint64 {
	var h uint64
	if len(data) >= 32 {
		v1 := seed + xxhPrime1 + xxhPrime2
		v2 := seed + xxhPrime2
		v3 := seed
		v4 := seed - xxhPrime1
		p := data
		for len(p) >= 32 {
			v1 = xxhRound(v1, binary.LittleEndian.Uint64(p))
			v2 = xxhRound(v2, binary.LittleEndian.Uint64(p[8:]))
			v3 = xxhRound(v3, binary.LittleEndian.Uint64(p[16:]))
			v4 = xxhRound(v4, binary.LittleEndian.Uint64(p[24:]))
			p = p[32:]
		}
		h = bits.RotateLeft64(v1, 1) + bits.RotateLeft64(v2, 7) +
			bits.RotateLeft64(v3, 12) + bits.RotateLeft64(v4, 18)
		h = xxhMergeRound(h, v1)
		h = xxhMergeRound(h, v2)
		h = xxhMergeRound(h, v3)
		h = xxhMergeRound(h, v4)
		h = xxhFinalize(h, uint64(len(data)), p)
		return h
	}
	return xxhFinalize(seed+xxhPrime5, uint64(len(data)), data)
}

// xxhRound is the xxHash64 mixing step: rotate(acc + input*prime2, 31) * prime1.
func xxhRound(acc, input uint64) uint64 {
	acc += input * xxhPrime2
	acc = bits.RotateLeft64(acc, 31)
	return acc * xxhPrime1
}

// xxhMergeRound folds a lane value into the accumulator.
func xxhMergeRound(acc, val uint64) uint64 {
	acc ^= xxhRound(0, val)
	return acc*xxhPrime1 + xxhPrime4
}

// xxhFinalize absorbs the remaining <32 bytes and avalanches the result.
func xxhFinalize(h, length uint64, p []byte) uint64 {
	h += length
	for len(p) >= 8 {
		k1 := xxhRound(0, binary.LittleEndian.Uint64(p))
		h ^= k1
		h = bits.RotateLeft64(h, 27)*xxhPrime1 + xxhPrime4
		p = p[8:]
	}
	if len(p) >= 4 {
		h ^= uint64(binary.LittleEndian.Uint32(p)) * xxhPrime1
		h = bits.RotateLeft64(h, 23)*xxhPrime2 + xxhPrime3
		p = p[4:]
	}
	for _, b := range p {
		h ^= uint64(b) * xxhPrime5
		h = bits.RotateLeft64(h, 11) * xxhPrime1
	}
	h ^= h >> 33
	h *= xxhPrime2
	h ^= h >> 29
	h *= xxhPrime3
	h ^= h >> 32
	return h
}
