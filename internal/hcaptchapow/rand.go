package hcaptchapow

import (
	"hash/crc32"
	"math/bits"
)

// randScale is 2^-32, the multiplier that turns the CRC-32 into a float in
// [0, 1) for the hCaptcha fingerprint rand value.
const randScale = 2.3283064365386963e-10

// randTable is the CRC-32 table built from the bit-reversed hCaptcha
// polynomial: 79764919 = 0x04C11DB7, reversed to 0xEDB88320 (the canonical
// IEEE polynomial, identical to crc32.MakeTable(crc32.IEEE)).
var randTable = crc32.MakeTable(bits.Reverse32(79764919))

// RandHash computes the hCaptcha fingerprint rand value for a fingerprint
// JSON payload with the "rand" entry removed: the CRC-32 of the payload
// scaled by 2^-32.
func RandHash(input []byte) (crc uint32, randVal float64) {
	crc = crc32.Checksum(input, randTable)
	return crc, float64(crc) * randScale
}
