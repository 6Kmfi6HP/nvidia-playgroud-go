package hcaptchapow

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/bits"
	"time"
)

const (
	stampVersion    = "1"
	stampDateFormat = "2006-01-02"
	stampSaltLength = 8 // base64 characters (derived from 8 random bytes)
)

// MintStamp mints an hCaptcha hashcash stamp for the given pow data.
//
// stampBits is the full proof-of-work difficulty in leading-zero bits (JWT
// challenge difficulty s times 2; it must be even). The minted stamp follows
// the hCaptcha hashcash layout:
//
//	1:<bits/2>:<YYYY-MM-DD UTC>:<powData>::<8-char base64 salt>:<counter hex>
//
// The SHA-1 digest of the stamp must start with at least stampBits zero bits
// in its first 8 bytes, interpreted as a big-endian uint64. The salt is
// random, so the minted stamp is not reproducible; use CheckStamp to verify.
func MintStamp(stampBits uint, powData string) (string, error) {
	return mintStampAt(stampBits, powData, "", time.Now())
}

// CheckStamp reports whether stamp satisfies the leading-zero requirement.
func CheckStamp(stamp string, stampBits uint) bool {
	return checkZeros(stamp, stampBits)
}

// mintStampAt mints with a fixed salt ("" draws a fresh random one) and clock,
// so tests can reproduce the exact stamp for a fixed counter.
func mintStampAt(stampBits uint, powData, salt string, now time.Time) (string, error) {
	if stampBits%2 != 0 {
		return "", fmt.Errorf("hcaptchapow: stamp bits must be even (JWT difficulty s*2), got %d", stampBits)
	}
	if salt == "" {
		var err error
		salt, err = randomSalt()
		if err != nil {
			return "", err
		}
	}
	date := now.UTC().Format(stampDateFormat)
	for counter := uint64(0); ; counter++ {
		stamp := fmt.Sprintf("%s:%d:%s:%s:%s:%s:%x",
			stampVersion, stampBits/2, date, powData, "", salt, counter)
		if checkZeros(stamp, stampBits) {
			return stamp, nil
		}
	}
}

// randomSalt returns 8 random bytes base64-encoded and truncated to the first
// 8 characters (mirrors the reference implementation, which reads 8 bytes).
func randomSalt() (string, error) {
	buf := make([]byte, stampSaltLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("hcaptchapow: read random salt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf)[:stampSaltLength], nil
}

// checkZeros reports whether the first 8 bytes of SHA-1(stamp), interpreted
// as a big-endian uint64, have at least want leading zero bits.
func checkZeros(stamp string, want uint) bool {
	sum := sha1.Sum([]byte(stamp))
	head := binary.BigEndian.Uint64(sum[:8])
	return uint(bits.LeadingZeros64(head)) >= want
}
