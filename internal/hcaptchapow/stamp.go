package hcaptchapow

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/bits"
	"runtime"
	"strconv"
	"sync/atomic"
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
//	1:<bits/2>:<date>:<pow_data>::<salt>:<counter>
//
// where salt is an 8-character base64 string, date is UTC YYYY-MM-DD and
// counter is a lowercase hex number. SHA-1(stamp) has at least stampBits
// leading zero bits.
func MintStamp(stampBits uint, powData string) (string, error) {
	salt, err := randomSalt()
	if err != nil {
		return "", err
	}
	return mintStampAt(stampBits, powData, salt, time.Now())
}

// mintStampAt mints a stamp with a caller-supplied salt and timestamp.
//
// High-performance zero-allocation implementation:
//   - Static prefix "1:<bits/2>:<date>:<powData>::<salt>:" is constructed once.
//   - Counter is formatted directly into a stack/local byte buffer without heap allocations.
//   - Uses hardware-accelerated SHA-1 (ARM64 NEON / x86 SHA-NI) via crypto/sha1.
//   - For stampBits > 10, searches concurrently across all available CPU cores.
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
	prefix := stampVersion + ":" + strconv.Itoa(int(stampBits/2)) + ":" + date + ":" + powData + "::" + salt + ":"
	prefixBytes := []byte(prefix)

	numWorkers := runtime.GOMAXPROCS(0)
	if stampBits <= 10 || numWorkers <= 1 {
		// Single-threaded fast path for low difficulties (preserves deterministic sequential search order)
		buf := make([]byte, len(prefixBytes)+16)
		copy(buf, prefixBytes)
		var counter uint64
		for {
			b := strconv.AppendUint(buf[:len(prefixBytes)], counter, 16)
			sum := sha1.Sum(b)
			head := binary.BigEndian.Uint64(sum[:8])
			if uint(bits.LeadingZeros64(head)) >= stampBits {
				return string(b), nil
			}
			counter++
		}
	}

	// Concurrent multi-core fast path
	var found atomic.Bool
	var result string
	done := make(chan struct{})

	for w := 0; w < numWorkers; w++ {
		go func(workerID int) {
			buf := make([]byte, len(prefixBytes)+16)
			copy(buf, prefixBytes)
			counter := uint64(workerID)
			step := uint64(numWorkers)

			for !found.Load() {
				b := strconv.AppendUint(buf[:len(prefixBytes)], counter, 16)
				sum := sha1.Sum(b)
				head := binary.BigEndian.Uint64(sum[:8])
				if uint(bits.LeadingZeros64(head)) >= stampBits {
					if found.CompareAndSwap(false, true) {
						result = string(b)
						close(done)
					}
					return
				}
				counter += step
			}
		}(w)
	}

	<-done
	return result, nil
}

// CheckStamp reports whether stamp satisfies the Hashcash difficulty of want
// leading zero bits.
func CheckStamp(stamp string, want uint) bool {
	return checkZeros(stamp, want)
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
