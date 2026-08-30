package hcaptchapow

import (
	"crypto/sha1"
	"encoding/binary"
	"math/bits"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Golden vectors minted with the reference algorithm (fixed salt and clock):
//
//	bits=4: first accepting counter is 12 (c), stamp is exactly
//	1:2:2024-02-07:hcaptcha-pow-test-data::AbCdEfGh:c, and counter 11 (b)
//	does not satisfy 4 leading zero bits.
//	bits=8: first accepting counter is 618 (26a).
const (
	testPowData = "hcaptcha-pow-test-data"
	testSalt    = "AbCdEfGh"
	testDate    = "2024-02-07"
)

func TestMintStampGolden(t *testing.T) {
	now := time.Date(2024, 2, 7, 15, 4, 5, 0, time.UTC)
	got, err := mintStampAt(4, testPowData, testSalt, now)
	if err != nil {
		t.Fatalf("mintStampAt: %v", err)
	}
	want := "1:2:" + testDate + ":" + testPowData + "::" + testSalt + ":c"
	if got != want {
		t.Errorf("stamp = %q, want %q", got, want)
	}
	if !CheckStamp(got, 4) {
		t.Errorf("CheckStamp(%q, 4) = false, want true", got)
	}
	prev := "1:2:" + testDate + ":" + testPowData + "::" + testSalt + ":b"
	if CheckStamp(prev, 4) {
		t.Errorf("CheckStamp(%q, 4) = true, want false (counter 11 must not satisfy)", prev)
	}

	got8, err := mintStampAt(8, testPowData, testSalt, now)
	if err != nil {
		t.Fatalf("mintStampAt(8): %v", err)
	}
	want8 := "1:4:" + testDate + ":" + testPowData + "::" + testSalt + ":26a"
	if got8 != want8 {
		t.Errorf("stamp(bits=8) = %q, want %q", got8, want8)
	}
}

var counterHex = regexp.MustCompile(`^[0-9a-f]+$`)

func TestMintStampFormat(t *testing.T) {
	stampBits := uint(4) // JWT difficulty s=2
	before := time.Now().UTC()
	stamp, err := MintStamp(stampBits, testPowData)
	if err != nil {
		t.Fatalf("MintStamp: %v", err)
	}
	after := time.Now().UTC()

	if !CheckStamp(stamp, stampBits) {
		t.Fatalf("minted stamp fails own zero check: %q", stamp)
	}
	fields := strings.Split(stamp, ":")
	if len(fields) != 7 {
		t.Fatalf("stamp = %q: got %d fields, want 7", stamp, len(fields))
	}
	if fields[0] != "1" {
		t.Errorf("version = %q, want \"1\"", fields[0])
	}
	if fields[1] != "2" {
		t.Errorf("difficulty field = %q, want \"2\" (bits/2)", fields[1])
	}
	date, err := time.Parse("2006-01-02", fields[2])
	if err != nil {
		t.Fatalf("date field %q: %v", fields[2], err)
	}
	if date.Before(before.Truncate(24*time.Hour)) || date.After(after) {
		t.Errorf("date %q not around today", fields[2])
	}
	if fields[3] != testPowData {
		t.Errorf("pow data = %q, want %q", fields[3], testPowData)
	}
	if fields[4] != "" {
		t.Errorf("extra = %q, want empty", fields[4])
	}
	if len(fields[5]) != 8 {
		t.Errorf("salt = %q, want 8 chars", fields[5])
	}
	if !counterHex.MatchString(fields[6]) {
		t.Errorf("counter = %q, want lowercase hex", fields[6])
	}
}

func TestMintStampRandomSalt(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 5; i++ {
		stamp, err := MintStamp(4, testPowData)
		if err != nil {
			t.Fatalf("MintStamp: %v", err)
		}
		if !CheckStamp(stamp, 4) {
			t.Fatalf("stamp fails zero check: %q", stamp)
		}
		fields := strings.Split(stamp, ":")
		if seen[fields[5]] {
			t.Errorf("repeated salt %q across mints", fields[5])
		}
		seen[fields[5]] = true
	}
}

func TestMintStampRejectsOddBits(t *testing.T) {
	if _, err := MintStamp(3, testPowData); err == nil {
		t.Error("MintStamp(3, ...) succeeded, want error for odd bits")
	}
}

// TestCheckZerosIndependent recomputes the zero-bit requirement with a direct
// SHA-1 implementation to guard checkZeros against drift.
func TestCheckZerosIndependent(t *testing.T) {
	stamp := "1:2:" + testDate + ":" + testPowData + "::" + testSalt + ":c"
	sum := sha1.Sum([]byte(stamp))
	wantZeros := uint(bits.LeadingZeros64(binary.BigEndian.Uint64(sum[:8])))
	for zeroBits := uint(0); zeroBits <= wantZeros; zeroBits++ {
		if !checkZeros(stamp, zeroBits) {
			t.Errorf("checkZeros(%q, %d) = false, want true", stamp, zeroBits)
		}
	}
	if wantZeros < 64 && checkZeros(stamp, wantZeros+1) {
		t.Errorf("checkZeros(%q, %d) = true, want false", stamp, wantZeros+1)
	}
}
