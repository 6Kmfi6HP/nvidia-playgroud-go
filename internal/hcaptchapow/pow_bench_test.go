package hcaptchapow

import (
	"testing"
	"time"
)

// BenchmarkSuitePoW measures Hashcash PoW minting performance at multiple difficulties.
func BenchmarkSuitePoW(b *testing.B) {
	powData := "d94b4070a8d6f51950d4a362799342531393f9c67a536ef0eb7ef68f3a388f7b"
	fixedTime := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	fixedSalt := "dGVzdHNh"

	b.Run("Difficulty_8_bits", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := mintStampAt(8, powData, fixedSalt, fixedTime)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Difficulty_12_bits", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := mintStampAt(12, powData, fixedSalt, fixedTime)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Difficulty_16_bits", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := mintStampAt(16, powData, fixedSalt, fixedTime)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Difficulty_20_bits", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := mintStampAt(20, powData, fixedSalt, fixedTime)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
