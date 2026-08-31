package hsw

import (
	"context"
	"testing"
)

const benchmarkMockBundle = `window.hsw = function(mode, data) {
  if (mode === 1 || mode === 0) {
    var u = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i++) u[i] = data[i];
    return Promise.resolve(u);
  }
  return Promise.resolve("N:" + String(mode) + ":" + String(data));
};`

func BenchmarkSuiteV8(b *testing.B) {
	bundle, err := Prepare([]byte(benchmarkMockBundle))
	if err != nil {
		b.Fatal(err)
	}
	s, err := New(bundle)
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()

	b.Run("SolveN", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := s.SolveN(ctx, "jwt.token.test", "fp_base64_sample")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Crypto_Mode1_Encrypt", func(b *testing.B) {
		payload := []byte("getcaptcha-payload-data-example")
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := s.Crypto(ctx, 1, payload)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Crypto_Mode0_Decrypt", func(b *testing.B) {
		payload := []byte("getcaptcha-encrypted-response-data")
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := s.Crypto(ctx, 0, payload)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
