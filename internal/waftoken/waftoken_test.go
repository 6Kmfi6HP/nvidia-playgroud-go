package waftoken

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// miniChallengeJS builds a small obfuscated-looking challenge.js the way
// real bundles are structured: a string-array function, a decoder function
// and an object-literal identifier assignment.
const miniArray = `function a0_0x8f3c() {
    var _0x3a1b=['z2v0','y29UC3rYDwn0B3i','h7b0c470f0cfe3a80a9e26526ad185f484f6817d0832712a4a37a908786a6a67f','6f71a512b1e035eaab53d8be73120d3fb68a0ca346b9560aab3e5cdf753d5e98','Zoey','2.4.0','Present','verify'];
    return _0x3a1b;
}
function a0_0x51f2(_0x2e8d, _0x4a10) {
    _0x2e8d = _0x2e8d - 0x0;
    var _0x3a1b = a0_0x8f3c();
    return _0x3a1b[_0x2e8d];
}
var _0x9f12 = a0_0x51f2;
var _0x1c4d = {'identifier': _0x9f12(0x4)};
`

func TestExtractCryptoConfig(t *testing.T) {
	cfg, err := extractCryptoConfig(miniArray)
	if err != nil {
		t.Fatalf("extractCryptoConfig: %v", err)
	}
	if cfg.Key != "6f71a512b1e035eaab53d8be73120d3fb68a0ca346b9560aab3e5cdf753d5e98" {
		t.Fatalf("key = %q", cfg.Key)
	}
	if cfg.Identifier != "Zoey" {
		t.Fatalf("identifier = %q", cfg.Identifier)
	}
	if cfg.SignalVersion != "2.4.0" {
		t.Fatalf("signalVersion = %q", cfg.SignalVersion)
	}
	if cfg.TypeNames["h7b0c470f0cfe3a80a9e26526ad185f484f6817d0832712a4a37a908786a6a67f"] != "verify" {
		t.Fatalf("typeNames = %v", cfg.TypeNames)
	}
}

func TestExtractFailure(t *testing.T) {
	if _, err := extractCryptoConfig("not a challenge script at all"); err == nil {
		t.Fatal("expected error for non-challenge script")
	}
}

func TestInnerChallengeTypeNetworkBandwidth(t *testing.T) {
	input := base64.StdEncoding.EncodeToString([]byte(`{"version":1,"difficulty":2,"challenge_type":"NetworkBandwidth"}`))
	if got := innerChallengeType(input); got != "NetworkBandwidth" {
		t.Fatalf("inner type = %q", got)
	}
}

func TestSolveNetworkBandwidth(t *testing.T) {
	sol, err := solveNetworkBandwidth(2)
	if err != nil {
		t.Fatalf("solveNetworkBandwidth: %v", err)
	}
	// difficulty 2 -> 10*0x400 zero bytes, base64 length = ceil(10240/3)*4
	if len(sol) != 13656 {
		t.Fatalf("solution len = %d, want 13656", len(sol))
	}
	if strings.Trim(sol, "A=") != "" {
		// zeroed buffer base64-encodes to a run of 'A'
		t.Fatalf("expected zeroed buffer, got %q", sol[:30])
	}
	if _, err := solveNetworkBandwidth(9); err == nil {
		t.Fatal("expected error for unsupported difficulty")
	}
}

func TestHasLeadingZeroBits(t *testing.T) {
	if !hasLeadingZeroBits([]byte{0x00, 0x00, 0xFF}, 2) {
		t.Fatal("0x00 0x00 0xFF should satisfy 2 leading zero bits")
	}
	if !hasLeadingZeroBits([]byte{0x00, 0x00, 0xFF}, 16) {
		t.Fatal("0x00 0x00 0xFF should satisfy 16 leading zero bits")
	}
	if hasLeadingZeroBits([]byte{0x80}, 1) {
		t.Fatal("0x80 should not satisfy 1 leading zero bit")
	}
}

func TestChallengeTypeName(t *testing.T) {
	names := map[string]string{"ha9faaffd31b4d5ede2a2e19d2d7fd525f66fee61911511960dcbb52d3c48ce25": "mp_verify"}
	if got := challengeTypeName(names, "ha9faaffd31b4d5ede2a2e19d2d7fd525f66fee61911511960dcbb52d3c48ce25"); got != "mp_verify" {
		t.Fatalf("got %s", got)
	}
	if got := challengeTypeName(nil, "h7b0c470f0cfe3a80a9e26526ad185f484f6817d0832712a4a37a908786a6a67f"); got != "verify" {
		t.Fatalf("got %s", got)
	}
	if got := challengeTypeName(nil, "hunknown"); got != "mp_verify" {
		t.Fatalf("got %s", got)
	}
}

func TestMintRequiresTarget(t *testing.T) {
	if _, err := MintProxy(context.Background(), "", ""); err == nil {
		t.Fatal("expected error for empty target")
	}
	if _, err := MintProxy(context.Background(), "https://x.test", "://bad"); err == nil {
		t.Fatal("expected error for invalid proxy")
	}
}
