package waftoken

// Browser-signal synthesis, AES-256-GCM encryption, and proof-of-work
// solving for the AWS WAF challenge.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	mrand "math/rand"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

func buildSignals(s *session) map[string]interface{} {
	now := time.Now()
	startTime := now.Add(-time.Duration(mrand.Intn(200)+100) * time.Millisecond)
	hwConc := []int{4, 8, 12, 16}[mrand.Intn(4)]
	devMem := []int{4, 8, 8, 16}[mrand.Intn(4)]
	dpr := []float64{1.0, 1.25, 1.5}[mrand.Intn(3)]

	gpus := []struct{ vendor, renderer string }{
		{"Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)"},
		{"Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"},
		{"Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"},
		{"Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)"},
	}
	gpu := gpus[mrand.Intn(len(gpus))]

	sigVer := s.crypto.signalVer

	return map[string]interface{}{
		"version": sigVer,
		"navigator": map[string]interface{}{
			"userAgent": s.userAgent, "appCodeName": "Mozilla", "appName": "Netscape",
			"appVersion": strings.TrimPrefix(s.userAgent, "Mozilla/"),
			"language":   "en-US", "languages": []string{"en-US", "en"},
			"platform": "Win32", "product": "Gecko", "productSub": "20030107",
			"vendor": "Google Inc.", "vendorSub": "",
			"hardwareConcurrency": hwConc, "maxTouchPoints": 0,
			"cookieEnabled": true, "onLine": true, "deviceMemory": devMem,
			"pdfViewerEnabled": true, "webdriver": false,
		},
		"screen": map[string]interface{}{
			"width": s.screenW, "height": s.screenH,
			"availWidth": s.screenW, "availHeight": s.screenH - 40,
			"colorDepth": 24, "pixelDepth": 24,
		},
		"window": map[string]interface{}{
			"innerWidth": s.screenW, "innerHeight": s.screenH - 117,
			"outerWidth": s.screenW, "outerHeight": s.screenH,
			"devicePixelRatio": dpr,
		},
		"tz":     map[string]interface{}{"offset": -300, "timezone": "America/New_York"},
		"time":   map[string]interface{}{"start": startTime.UnixMilli(), "elapsed": mrand.Intn(200) + 100},
		"canvas": map[string]interface{}{"hash": generateCanvasHash()},
		"gpu": map[string]interface{}{
			"vendor": gpu.vendor, "renderer": gpu.renderer,
			"extensions":    mrand.Intn(10) + 30,
			"viewportWidth": s.screenW, "viewportHeight": s.screenH - 117,
		},
		"math": map[string]interface{}{
			"acos": 1.4473588658278522, "acosh": 709.889355822726,
			"asin": 0.12343746096704435, "asinh": 0.881373587019543,
			"atan": 0.4636476090008061, "atanh": 0.5493061443340549,
			"cos": -0.4161468365471424, "cosh": 1.5430806348152437,
			"exp": 2.718281828459045, "expm1": 1.718281828459045,
			"log": 0.6931471805599453, "sin": 0.8414709848078965,
			"sinh": 1.1752011936438014, "sqrt": 1.4142135623730951,
			"tan": -1.5574077246549023, "tanh": 0.7615941559557649,
		},
		"fonts": map[string]interface{}{
			"count": []int{42, 48, 55, 63}[mrand.Intn(4)],
			"hash":  fmt.Sprintf("%x", sha256Sum([]byte(fmt.Sprintf("fonts_%d_%d", s.screenW, mrand.Int())))),
		},
		"plugins": map[string]interface{}{
			"count": 5,
			"hash":  fmt.Sprintf("%x", sha256Sum([]byte("PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF"))),
		},
		"perf": map[string]interface{}{
			"navigationStart": startTime.Add(-time.Duration(mrand.Intn(2000)+500) * time.Millisecond).UnixMilli(),
		},
		"stealth": map[string]interface{}{
			"webdriver": false, "phantom": false, "nightmare": false, "selenium": false,
			"domAutomation": false, "chromiumBrowser": true,
			"languageInconsist": false, "platformInconsist": false, "permissions": true,
		},
		"batt": map[string]interface{}{
			"charging": true, "chargingTime": 0, "dischargingTime": nil,
			"level": []float64{0.85, 0.90, 0.95, 1.0}[mrand.Intn(4)],
		},
		"amazonUseragent": s.userAgent,
		"client":          "Browser",
		"tVersion":        sigVer,
		"id":              generateRandomID(),
		"errors":          []interface{}{},
	}
}

func encodeSignals(signals map[string]interface{}, crypto *cryptoConfigFull) (out []interface{}, checksum string, err error) {
	jsonData, err := json.Marshal(signals)
	if err != nil {
		return nil, "", err
	}
	checksum = fmt.Sprintf("%x", crc32.ChecksumIEEE(jsonData))

	block, err := aes.NewCipher(crypto.key)
	if err != nil {
		return nil, "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(checksum+"#"+string(jsonData)), nil)
	tagSize := gcm.Overhead()
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	encrypted := base64.StdEncoding.EncodeToString(nonce) + "::" +
		hex.EncodeToString(tag) + "::" + hex.EncodeToString(ciphertext)

	arr := []interface{}{
		map[string]interface{}{
			"name":  crypto.identifier,
			"value": map[string]interface{}{"Present": encrypted},
		},
	}
	return arr, checksum, nil
}

func (s *session) solveChallenge(ctx context.Context, ci *challengeInputs, checksum string) (string, error) {
	innerType := innerChallengeType(ci.Input)
	switch {
	case innerType == "NetworkBandwidth":
		return solveNetworkBandwidth(ci.Diff)
	case strings.HasPrefix(ci.CType, "h72f957df"):
		return solveScryptHashcash(ci.Input, checksum, ci.Diff, ci.Mem)
	case strings.HasPrefix(ci.CType, "h7b0c470f"):
		return solveSHA2Hashcash(ctx, ci.Input, checksum, ci.Diff)
	default:
		if ci.Diff >= 1 && ci.Diff <= 5 {
			return solveNetworkBandwidth(ci.Diff)
		}
		return solveScryptHashcash(ci.Input, checksum, ci.Diff, ci.Mem)
	}
}

func innerChallengeType(input string) string {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "unknown"
	}
	var inner struct {
		ChallengeType string `json:"challenge_type"`
	}
	if json.Unmarshal(decoded, &inner) != nil {
		return "unknown"
	}
	return inner.ChallengeType
}

func solveNetworkBandwidth(difficulty int) (string, error) {
	var bufSize int
	switch difficulty {
	case 1:
		bufSize = 1 * 0x400
	case 2:
		bufSize = 10 * 0x400
	case 3:
		bufSize = 100 * 0x400
	case 4:
		bufSize = 1 * 0x100000
	case 5:
		bufSize = 10 * 0x100000
	default:
		return "", fmt.Errorf("waftoken: unsupported NetworkBandwidth difficulty %d", difficulty)
	}
	return base64.StdEncoding.EncodeToString(make([]byte, bufSize)), nil
}

func solveScryptHashcash(input, checksum string, difficulty, memory int) (string, error) {
	if difficulty < 0 || difficulty > 256 {
		return "", fmt.Errorf("waftoken: invalid difficulty %d", difficulty)
	}
	if memory <= 0 {
		memory = 128
	}
	baseString := input + checksum
	salt := []byte(checksum)
	for nonce := 0; ; nonce++ {
		hash, err := scrypt.Key([]byte(baseString+fmt.Sprintf("%d", nonce)), salt, memory, 8, 1, 16)
		if err != nil {
			return "", fmt.Errorf("waftoken: scrypt: %w", err)
		}
		if hasLeadingZeroBits(hash, difficulty) {
			return fmt.Sprintf("%d", nonce), nil
		}
	}
}

func solveSHA2Hashcash(ctx context.Context, input, checksum string, difficulty int) (string, error) {
	baseString := input + checksum
	for nonce := 0; ; nonce++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		hash := sha256.Sum256([]byte(baseString + fmt.Sprintf("%d", nonce)))
		if hasLeadingZeroBits(hash[:], difficulty) {
			return fmt.Sprintf("%d", nonce), nil
		}
	}
}

func hasLeadingZeroBits(hash []byte, n int) bool {
	for i := 0; i < n; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		if byteIdx >= len(hash) {
			return false
		}
		if hash[byteIdx]&(1<<uint(bitIdx)) != 0 {
			return false
		}
	}
	return true
}

func generateRandomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateCanvasHash() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
