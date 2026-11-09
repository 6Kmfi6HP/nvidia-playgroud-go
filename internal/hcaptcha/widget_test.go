package hcaptcha

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// TestWidgetFlowOffline pins the reference-minter payload: the checksiteconfig
// challenge is submitted directly, encrypted over ext18, and carries the
// browser widget fields (live v, motionData, e:null). The answer is plaintext
// in this test, so the passcode path is independent of wasm decryption.
func TestWidgetFlowOffline(t *testing.T) {
	oldV, oldT := versionValue, versionFetched
	versionValue, versionFetched = "testversion", time.Now()
	defer func() { versionValue, versionFetched = oldV, oldT }()

	const tok = "P1_eyJ3aWRnZXQifQ.offline"
	const location = "/c/getcaptcha-test-loc"
	var jwt string
	jwt, _, cleanup := offlineCaptchaEnv(t, func(ctx context.Context, params map[string]string) (int, []byte, error) {
		if params["n"] == "" && params["c"] == "" {
			return http.StatusOK, []byte(`{"c":{"type":"hsw","req":"` + jwt + `"}}`), nil
		}
		t.Errorf("plaintext variant reached on widget path: %v", params)
		return http.StatusOK, []byte(`{"pass":false}`), nil
	})
	defer cleanup()

	fetchChecksite = func(ctx context.Context, sitekey, host string) (string, string, string, bool, error) {
		return jwt, location, "", true, nil
	}

	var specReq string
	var payload map[string]any
	oldOctet := postGetCaptchaOctetFn
	defer func() { postGetCaptchaOctetFn = oldOctet }()
	postGetCaptchaOctetFn = func(ctx context.Context, sitekey string, body []byte) (int, []byte, error) {
		v, rest, err := msgpackDecode(body)
		if err != nil || len(rest) != 0 {
			t.Fatalf("wire decode: %v rest=%d", err, len(rest))
		}
		arr, ok := v.([]any)
		if !ok || len(arr) != 2 {
			t.Fatalf("wire = %T %v, want [spec, cipher]", v, v)
		}
		spec, ok := arr[0].(string)
		if !ok {
			t.Fatalf("wire spec = %T", arr[0])
		}
		var doc struct {
			Type string `json:"type"`
			Req  string `json:"req"`
		}
		if err := json.Unmarshal([]byte(spec), &doc); err != nil {
			t.Fatalf("spec json: %v", err)
		}
		specReq = doc.Req
		if doc.Type != "hsw" {
			t.Errorf("spec type = %q, want hsw", doc.Type)
		}
		cipher, ok := arr[1].([]byte)
		if !ok {
			t.Fatalf("wire cipher = %T, want []byte", arr[1])
		}
		solver, err := solverFor(ctx, location)
		if err != nil {
			t.Fatalf("solver: %v", err)
		}
		plain, err := solver.Crypto(ctx, 0, cipher)
		if err != nil {
			t.Fatalf("decrypt payload: %v", err)
		}
		m, rest, err := msgpackDecode(plain)
		if err != nil || len(rest) != 0 {
			t.Fatalf("payload decode: %v rest=%d", err, len(rest))
		}
		payload, ok = m.(map[string]any)
		if !ok {
			t.Fatalf("payload = %T, want map", m)
		}
		return http.StatusOK, []byte(`{"pass":true,"generated_pass_UUID":"` + tok + `"}`), nil
	}

	solve, attempts, err := CaptchaAttempts(context.Background(), "sitekey", "host")
	if err != nil {
		t.Fatalf("CaptchaAttempts: %v", err)
	}
	if solve.JWT != jwt {
		t.Errorf("solve.JWT = %q, want checksiteconfig jwt", solve.JWT)
	}
	if len(attempts) != 1 || attempts[0].Name != "widget" {
		t.Fatalf("attempts = %+v, want one widget attempt", attempts)
	}
	if attempts[0].Token != tok {
		t.Errorf("token = %q, want %q", attempts[0].Token, tok)
	}
	if specReq != jwt {
		t.Errorf("spec req = %q, want %q", specReq, jwt)
	}
	want := map[string]string{
		"v":          "testversion",
		"sitekey":    "sitekey",
		"host":       "host",
		"hl":         "en",
		"motionData": "{}",
	}
	for k, w := range want {
		if got, _ := payload[k].(string); got != w {
			t.Errorf("payload[%s] = %q, want %q", k, got, w)
		}
	}
	if payload["n"] == "" || payload["n"] == nil {
		t.Error("payload n is empty")
	}
	if got, ok := payload["e"]; !ok || got != nil {
		t.Errorf("payload e = %v (present=%v), want explicit null", got, ok)
	}
}
