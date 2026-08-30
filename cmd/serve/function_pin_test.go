package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"glm52-nvidia/internal/models"

	"github.com/gin-gonic/gin"
)

const testPin = "4f1a2b3c-0000-4000-8000-000000000001"

func TestApplyFunctionPin(t *testing.T) {
	t.Run("body pin is split off the model", func(t *testing.T) {
		raw := []byte(`{"model":"` + testPin + `@moonshotai/kimi-k3","messages":[{"role":"user","content":"hi"}],"stream":true}`)
		body, pin, slug, err := applyFunctionPin(raw, "")
		if err != nil {
			t.Fatal(err)
		}
		if slug != "" {
			t.Fatalf("slug = %q, want none for a registered model", slug)
		}
		if pin != testPin {
			t.Fatalf("pin = %q, want %q", pin, testPin)
		}
		if strings.Contains(string(body), testPin) {
			t.Fatalf("pin still in body: %s", body)
		}
		if bodyModel(t, body) != "moonshotai/kimi-k3" {
			t.Fatalf("body model = %q", body)
		}
		if !strings.Contains(string(body), `"content":"hi"`) || !strings.Contains(string(body), `"stream":true`) {
			t.Fatalf("other fields changed: %s", body)
		}
	})

	t.Run("no pin leaves the body alone", func(t *testing.T) {
		raw := []byte(`{"model":"moonshotai/kimi-k3","messages":[]}`)
		body, pin, _, err := applyFunctionPin(raw, "")
		if err != nil {
			t.Fatal(err)
		}
		if pin != "" {
			t.Fatalf("pin = %q, want none", pin)
		}
		if !bytes.Equal(body, raw) {
			t.Fatalf("body changed: %s", body)
		}
	})

	t.Run("header pin passes through", func(t *testing.T) {
		raw := []byte(`{"model":"moonshotai/kimi-k3"}`)
		body, pin, _, err := applyFunctionPin(raw, testPin)
		if err != nil {
			t.Fatal(err)
		}
		if pin != "" {
			t.Fatalf("pin = %q, want the header to stay as sent", pin)
		}
		if !bytes.Equal(body, raw) {
			t.Fatalf("body changed: %s", body)
		}
	})

	t.Run("unlisted pinned model falls back to headers + default carrier", func(t *testing.T) {
		raw := []byte(`{"model":"` + testPin + `@qwen3.8-2.4t-a95b","messages":[]}`)
		body, pin, slug, err := applyFunctionPin(raw, "")
		if err != nil {
			t.Fatal(err)
		}
		if pin != testPin || slug != "qwen3.8-2.4t-a95b" {
			t.Fatalf("pin=%q slug=%q", pin, slug)
		}
		if bodyModel(t, body) != models.DefaultModel {
			t.Fatalf("body model = %s, want the routing carrier %s", body, models.DefaultModel)
		}
	})

	t.Run("malformed pins are rejected", func(t *testing.T) {
		if _, _, _, err := applyFunctionPin([]byte(`{"model":"bad id@moonshotai/kimi-k3"}`), ""); err == nil {
			t.Fatal("want error for a pin with a space")
		}
		if _, _, _, err := applyFunctionPin([]byte(`{"model":"@moonshotai/kimi-k3"}`), ""); err == nil {
			t.Fatal("want error for an empty pin")
		}
		if _, _, _, err := applyFunctionPin([]byte(`{"model":"`+testPin+`@"}`), ""); err == nil {
			t.Fatal("want error for an empty model id")
		}
		if _, _, _, err := applyFunctionPin([]byte(`{"model":"moonshotai/kimi-k3"}`), "not a uuid"); err == nil {
			t.Fatal("want error for a malformed header pin")
		}
		if _, _, _, err := applyFunctionPin([]byte(`{"model":"`+testPin+`@bad model"}`), ""); err == nil {
			t.Fatal("want error for an unlistable slug with a space")
		}
	})

	t.Run("non-json bodies are ignored", func(t *testing.T) {
		raw := []byte(`not json at all`)
		body, pin, _, err := applyFunctionPin(raw, "")
		if err != nil || pin != "" || !bytes.Equal(body, raw) {
			t.Fatalf("body=%q pin=%q err=%v", body, pin, err)
		}
	})
}

// TestFunctionPinMiddlewareFeedsTheExecutor runs the middleware in front of a
// handler that reads the body the way cliproxy's handlers do, and checks what
// the nvidia executor would then see: a routable model id plus the pin in the
// request headers.
func TestFunctionPinMiddlewareFeedsTheExecutor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(functionPinMiddleware())
	// echo stands in for cliproxy's handlers: it reads the body the same way
	// (io.ReadAll on the request body) and reports what it saw.
	echo := func(c *gin.Context) {
		raw, err := io.ReadAll(c.Request.Body)
		if err != nil {
			t.Errorf("handler body read: %v", err)
		}
		c.JSON(http.StatusOK, gin.H{
			"body": string(raw),
			"pin":  c.Request.Header.Get(functionIDHeader),
			"slug": c.Request.Header.Get(functionSlugHeader),
		})
	}
	engine.POST("/v1/chat/completions", echo)
	engine.POST("/v1/images/generations", echo)
	srv := httptest.NewServer(engine)
	defer srv.Close()

	type echoResult struct {
		pin  string
		slug string
	}
	post := func(path, body string, headers map[string]string) (int, echoResult, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		var out struct {
			Body  string `json:"body"`
			Pin   string `json:"pin"`
			Slug  string `json:"slug"`
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		msg := out.Body
		if out.Error.Message != "" {
			msg = out.Error.Message
		}
		return resp.StatusCode, echoResult{pin: out.Pin, slug: out.Slug}, msg
	}

	t.Run("pinned model", func(t *testing.T) {
		status, echo, body := post("/v1/chat/completions",
			`{"model":"`+testPin+`@moonshotai/kimi-k3","messages":[{"role":"user","content":"hi"}]}`, nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d (%s)", status, body)
		}
		if echo.pin != testPin {
			t.Fatalf("%s = %q, want %q", functionIDHeader, echo.pin, testPin)
		}
		if !strings.Contains(body, `"model":"moonshotai/kimi-k3"`) {
			t.Fatalf("handler saw %s", body)
		}
		// The rewritten model must still route: that is what cliproxy checks.
		if _, err := models.Lookup(bodyModel(t, []byte(body))); err != nil {
			t.Fatalf("routed model not in registry: %v", err)
		}
	})

	t.Run("header pin only", func(t *testing.T) {
		status, echo, body := post("/v1/chat/completions",
			`{"model":"moonshotai/kimi-k3","messages":[]}`, map[string]string{functionIDHeader: testPin})
		if status != http.StatusOK || echo.pin != testPin || !strings.Contains(body, `"model":"moonshotai/kimi-k3"`) {
			t.Fatalf("status=%d pin=%q body=%s", status, echo.pin, body)
		}
	})

	t.Run("body pin wins over header pin", func(t *testing.T) {
		_, echo, _ := post("/v1/chat/completions",
			`{"model":"`+testPin+`@moonshotai/kimi-k3"}`, map[string]string{functionIDHeader: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"})
		if echo.pin != testPin {
			t.Fatalf("pin = %q, want the body pin %q", echo.pin, testPin)
		}
	})

	t.Run("unpinned request is untouched", func(t *testing.T) {
		status, echo, body := post("/v1/chat/completions", `{"model":"moonshotai/kimi-k3","messages":[]}`, nil)
		if status != http.StatusOK || echo.pin != "" || body != `{"model":"moonshotai/kimi-k3","messages":[]}` {
			t.Fatalf("status=%d pin=%q body=%s", status, echo.pin, body)
		}
	})

	t.Run("unlisted pinned model routes via headers and the default carrier", func(t *testing.T) {
		status, echo, body := post("/v1/chat/completions",
			`{"model":"`+testPin+`@qwen3.8-2.4t-a95b","messages":[]}`, nil)
		if status != http.StatusOK {
			t.Fatalf("status=%d body=%s", status, body)
		}
		if echo.pin != testPin || echo.slug != "qwen3.8-2.4t-a95b" {
			t.Fatalf("pin=%q slug=%q", echo.pin, echo.slug)
		}
		if !strings.Contains(body, `"model":"`+models.DefaultModel+`"`) {
			t.Fatalf("handler body = %s, want carrier %s", body, models.DefaultModel)
		}
	})

	t.Run("malformed pin returns 400", func(t *testing.T) {
		status, _, msg := post("/v1/chat/completions", `{"model":"bad id@moonshotai/kimi-k3"}`, nil)
		if status != http.StatusBadRequest || !strings.Contains(msg, "nv-function-id") {
			t.Fatalf("status=%d msg=%s", status, msg)
		}
	})

	t.Run("other endpoints are skipped", func(t *testing.T) {
		status, echo, body := post("/v1/images/generations", `{"model":"`+testPin+`@moonshotai/kimi-k3"}`, nil)
		if status != http.StatusOK || echo.pin != "" || !strings.Contains(body, testPin) {
			t.Fatalf("status=%d pin=%q body=%s", status, echo.pin, body)
		}
	})
}

// bodyModel reads the top-level model field back out of a request body.
func bodyModel(t *testing.T, body []byte) string {
	t.Helper()
	var probe struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return probe.Model
}
