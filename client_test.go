package glm52

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestBuildRequestUsesCaptchaAuthentication(t *testing.T) {
	client := New(WithCaptchaToken("test-captcha-token"))
	chatRequest := &ChatRequest{
		Model: DefaultModel,
		Messages: []Message{
			{Role: RoleUser, Content: "Hello"},
		},
	}

	req, err := client.buildRequest(context.Background(), chatRequest)
	if err != nil {
		t.Fatalf("buildRequest() error = %v", err)
	}

	if req.Method != http.MethodPost {
		t.Errorf("method = %q, want %q", req.Method, http.MethodPost)
	}
	if req.URL.String() != PredictEndpoint {
		t.Errorf("URL = %q, want %q", req.URL.String(), PredictEndpoint)
	}

	wantHeaders := map[string]string{
		"Content-Type":     "application/json",
		"Accept":           "text/event-stream",
		"nv-function-id":   NVFunctionID,
		"nv-captcha-token": "test-captcha-token",
		"Origin":           "https://build.nvidia.com",
		"Referer":          "https://build.nvidia.com/",
	}
	for name, want := range wantHeaders {
		if got := req.Header.Get(name); got != want {
			t.Errorf("header %q = %q, want %q", name, got, want)
		}
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization header = %q, want empty", got)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	var got ChatRequest
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	if got.Model != chatRequest.Model {
		t.Errorf("body model = %q, want %q", got.Model, chatRequest.Model)
	}
	if len(got.Messages) != 1 || got.Messages[0] != chatRequest.Messages[0] {
		t.Errorf("body messages = %#v, want %#v", got.Messages, chatRequest.Messages)
	}
}

func TestApplyDefaultsSkipsThinkingForUnverifiedModel(t *testing.T) {
	// The default model (kimi-k3) has no Capability.Thinking hint, so the
	// client must NOT inject chat_template_kwargs (upstream 400s on it).
	client := New(WithCaptchaToken("t"))
	req := &ChatRequest{Messages: []Message{{Role: RoleUser, Content: "Hi"}}}
	client.applyDefaults(req)
	if len(req.ChatTemplateKwargs) != 0 {
		t.Fatalf("chat_template_kwargs = %#v, want none for unverified model", req.ChatTemplateKwargs)
	}
}

func TestApplyDefaultsEnablesThinkingWhenExplicit(t *testing.T) {
	client := New(WithCaptchaToken("t"), WithThinking(true))
	req := &ChatRequest{Messages: []Message{{Role: RoleUser, Content: "Hi"}}}
	client.applyDefaults(req)
	if req.ChatTemplateKwargs["enable_thinking"] != true {
		t.Fatalf("enable_thinking = %#v, want true", req.ChatTemplateKwargs["enable_thinking"])
	}
	if req.ChatTemplateKwargs["clear_thinking"] != false {
		t.Fatalf("clear_thinking = %#v, want false", req.ChatTemplateKwargs["clear_thinking"])
	}
}

func TestWithThinkingFalse(t *testing.T) {
	client := New(WithCaptchaToken("t"), WithThinking(false))
	req := &ChatRequest{Messages: []Message{{Role: RoleUser, Content: "Hi"}}}
	client.applyDefaults(req)
	if req.ChatTemplateKwargs != nil {
		t.Fatalf("ChatTemplateKwargs = %#v, want nil when thinking disabled", req.ChatTemplateKwargs)
	}
}

func TestApplyDefaultsPreservesCallerKwargs(t *testing.T) {
	client := New(WithCaptchaToken("t"))
	req := &ChatRequest{
		Messages:           []Message{{Role: RoleUser, Content: "Hi"}},
		ChatTemplateKwargs: map[string]any{"enable_thinking": false},
	}
	client.applyDefaults(req)
	if req.ChatTemplateKwargs["enable_thinking"] != false {
		t.Fatalf("got %#v", req.ChatTemplateKwargs)
	}
}

func TestApplyDefaultsFillsEmptyKwargsWhenExplicit(t *testing.T) {
	client := New(WithCaptchaToken("t"), WithThinking(true))
	req := &ChatRequest{
		Messages:           []Message{{Role: RoleUser, Content: "Hi"}},
		ChatTemplateKwargs: map[string]any{},
	}
	client.applyDefaults(req)
	if req.ChatTemplateKwargs["enable_thinking"] != true {
		t.Fatalf("empty kwargs should get defaults, got %#v", req.ChatTemplateKwargs)
	}
}

// buildRequest must route each model to its own NVCF endpoint + function-id, not
// a single hardcoded GLM endpoint. Pinned to two concrete registry entries so a
// future scrape that changes their ids is caught here.
func TestBuildRequestRoutesPerModel(t *testing.T) {
	client := New(WithCaptchaToken("tok"))
	cases := map[string]struct {
		endpoint string
		fnID     string
	}{
		"moonshotai/kimi-k3": {
			"https://buildapi.ngc.nvidia.com/v2/predict/models/qc69jvmznzxy/kimi-k3",
			"1586112a-925c-48af-8631-7c815dbd749c",
		},
		"deepseek-ai/deepseek-v4-pro-0813": {
			"https://buildapi.ngc.nvidia.com/v2/predict/models/qc69jvmznzxy/deepseek-v4-pro-0813",
			"6e70713f-4eeb-4ef7-b4f8-2d984f4141f6",
		},
	}
	for model, want := range cases {
		req, err := client.buildRequest(context.Background(), &ChatRequest{
			Model: model, Messages: []Message{{Role: RoleUser, Content: "Hi"}},
		})
		if err != nil {
			t.Errorf("%s: buildRequest: %v", model, err)
			continue
		}
		if got := req.URL.String(); got != want.endpoint {
			t.Errorf("%s: endpoint = %q want %q", model, got, want.endpoint)
		}
		if got := req.Header.Get("nv-function-id"); got != want.fnID {
			t.Errorf("%s: nv-function-id = %q want %q", model, got, want.fnID)
		}
	}
}

func TestBuildRequestUnknownModel(t *testing.T) {
	client := New(WithCaptchaToken("tok"))
	_, err := client.buildRequest(context.Background(), &ChatRequest{
		Model: "no-such-org/never", Messages: []Message{{Role: RoleUser, Content: "Hi"}},
	})
	if err == nil {
		t.Fatal("expected error for unknown model")
	}
	if !strings.Contains(err.Error(), "no-such-org/never") {
		t.Fatalf("error %q should name the model", err.Error())
	}
}
