package glm52

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"glm52-nvidia/internal/models"
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

// TestBuildRequestAppliesFunctionPin checks the "function-id@model" form: the
// pinned id becomes the nv-function-id header, the endpoint still comes from
// the registry, and the body carries the plain model id.
func TestBuildRequestAppliesFunctionPin(t *testing.T) {
	const pinned = "4f1a2b3c-0000-4000-8000-000000000001"
	client := New(WithCaptchaToken("t"), WithModel(pinned+"@"+DefaultModel))

	req := &ChatRequest{Messages: []Message{{Role: RoleUser, Content: "Hi"}}}
	client.applyDefaults(req)
	httpReq, err := client.buildRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("buildRequest() error = %v", err)
	}
	if httpReq.URL.String() != PredictEndpoint {
		t.Errorf("URL = %q, want the pinned model's endpoint %q", httpReq.URL.String(), PredictEndpoint)
	}
	if got := httpReq.Header.Get("nv-function-id"); got != pinned {
		t.Errorf("nv-function-id = %q, want %q", got, pinned)
	}
	body, err := io.ReadAll(httpReq.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var got ChatRequest
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Model != DefaultModel {
		t.Errorf("body model = %q, want %q without the pin", got.Model, DefaultModel)
	}
	if req.Model != DefaultModel {
		t.Errorf("caller request model = %q, want %q", req.Model, DefaultModel)
	}
}

// TestBuildRequestPinRejectsMalformedID keeps a typo out of the wire: an empty
// or unsafe function id must fail locally instead of 400-ing upstream.
func TestBuildRequestPinRejectsMalformedID(t *testing.T) {
	for _, model := range []string{"@moonshotai/kimi-k3", pinnedBadID + "@moonshotai/kimi-k3", "4f1a2b3c-0000-4000-8000-000000000001@"} {
		client := New(WithCaptchaToken("t"), WithModel(model))
		if _, err := client.buildRequest(context.Background(), &ChatRequest{Model: model, Messages: []Message{{Role: RoleUser, Content: "Hi"}}}); err == nil {
			t.Errorf("buildRequest(%q) error = nil, want a client error", model)
		}
	}
}

const pinnedBadID = "not a uuid"

// TestBuildRequestModelInfoOverrideWins documents the precedence with an
// explicit target: WithModelInfo pins namespace/slug/function id, and a model
// pin only strips itself out of the body.
func TestBuildRequestModelInfoOverrideWins(t *testing.T) {
	const pinned = "4f1a2b3c-0000-4000-8000-000000000001"
	client := New(
		WithCaptchaToken("t"),
		WithModelInfo(models.ModelInfo{Namespace: "ns", Slug: "sl", FunctionID: "override-id"}),
	)
	model := pinned + "@" + DefaultModel
	httpReq, err := client.buildRequest(context.Background(), &ChatRequest{Model: model, Messages: []Message{{Role: RoleUser, Content: "Hi"}}})
	if err != nil {
		t.Fatalf("buildRequest() error = %v", err)
	}
	if got := httpReq.Header.Get("nv-function-id"); got != "override-id" {
		t.Errorf("nv-function-id = %q, want the explicit override", got)
	}
	if want := "https://buildapi.ngc.nvidia.com/v2/predict/models/ns/sl"; httpReq.URL.String() != want {
		t.Errorf("URL = %q, want %q", httpReq.URL.String(), want)
	}
	body, err := io.ReadAll(httpReq.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(httpReq.Body) error = %v", err)
	}
	if strings.Contains(string(body), pinned) {
		t.Errorf("body still carries the pin: %s", body)
	}
}
