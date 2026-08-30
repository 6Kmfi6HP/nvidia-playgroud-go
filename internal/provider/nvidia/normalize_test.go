package nvidia

import (
	"encoding/json"
	"testing"

	"glm52-nvidia/internal/models"
)

func TestNormalizeRequestBody(t *testing.T) {
	in := []byte(`{"stream":true,"messages":[]}`)
	out, err := NormalizeRequestBody(in)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	opts := raw["stream_options"].(map[string]any)
	if opts["continuous_usage_stats"] != false {
		t.Fatalf("got %#v", opts["continuous_usage_stats"])
	}
	if _, ok := raw["chat_template_kwargs"]; ok {
		t.Fatalf("thinking kwargs should not be injected without a supported model: %#v", raw)
	}
}

func TestNormalizeRequestBodyEmptyOrNullKwargs(t *testing.T) {
	cases := []string{
		`{"model":"qwen/qwen3-next-80b-a3b-instruct","stream":false,"chat_template_kwargs":{}}`,
		`{"model":"qwen/qwen3-next-80b-a3b-instruct","stream":false,"chat_template_kwargs":null}`,
	}
	for _, in := range cases {
		out, err := NormalizeRequestBody([]byte(in))
		if err != nil {
			t.Fatalf("in=%s: %v", in, err)
		}
		var raw map[string]any
		if err := json.Unmarshal(out, &raw); err != nil {
			t.Fatal(err)
		}
		if kw, ok := raw["chat_template_kwargs"].(map[string]any); ok && len(kw) != 0 {
			t.Fatalf("in=%s thinking kwargs = %#v", in, kw)
		}
	}
}

func TestNormalizeRequestBodyPreservesThinking(t *testing.T) {
	in := []byte(`{"model":"google/diffusiongemma-26b-a4b-it","stream":false,"chat_template_kwargs":{"enable_thinking":false}}`)
	out, err := NormalizeRequestBody(in)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	kw := raw["chat_template_kwargs"].(map[string]any)
	if kw["enable_thinking"] != false {
		t.Fatalf("should preserve caller kwargs, got %#v", kw)
	}
}

func TestNormalizeThinkingKwargsAliases(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		want     map[string]any
		stripped []string
	}{
		{
			name: "zai thinking enabled",
			in:   `{"model":"google/diffusiongemma-26b-a4b-it","stream":false,"thinking":{"type":"enabled","clear_thinking":false}}`,
			want: map[string]any{
				"enable_thinking": true,
				"clear_thinking":  false,
			},
			stripped: []string{"thinking"},
		},
		{
			name: "zai thinking disabled",
			in:   `{"model":"google/diffusiongemma-26b-a4b-it","stream":false,"thinking":{"type":"disabled"}}`,
			want: map[string]any{
				"enable_thinking": false,
			},
			stripped: []string{"thinking"},
		},
		{
			name: "top-level enable_thinking false",
			in:   `{"model":"google/diffusiongemma-26b-a4b-it","stream":false,"enable_thinking":false}`,
			want: map[string]any{
				"enable_thinking": false,
			},
			stripped: []string{"enable_thinking"},
		},
		{
			name: "top-level enable_thinking true + effort",
			in:   `{"model":"google/diffusiongemma-26b-a4b-it","stream":false,"enable_thinking":true,"reasoning_effort":"high"}`,
			want: map[string]any{
				"enable_thinking": true,
			},
			stripped: []string{"enable_thinking", "reasoning_effort"},
		},
		{
			name: "kwargs wins over aliases",
			in:   `{"model":"google/diffusiongemma-26b-a4b-it","stream":false,"chat_template_kwargs":{"enable_thinking":false},"thinking":{"type":"enabled"},"enable_thinking":true}`,
			want: map[string]any{
				"enable_thinking": false,
			},
			stripped: []string{"thinking", "enable_thinking"},
		},
		{
			name: "disabled thinking removes conflicting effort",
			in:   `{"model":"google/diffusiongemma-26b-a4b-it","stream":false,"chat_template_kwargs":{"enable_thinking":false},"reasoning_effort":"high"}`,
			want: map[string]any{
				"enable_thinking": false,
			},
			stripped: []string{"reasoning_effort"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := NormalizeRequestBody([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]any
			if err := json.Unmarshal(out, &raw); err != nil {
				t.Fatal(err)
			}
			for _, key := range tc.stripped {
				if _, ok := raw[key]; ok {
					t.Fatalf("alias %q should be stripped, body=%#v", key, raw)
				}
			}
			kw := raw["chat_template_kwargs"].(map[string]any)
			if len(kw) != len(tc.want) {
				t.Fatalf("kwargs=%#v want %#v", kw, tc.want)
			}
			for k, v := range tc.want {
				if kw[k] != v {
					t.Fatalf("kwargs[%q]=%#v want %#v (full=%#v)", k, kw[k], v, kw)
				}
			}
		})
	}
}

func TestNormalizeRequestBodyMapsReasoningEffortByModel(t *testing.T) {
	cases := []struct {
		name  string
		model string
		in    string
		key   string
		want  any
	}{
		{name: "deepseek low rounds up to high", model: "deepseek-ai/deepseek-v4-pro-0813", in: "low", key: "reasoning_effort", want: "high"},
		{name: "deepseek medium rounds up to high", model: "deepseek-ai/deepseek-v4-flash-0731", in: "medium", key: "reasoning_effort", want: "high"},
		{name: "deepseek xhigh rounds up to max", model: "deepseek-ai/deepseek-v4-pro-0813", in: "xhigh", key: "reasoning_effort", want: "max"},
		{name: "nemotron ultra max caps at high", model: "nvidia/nemotron-3-ultra-550b-a55b", in: "max", key: "reasoning_effort", want: "high"},
		{name: "diffusiongemma high enables thinking", model: "google/diffusiongemma-26b-a4b-it", in: "high", key: "enable_thinking", want: true},
		{name: "diffusiongemma none disables thinking", model: "google/diffusiongemma-26b-a4b-it", in: "none", key: "enable_thinking", want: false},
		{name: "diffusiongemma high enables thinking", model: "google/diffusiongemma-26b-a4b-it", in: "high", key: "enable_thinking", want: true},
		{name: "qwen none disables thinking", model: "google/diffusiongemma-26b-a4b-it", in: "none", key: "enable_thinking", want: false},
		{name: "qwen high enables thinking", model: "google/diffusiongemma-26b-a4b-it", in: "high", key: "enable_thinking", want: true},
		{name: "minimax medium uses adaptive thinking", model: "minimaxai/minimax-m3", in: "medium", key: "thinking_mode", want: "adaptive"},
		{name: "minimax xhigh enables thinking", model: "minimaxai/minimax-m3", in: "xhigh", key: "thinking_mode", want: "enabled"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"model":"` + tc.model + `","reasoning_effort":"` + tc.in + `","stream":false}`)
			out, err := NormalizeRequestBody(body)
			if err != nil {
				t.Fatal(err)
			}

			var raw map[string]any
			if err := json.Unmarshal(out, &raw); err != nil {
				t.Fatal(err)
			}
			kw, ok := raw["chat_template_kwargs"].(map[string]any)
			if !ok {
				t.Fatalf("chat_template_kwargs missing from %s", out)
			}
			if got := kw[tc.key]; got != tc.want {
				t.Fatalf("%s=%#v want %#v (body=%s)", tc.key, got, tc.want, out)
			}
			if _, ok := raw["reasoning_effort"]; ok {
				t.Fatalf("reasoning_effort alias was not consumed: %s", out)
			}
		})
	}
}

func TestNormalizeRequestBodyDoesNotInjectThinkingIntoUnsupportedModel(t *testing.T) {
	out, err := NormalizeRequestBody([]byte(`{"model":"qwen/qwen3-next-80b-a3b-instruct","messages":[],"stream":false}`))
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["chat_template_kwargs"]; ok {
		t.Fatalf("unsupported model received thinking kwargs: %s", out)
	}
}

func TestReasoningProfilesReferenceRegisteredModels(t *testing.T) {
	for model := range reasoningProfiles {
		if _, err := models.Lookup(model); err != nil {
			t.Errorf("reasoning profile references unsupported model %q: %v", model, err)
		}
	}
}
