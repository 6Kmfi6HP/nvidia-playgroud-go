package main

import (
	"context"
	"strings"
	"testing"

	"glm52-nvidia/internal/models"
)

func TestResolveTarget(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config
		wantURL string
		wantFID string
		wantMod string
		wantErr string
	}{
		{
			name:    "no flags falls back to the default registry model",
			cfg:     config{},
			wantURL: models.PredictBase + "/v2/predict/models/qc69jvmznzxy/kimi-k3",
			wantFID: "1586112a-925c-48af-8631-7c815dbd749c",
			wantMod: models.DefaultModel,
		},
		{
			name:    "registry model fills the triple",
			cfg:     config{model: "minimaxai/minimax-m3"},
			wantURL: models.PredictBase + "/v2/predict/models/qc69jvmznzxy/minimax-m3",
			wantFID: "87ea0ddc-cff1-4bca-bf8b-3bd98a35ddd0",
			wantMod: "minimaxai/minimax-m3",
		},
		{
			name: "explicit flags override the registry",
			cfg: config{
				model:      "minimaxai/minimax-m3",
				namespace:  "otherns",
				slug:       "some-slug",
				functionID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			},
			wantURL: models.PredictBase + "/v2/predict/models/otherns/some-slug",
			wantFID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			wantMod: "minimaxai/minimax-m3",
		},
		{
			name:    "slug override keeps the pinned function id",
			cfg:     config{model: "moonshotai/kimi-k3", slug: "kimi-k2"},
			wantURL: models.PredictBase + "/v2/predict/models/qc69jvmznzxy/kimi-k2",
			wantFID: "1586112a-925c-48af-8631-7c815dbd749c",
			wantMod: "moonshotai/kimi-k3",
		},
		{
			name:    "unknown model with a pinned triple",
			cfg:     config{model: "acme/new-llm", slug: "new-llm", functionID: "fid-1"},
			wantURL: models.PredictBase + "/v2/predict/models/qc69jvmznzxy/new-llm",
			wantFID: "fid-1",
			wantMod: "acme/new-llm",
		},
		{
			name:    "unknown model without a triple fails with guidance",
			cfg:     config{model: "acme/new-llm"},
			wantErr: "pass -slug and -function-id",
		},
		{
			name:    "model-field pin overrides only the function id",
			cfg:     config{model: "4f1a2b3c-0000-4000-8000-000000000001@moonshotai/kimi-k3"},
			wantURL: models.PredictBase + "/v2/predict/models/qc69jvmznzxy/kimi-k3",
			wantFID: "4f1a2b3c-0000-4000-8000-000000000001",
			wantMod: "moonshotai/kimi-k3",
		},
		{
			name: "explicit -function-id wins over the model-field pin",
			cfg: config{
				model:      "4f1a2b3c-0000-4000-8000-000000000001@moonshotai/kimi-k3",
				functionID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			},
			wantURL: models.PredictBase + "/v2/predict/models/qc69jvmznzxy/kimi-k3",
			wantFID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			wantMod: "moonshotai/kimi-k3",
		},
		{
			name:    "pin on an unknown model still needs the triple",
			cfg:     config{model: "4f1a2b3c-0000-4000-8000-000000000001@acme/new-llm"},
			wantErr: "unknown model: acme/new-llm",
		},
		{
			name:    "malformed pin is rejected",
			cfg:     config{model: "not a uuid@moonshotai/kimi-k3"},
			wantErr: "invalid nv-function-id",
		},
		{
			name:    "pin without a model is rejected",
			cfg:     config{model: "4f1a2b3c-0000-4000-8000-000000000001@"},
			wantErr: "missing model id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, model, err := resolveTarget(&tt.cfg)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveTarget: %v", err)
			}
			if got := info.PredictEndpoint(); got != tt.wantURL {
				t.Errorf("endpoint = %s, want %s", got, tt.wantURL)
			}
			if info.FunctionID != tt.wantFID {
				t.Errorf("function-id = %s, want %s", info.FunctionID, tt.wantFID)
			}
			if model != tt.wantMod {
				t.Errorf("body model = %s, want %s", model, tt.wantMod)
			}
		})
	}
}

// TestResolveTargetCapability checks the thinking-capability propagation that
// drives -thinking=auto: carried over when the slug matches the registry
// entry, dropped when -slug points at a different endpoint.
func TestResolveTargetCapability(t *testing.T) {
	orig := models.All()
	defer models.Replace(orig)
	models.Replace(map[string]models.ModelInfo{
		"acme/thinker": {
			Slug: "thinker", Namespace: "ns9", FunctionID: "fid9",
			Capability: &models.ModelCapability{Thinking: true},
		},
	})

	matched, _, err := resolveTarget(&config{model: "acme/thinker"})
	if err != nil {
		t.Fatal(err)
	}
	if matched.Capability == nil || !matched.Capability.Thinking {
		t.Errorf("matching slug should carry the capability, got %+v", matched.Capability)
	}

	overridden, _, err := resolveTarget(&config{model: "acme/thinker", slug: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if overridden.Capability != nil {
		t.Errorf("overridden slug should drop the capability, got %+v", overridden.Capability)
	}
}

func TestBuildMessages(t *testing.T) {
	t.Run("system plus prompt", func(t *testing.T) {
		msgs, err := buildMessages(&config{system: "s", prompt: "p"})
		if err != nil {
			t.Fatal(err)
		}
		if len(msgs) != 2 || msgs[0].Role != "system" || msgs[1].Content != "p" {
			t.Fatalf("got %+v", msgs)
		}
	})

	t.Run("messages json", func(t *testing.T) {
		msgs, err := buildMessages(&config{messages: `[{"role":"user","content":"hi"}]`, prompt: "ignored"})
		if err != nil {
			t.Fatal(err)
		}
		if len(msgs) != 1 || msgs[0].Content != "hi" {
			t.Fatalf("got %+v", msgs)
		}
	})

	t.Run("messages json wins over prompt", func(t *testing.T) {
		if _, err := buildMessages(&config{messages: `[]`}); err == nil {
			t.Fatal("empty array should error")
		}
		if _, err := buildMessages(&config{messages: `not json`}); err == nil {
			t.Fatal("invalid json should error")
		}
	})
}

func TestCurlCommand(t *testing.T) {
	info := models.ModelInfo{Namespace: "ns1", Slug: "sl1", FunctionID: "fid1"}
	cmd := curlCommand(info, "P1_tok", []byte(`{"model":"a/b","messages":[{"role":"user","content":"it's"}]}`))

	for _, want := range []string{
		"/v2/predict/models/ns1/sl1",
		"-H 'nv-function-id: fid1'",
		"-H 'nv-captcha-token: P1_tok'",
		`'\''`, // embedded single quote escaped for the shell
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("curl output missing %q:\n%s", want, cmd)
		}
	}
}

func TestTokenForRejectsReplay(t *testing.T) {
	c := &config{captcha: "P1_one_shot"}
	if tok, err := c.tokenFor(context.TODO(), 1); err != nil || tok != "P1_one_shot" {
		t.Fatalf("first use: tok=%q err=%v", tok, err)
	}
	if _, err := c.tokenFor(context.TODO(), 2); err == nil {
		t.Fatal("replaying a one-shot token should error")
	}
}
