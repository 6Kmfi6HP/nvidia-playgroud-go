package nvidia

import (
	"encoding/json"
	"testing"
)

// Fixtures captured from api.ngc.nvidia.com playground predict (z-ai/glm-5.2).

const fixtureNonStreamCold = `{
  "choices": [
    {
      "finish_reason": "stop",
      "index": 0,
      "logprobs": null,
      "message": {
        "content": "cold",
        "reasoning_content": null,
        "role": "assistant"
      }
    }
  ],
  "created": 1784881313,
  "id": "chatcmpl-5fef88e4-45d9-46d8-82c0-6039b34997b3",
  "model": "z-ai/glm-5.2",
  "object": "chat.completion",
  "service_tier": null,
  "system_fingerprint": null,
  "usage": {
    "completion_tokens": 2,
    "prompt_tokens": 1219,
    "total_tokens": 1221
  }
}`

const fixtureNonStreamThinking = `{
  "choices": [
    {
      "finish_reason": "length",
      "index": 0,
      "logprobs": null,
      "message": {
        "content": null,
        "reasoning_content": "thinking…",
        "role": "assistant"
      }
    }
  ],
  "created": 1784881374,
  "id": "chatcmpl-0d99b044-95b7-49d1-b285-7462294364fe",
  "model": "z-ai/glm-5.2",
  "object": "chat.completion",
  "service_tier": null,
  "system_fingerprint": null,
  "usage": {
    "completion_tokens": 128,
    "prompt_tokens": 26,
    "total_tokens": 154
  }
}`

const fixtureStreamDelta = `{
  "choices": [
    {
      "delta": {
        "content": "done",
        "role": "assistant"
      },
      "finish_reason": null,
      "index": 0,
      "logprobs": null
    }
  ],
  "created": 1784881325,
  "id": "chatcmpl-198f4acd-4e2a-4ffd-b665-fea0bd1f8ac6",
  "model": "z-ai/glm-5.2",
  "object": "chat.completion.chunk",
  "service_tier": null,
  "system_fingerprint": null,
  "usage": null
}`

const fixtureStreamUsageCached = `{
  "choices": [],
  "created": 1784880000,
  "id": "chatcmpl-cache-hit",
  "model": "z-ai/glm-5.2",
  "object": "chat.completion.chunk",
  "service_tier": null,
  "system_fingerprint": null,
  "usage": {
    "completion_tokens": 3,
    "prompt_tokens": 1269,
    "prompt_tokens_details": {
      "audio_tokens": null,
      "cached_tokens": 1216
    },
    "total_tokens": 1272
  }
}`

func TestUnmarshalChatResponseCold(t *testing.T) {
	var resp ChatResponse
	if err := json.Unmarshal([]byte(fixtureNonStreamCold), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Object != "chat.completion" {
		t.Fatalf("object=%q", resp.Object)
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("choices=%d", len(resp.Choices))
	}
	ch := resp.Choices[0]
	if ch.Message.Content != "cold" {
		t.Fatalf("content=%q", ch.Message.Content)
	}
	if ch.Message.ReasoningContent != "" {
		t.Fatalf("reasoning should be empty for null, got %q", ch.Message.ReasoningContent)
	}
	if ch.Logprobs != nil {
		t.Fatalf("logprobs=%#v want nil", ch.Logprobs)
	}
	if resp.Usage == nil || resp.Usage.PromptTokens != 1219 || resp.Usage.CachedTokens() != 0 {
		t.Fatalf("usage=%#v", resp.Usage)
	}
	if resp.ServiceTier != "" || resp.SystemFingerprint != "" {
		t.Fatalf("null tiers should be empty strings: tier=%q fp=%q", resp.ServiceTier, resp.SystemFingerprint)
	}
}

func TestUnmarshalChatResponseThinkingNullContent(t *testing.T) {
	var resp ChatResponse
	if err := json.Unmarshal([]byte(fixtureNonStreamThinking), &resp); err != nil {
		t.Fatal(err)
	}
	msg := resp.Choices[0].Message
	if msg.Content != "" {
		t.Fatalf("null content -> %q", msg.Content)
	}
	if msg.ReasoningContent != "thinking…" {
		t.Fatalf("reasoning=%q", msg.ReasoningContent)
	}
	if resp.Choices[0].FinishReason != "length" {
		t.Fatalf("finish=%q", resp.Choices[0].FinishReason)
	}
}

func TestUnmarshalChatChunkDeltaAndCachedUsage(t *testing.T) {
	var delta ChatChunk
	if err := json.Unmarshal([]byte(fixtureStreamDelta), &delta); err != nil {
		t.Fatal(err)
	}
	if delta.Object != "chat.completion.chunk" {
		t.Fatalf("object=%q", delta.Object)
	}
	if delta.Usage != nil {
		t.Fatalf("usage should be nil, got %#v", delta.Usage)
	}
	if delta.Choices[0].FinishReason != "" {
		t.Fatalf("null finish_reason -> %q", delta.Choices[0].FinishReason)
	}
	if delta.Choices[0].Delta.Content != "done" {
		t.Fatalf("delta content=%q", delta.Choices[0].Delta.Content)
	}

	var usageChunk ChatChunk
	if err := json.Unmarshal([]byte(fixtureStreamUsageCached), &usageChunk); err != nil {
		t.Fatal(err)
	}
	if len(usageChunk.Choices) != 0 {
		t.Fatalf("choices=%d", len(usageChunk.Choices))
	}
	u := usageChunk.Usage
	if u == nil {
		t.Fatal("usage nil")
	}
	if u.PromptTokens != 1269 || u.CompletionTokens != 3 || u.TotalTokens != 1272 {
		t.Fatalf("usage totals=%#v", u)
	}
	if u.PromptTokensDetails == nil || u.PromptTokensDetails.CachedTokens == nil {
		t.Fatalf("details=%#v", u.PromptTokensDetails)
	}
	if *u.PromptTokensDetails.CachedTokens != 1216 {
		t.Fatalf("cached=%d", *u.PromptTokensDetails.CachedTokens)
	}
	if u.PromptTokensDetails.AudioTokens != nil {
		t.Fatalf("audio_tokens should stay nil, got %#v", u.PromptTokensDetails.AudioTokens)
	}
	if u.CachedTokens() != 1216 {
		t.Fatalf("CachedTokens()=%d", u.CachedTokens())
	}
	got := u.Format()
	want := "1269 prompt + 3 completion = 1272 total (cached 1216)"
	if got != want {
		t.Fatalf("Format()=%q want %q", got, want)
	}
}

func TestUsageFormatNoCache(t *testing.T) {
	u := &Usage{PromptTokens: 10, CompletionTokens: 2, TotalTokens: 12}
	if got := u.Format(); got != "10 prompt + 2 completion = 12 total" {
		t.Fatalf("got %q", got)
	}
	zero := 0
	u.PromptTokensDetails = &PromptTokensDetails{CachedTokens: &zero}
	if got := u.Format(); got != "10 prompt + 2 completion = 12 total (cached 0)" {
		t.Fatalf("got %q", got)
	}
}
