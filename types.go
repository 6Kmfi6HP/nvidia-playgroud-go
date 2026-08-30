// Package glm52 provides a Go client for NVIDIA Build Playground's anonymous
// predict API. It is multi-model: requests are routed by model id through the
// registry in internal/models (default: moonshotai/kimi-k3; z-ai/glm-5.2 was
// removed upstream in 2026-08). Auth is a one-shot P1_ hCaptcha token — minted
// by the pure-Go PoW solver, or taken from the browser widget.
//
// Usage:
//
//	client := glm52.New(glm52.WithCaptchaToken("P1_...")) // default model: moonshotai/kimi-k3
//
//	// Simple chat
//	resp, _ := client.Chat(ctx, []Message{{Role: "user", Content: "Hi"}})
//	fmt.Println(resp.Choices[0].Message.Content)
//
//	// Streaming chat
//	client.StreamChat(ctx, []Message{{Role: "user", Content: "Hi"}},
//	    func(chunk ChatChunk) { fmt.Print(chunk.Content) })
package glm52

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// --- types ---

// Role constants.
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleContext   = "context"
)

// Message represents a single chat message.
// When Thinking is enabled, assistant deltas/messages may include ReasoningContent.
// Upstream may send JSON null for Content or ReasoningContent; that unmarshals to "".
type Message struct {
	Role             string `json:"role,omitempty"`
	Content          string `json:"content,omitempty"`
	ReasoningContent string `json:"reasoning_content,omitempty"`
}

// ChatRequest is the request body sent to the predict API.
type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature,omitempty"`
	TopP        float64   `json:"top_p,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Seed        int       `json:"seed,omitempty"`
	Stream      bool      `json:"stream,omitempty"`

	// Extra body for NVIDIA-specific features (thinking, etc.).
	ChatTemplateKwargs map[string]any `json:"chat_template_kwargs,omitempty"`
	StreamOptions      *StreamOptions `json:"stream_options,omitempty"`
}

// StreamOptions controls SSE streaming metadata.
type StreamOptions struct {
	IncludeUsage         bool `json:"include_usage"`
	ContinuousUsageStats bool `json:"continuous_usage_stats"`
}

// ChatResponse is the non-streaming response (also used as final assembled result).
// Field set matches NVIDIA playground predict (OpenAI chat.completion shape).
type ChatResponse struct {
	ID                string   `json:"id"`
	Object            string   `json:"object"`
	Created           int64    `json:"created"`
	Model             string   `json:"model"`
	Choices           []Choice `json:"choices"`
	Usage             *Usage   `json:"usage,omitempty"`
	SystemFingerprint string   `json:"system_fingerprint,omitempty"`
	ServiceTier       string   `json:"service_tier,omitempty"`
}

// Choice is a single completion choice.
type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
	// Logprobs is opaque; upstream currently returns null.
	Logprobs any `json:"logprobs,omitempty"`
}

// PromptTokensDetails is nested under usage when the backend reports prompt breakdowns.
// Observed on cache hits: {"audio_tokens":null,"cached_tokens":N}.
type PromptTokensDetails struct {
	CachedTokens *int `json:"cached_tokens"`
	AudioTokens  *int `json:"audio_tokens"`
}

// Usage contains token usage stats from upstream predict responses.
type Usage struct {
	PromptTokens        int                  `json:"prompt_tokens"`
	CompletionTokens    int                  `json:"completion_tokens"`
	TotalTokens         int                  `json:"total_tokens"`
	PromptTokensDetails *PromptTokensDetails `json:"prompt_tokens_details,omitempty"`
}

// CachedTokens returns prompt cache hit count when prompt_tokens_details.cached_tokens is set.
func (u *Usage) CachedTokens() int {
	if u == nil || u.PromptTokensDetails == nil || u.PromptTokensDetails.CachedTokens == nil {
		return 0
	}
	return *u.PromptTokensDetails.CachedTokens
}

// Format returns a compact human-readable usage line for CLI display.
func (u *Usage) Format() string {
	if u == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d prompt + %d completion = %d total",
		u.PromptTokens, u.CompletionTokens, u.TotalTokens)
	if c := u.CachedTokens(); c > 0 {
		b.WriteString(" (cached ")
		b.WriteString(strconv.Itoa(c))
		b.WriteByte(')')
	} else if u.PromptTokensDetails != nil && u.PromptTokensDetails.CachedTokens != nil {
		b.WriteString(" (cached 0)")
	}
	return b.String()
}

// ChatChunk is a single SSE data chunk (streaming).
// Object is typically "chat.completion.chunk". Final usage-only chunks may have empty Choices.
type ChatChunk struct {
	ID                string        `json:"id"`
	Object            string        `json:"object"`
	Created           int64         `json:"created"`
	Model             string        `json:"model"`
	Choices           []ChunkChoice `json:"choices"`
	Usage             *Usage        `json:"usage,omitempty"`
	SystemFingerprint string        `json:"system_fingerprint,omitempty"`
	ServiceTier       string        `json:"service_tier,omitempty"`
}

// ChunkChoice is a delta choice for streaming.
type ChunkChoice struct {
	Index        int     `json:"index"`
	Delta        Message `json:"delta"`
	FinishReason string  `json:"finish_reason"`
	// Logprobs is opaque; upstream currently returns null.
	Logprobs any `json:"logprobs,omitempty"`
}

// ErrorResponse represents an API error.
type ErrorResponse struct {
	RequestStatus struct {
		StatusCode        string `json:"statusCode"`
		StatusDescription string `json:"statusDescription"`
		RequestID         string `json:"requestId"`
	} `json:"requestStatus"`
}

func (e *ErrorResponse) Error() string {
	return e.RequestStatus.StatusDescription
}

// --- constants ---

const (
	// DefaultModel is the default playground model id (the historical
	// z-ai/glm-5.2 was removed from NVIDIA's anonymous catalog in 2026-08).
	DefaultModel = "moonshotai/kimi-k3"

	// PredictEndpoint is the reverse-engineered Playground API endpoint
	// (buildapi gateway used since 2026-08; api.ngc.nvidia.com 404s now).
	PredictEndpoint = "https://buildapi.ngc.nvidia.com/v2/predict/models/qc69jvmznzxy/kimi-k3"

	// NVFunctionID is the static NVCF function identifier for the default
	// model.
	NVFunctionID = "1586112a-925c-48af-8631-7c815dbd749c"

	defaultMaxTokens = 16384
	defaultSeed      = 42
	defaultTemp      = 1.0
	// top_p is omitted by default: several 2026-08 catalog models
	// (e.g. kimi-k3) reject it with 400 from the grpc backend.
	defaultTopP    = 0.0
	requestTimeout = 120 * time.Second
)
