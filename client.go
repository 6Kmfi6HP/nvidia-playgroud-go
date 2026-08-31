package glm52

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"glm52-nvidia/internal/models"
)

// --- Client ---

// Client is the NVIDIA Build Playground predict client (multi-model).
type Client struct {
	captchaToken string // reverse-engineered captcha token

	// HTTP client (can be overridden)
	httpClient *http.Client

	// default request parameters
	model     string
	maxTokens int
	seed      int
	temp      float64
	topP      float64

	// thinking mirrors Playground: chat_template_kwargs.enable_thinking
	thinking *bool

	// infoOverride bypasses registry lookup in buildRequest (custom
	// namespace/slug/function-id targets). Nil means use the registry.
	infoOverride *models.ModelInfo
}

// Option configures the Client.
type Option func(*Client)

// WithCaptchaToken sets the hCaptcha token for the reverse-engineered endpoint.
// Obtain this from the Playground page: widget's data-hcaptcha-response attribute.
func WithCaptchaToken(token string) Option {
	return func(c *Client) { c.captchaToken = token }
}

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithModel overrides the model name.
func WithModel(m string) Option {
	return func(c *Client) { c.model = m }
}

// WithModelInfo pins the NVCF invocation target (namespace, slug,
// function id) directly, bypassing the model registry. Use it to call a
// predict endpoint the registry does not know yet. The request body's
// model field still comes from WithModel / req.Model.
func WithModelInfo(info models.ModelInfo) Option {
	return func(c *Client) { c.infoOverride = &info }
}

// WithDefaults sets default request parameters.
func WithDefaults(maxTokens int, seed int, temp, topP float64) Option {
	return func(c *Client) {
		c.maxTokens = maxTokens
		c.seed = seed
		c.temp = temp
		c.topP = topP
	}
}

// WithThinking forces thinking mode (reasoning_content) on or off. Without
// it, chat_template_kwargs.enable_thinking is injected only for models that
// declare the Thinking capability (most of the current anonymous catalog
// rejects thinking kwargs with 400).
func WithThinking(enable bool) Option {
	return func(c *Client) { c.thinking = &enable }
}

// New creates a client configured with an hCaptcha token (default model
// moonshotai/kimi-k3; override with WithModel).
func New(opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: requestTimeout},
		model:      DefaultModel,
		maxTokens:  defaultMaxTokens,
		seed:       defaultSeed,
		temp:       defaultTemp,
		topP:       defaultTopP,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// --- internal request helpers ---

func (c *Client) buildRequest(ctx context.Context, req *ChatRequest) (*http.Request, error) {
	model := req.Model
	if model == "" {
		model = c.model
	}
	info, canonical, err := c.modelInfo(model)
	if err != nil {
		return nil, fmt.Errorf("glm52: %w", err)
	}
	// A "<function-id>@<model>" pin selects the NVCF function; the body keeps
	// the plain registry model id NVIDIA expects to see.
	if req.Model == model && model != canonical {
		req.Model = canonical
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("glm52: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", info.PredictEndpoint(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("glm52: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("accept", "text/event-stream")
	httpReq.Header.Set("nv-function-id", info.FunctionID)
	httpReq.Header.Set("nv-captcha-token", c.captchaToken)
	httpReq.Header.Set("Origin", "https://build.nvidia.com")
	httpReq.Header.Set("Referer", "https://build.nvidia.com/")

	return httpReq, nil
}

func (c *Client) applyDefaults(r *ChatRequest) {
	if r.Model == "" {
		r.Model = c.model
	}
	if r.MaxTokens == 0 {
		r.MaxTokens = c.maxTokens
	}
	if r.Seed == 0 {
		r.Seed = c.seed
	}
	if r.Temperature == 0 {
		r.Temperature = c.temp
	}
	if r.TopP == 0 {
		r.TopP = c.topP
	}
	if len(r.ChatTemplateKwargs) == 0 {
		enable := true
		if c.thinking != nil {
			enable = *c.thinking
		} else {
			// Only inject thinking kwargs for models known to accept them
			// (Capability.Thinking). Most of the current anonymous catalog
			// (kimi-k3 etc.) rejects chat_template_kwargs with 400.
			info, _, err := c.modelInfo(r.Model)
			if err != nil || info.Capability == nil || !info.Capability.Thinking {
				return
			}
		}
		if enable {
			r.ChatTemplateKwargs = map[string]any{
				"enable_thinking": true,
				"clear_thinking":  false,
			}
		}
	}
}

// modelInfo resolves the NVCF invocation data for a request and the canonical
// model id to send upstream: the explicit WithModelInfo override when set,
// otherwise the registry. A "<function-id>@<model>" pin overrides the registry
// function id, which is how a caller reaches a specific NVCF instance behind a
// playground slug.
func (c *Client) modelInfo(model string) (models.ModelInfo, string, error) {
	pin, base, hasPin := models.SplitFunctionRef(model)
	if hasPin {
		if err := models.ValidateFunctionRef(pin, base); err != nil {
			return models.ModelInfo{}, "", err
		}
		model = base
	}
	if c.infoOverride != nil {
		return *c.infoOverride, model, nil
	}
	info, err := models.Lookup(model)
	if err != nil {
		return models.ModelInfo{}, "", err
	}
	if hasPin {
		info.FunctionID = pin
	}
	return info, model, nil
}

// --- Public API ---

// Chat sends a synchronous chat completion request.
func (c *Client) Chat(ctx context.Context, messages []Message) (*ChatResponse, error) {
	req := &ChatRequest{
		Messages: messages,
		Stream:   false,
	}
	c.applyDefaults(req)

	var resp ChatResponse
	if err := c.doRequest(ctx, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// StreamChunk is yielded by StreamChat.
type StreamChunk struct {
	Content   string
	Reasoning string // delta.reasoning_content when Thinking is on
	Usage     *Usage
	Done      bool
	Error     error
}

// StreamChat sends a streaming chat completion. Each chunk is delivered to the callback.
// The callback's return value controls whether streaming continues (true = continue).
func (c *Client) StreamChat(ctx context.Context, messages []Message, cb func(StreamChunk)) error {
	req := &ChatRequest{
		Messages: messages,
		Stream:   true,
		StreamOptions: &StreamOptions{
			IncludeUsage:         true,
			ContinuousUsageStats: false, // usage once at end — less payload / cleaner clients
		},
	}
	c.applyDefaults(req)

	return c.doStream(ctx, req, cb)
}

// --- Internal: doRequest (non-streaming) ---

func (c *Client) doRequest(ctx context.Context, req *ChatRequest, target interface{}) error {
	httpReq, err := c.buildRequest(ctx, req)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("glm52: http do: %w", err)
	}
	defer resp.Body.Close()

	// Read full body
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("glm52: read body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return parseError(raw)
	}

	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("glm52: decode response: %w", err)
	}
	return nil
}

// --- Internal: doStream (SSE streaming) ---

func (c *Client) doStream(ctx context.Context, req *ChatRequest, cb func(StreamChunk)) error {
	httpReq, err := c.buildRequest(ctx, req)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("glm52: http do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return parseError(raw)
	}

	// Read SSE stream
	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				cb(StreamChunk{Done: true})
				return nil
			}
			return fmt.Errorf("glm52: read sse: %w", err)
		}

		line = strings.TrimSpace(line)

		// Skip empty lines / comments
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}

		// data: [DONE]
		if line == "data: [DONE]" {
			cb(StreamChunk{Done: true})
			return nil
		}

		// data: {...}
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			var chunk ChatChunk
			if err := json.Unmarshal([]byte(data), &chunk); err != nil {
				cb(StreamChunk{Error: fmt.Errorf("glm52: decode chunk: %w", err)})
				continue
			}

			sc := StreamChunk{}
			if len(chunk.Choices) > 0 {
				sc.Content = chunk.Choices[0].Delta.Content
				sc.Reasoning = chunk.Choices[0].Delta.ReasoningContent
			}
			if chunk.Usage != nil {
				sc.Usage = chunk.Usage
			}
			cb(sc)
		}
	}
}

// --- helpers ---

func parseError(raw []byte) error {
	var apiErr ErrorResponse
	if err := json.Unmarshal(raw, &apiErr); err == nil && apiErr.RequestStatus.StatusCode != "" {
		return &apiErr
	}
	// Try OpenAI error format
	var oaiErr struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &oaiErr); err == nil && oaiErr.Error.Message != "" {
		return fmt.Errorf("glm52: %s: %s", oaiErr.Error.Type, oaiErr.Error.Message)
	}
	return fmt.Errorf("glm52: http error: %s", string(raw[:min(len(raw), 300)]))
}
