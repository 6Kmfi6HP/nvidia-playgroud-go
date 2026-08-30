// cmd/predict — one raw request to the NVIDIA playground predict API, with the
// NVCF invocation triple (nv-function-id, namespace, slug) set from flags and
// nv-captcha-token minted by the pure-Go hCaptcha PoW solver (no browser).
//
// The predict call needs exactly four things:
//
//	POST https://buildapi.ngc.nvidia.com/v2/predict/models/{namespace}/{slug}
//	Content-Type: application/json
//	nv-function-id:   {functionID}      <- per-model NVCF function UUID
//	nv-captcha-token: P1_...            <- one-shot hCaptcha passcode
//	Origin/Referer:   https://build.nvidia.com
//
// No API key, no cookie. The token is single-use and expires in ~2-3 minutes,
// so every request mints a fresh one unless -captcha pins one.
//
// Usage:
//
//	# registry model (default moonshotai/kimi-k3), stream, PoW-minted token
//	go run ./cmd/predict -prompt "ping"
//
//	# another registry model — namespace/slug/function-id come from the table
//	go run ./cmd/predict -model deepseek-ai/deepseek-v4-pro-0813
//
//	# a model the registry does not know yet: pin the triple yourself
//	go run ./cmd/predict -model acme/new-llm -slug new-llm -function-id 6e70713f-4eeb-4ef7-b4f8-2d984f4141f6
//
//	# a different NVCF function behind a known slug (same pin syntax the
//	# gateway accepts in the model field or as the nv-function-id header)
//	go run ./cmd/predict -model 6e70713f-4eeb-4ef7-b4f8-2d984f4141f6@moonshotai/kimi-k3
//
//	# reuse a token captured from the browser widget instead of solving
//	go run ./cmd/predict -captcha "P1_eyJ..." -slug kimi-k3
//
//	# show the known triples / print the equivalent curl without sending
//	go run ./cmd/predict -list
//	go run ./cmd/predict -curl -slug kimi-k3 -function-id 1586112a-925c-48af-8631-7c815dbd749c -captcha P1_x
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"time"

	glm52 "glm52-nvidia"
	"glm52-nvidia/internal/captcha"
	"glm52-nvidia/internal/hcaptcha"
	"glm52-nvidia/internal/hcaptchapow"
	"glm52-nvidia/internal/models"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// config holds every flag, resolved once in run().
type config struct {
	// NVCF invocation target
	namespace  string
	slug       string
	functionID string
	model      string

	// captcha: manual token, or PoW solve parameters
	captcha string
	sitekey string
	host    string

	// request content
	system   string
	prompt   string
	messages string

	// sampling / generation
	stream    bool
	maxTokens int
	seed      int
	temp      float64
	topP      float64
	thinking  string

	// run control
	requests int
	timeout  time.Duration
	list     bool
	curl     bool
	verbose  bool
}

func run() error {
	c := &config{}
	fs := flag.NewFlagSet("predict", flag.ContinueOnError)
	fs.StringVar(&c.namespace, "namespace", "", "NVCF namespace path segment (default: registry value, else "+models.Namespace+")")
	fs.StringVar(&c.slug, "slug", "", "model slug path segment (default: registry value for -model)")
	fs.StringVar(&c.functionID, "function-id", "", "nv-function-id header value (default: registry value for -model)")
	fs.StringVar(&c.model, "model", "", "model id sent in the request body; a \"<function-id>@\" prefix pins the NVCF function (default: "+models.DefaultModel+")")

	fs.StringVar(&c.captcha, "captcha", "", "use this nv-captcha-token instead of solving with PoW")
	fs.StringVar(&c.sitekey, "sitekey", captcha.PlaygroundSitekey, "hCaptcha sitekey to solve for")
	fs.StringVar(&c.host, "host", captcha.PlaygroundHost, "host the hCaptcha widget is served on")

	fs.StringVar(&c.system, "system", "", "optional system message")
	fs.StringVar(&c.prompt, "prompt", "Reply with a one-word answer: are you alive?", "user prompt")
	fs.StringVar(&c.messages, "messages", "", `JSON array of {"role","content"} (string or @file); replaces -system/-prompt`)

	fs.BoolVar(&c.stream, "stream", true, "stream the reply over SSE")
	fs.IntVar(&c.maxTokens, "max-tokens", 16384, "max_tokens")
	fs.IntVar(&c.seed, "seed", 42, "seed")
	fs.Float64Var(&c.temp, "temperature", 1.0, "temperature")
	fs.Float64Var(&c.topP, "top-p", 0, "top_p (0 = omit; some models 400 on it)")
	fs.StringVar(&c.thinking, "thinking", "auto", "reasoning kwargs: auto|on|off (auto = only for models that declare support)")

	fs.IntVar(&c.requests, "n", 1, "number of requests; each mints its own one-shot token")
	fs.DurationVar(&c.timeout, "timeout", 180*time.Second, "total timeout for solving plus requests")
	fs.BoolVar(&c.list, "list", false, "print the model registry (namespace/slug/function-id) and exit")
	fs.BoolVar(&c.curl, "curl", false, "print the equivalent curl command and exit without sending")
	fs.BoolVar(&c.verbose, "v", false, "log the resolved target, per-stage PoW timing, and request headers")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	if c.list {
		printRegistry()
		return nil
	}

	info, model, err := resolveTarget(c)
	if err != nil {
		return err
	}
	msgs, err := buildMessages(c)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, c.timeout)
	defer cancelTimeout()

	if c.curl {
		token, err := c.tokenFor(ctx, 1)
		if err != nil {
			return err
		}
		body, err := c.requestBody(model, msgs)
		if err != nil {
			return err
		}
		fmt.Println(curlCommand(info, token, body))
		return nil
	}

	if c.verbose {
		fmt.Fprintf(os.Stderr, "target: POST %s\n         nv-function-id=%s model=%s stream=%v\n",
			info.PredictEndpoint(), info.FunctionID, model, c.stream)
	}

	for i := 1; i <= c.requests; i++ {
		token, err := c.tokenFor(ctx, i)
		if err != nil {
			return err
		}
		if c.requests > 1 {
			fmt.Fprintf(os.Stderr, "--- request %d/%d ---\n", i, c.requests)
		}
		if err := sendOnce(ctx, c, info, model, token, msgs); err != nil {
			return err
		}
	}
	return nil
}

// tokenFor returns the nv-captcha-token for request n: the pinned -captcha
// value for the first request, otherwise a freshly solved PoW token. Tokens
// are single-use, so a pinned token may not be replayed across -n > 1.
func (c *config) tokenFor(ctx context.Context, n int) (string, error) {
	if c.captcha == "" {
		return mintToken(ctx, c)
	}
	if n > 1 {
		return "", fmt.Errorf("-captcha tokens are one-shot: use -n 1, or drop -captcha to mint one per request")
	}
	return c.captcha, nil
}

// mintToken solves the hCaptcha challenge for (sitekey, host) with the pure-Go
// PoW pipeline and returns the P1_ passcode.
func mintToken(ctx context.Context, c *config) (string, error) {
	start := time.Now()
	token, solve, err := hcaptcha.CaptchaTokenDetail(ctx, c.sitekey, c.host)
	if err != nil {
		return "", fmt.Errorf("solve captcha: %w", err)
	}
	if c.verbose {
		difficulty := "-"
		if pow, perr := hcaptchapow.ParsePow(solve.JWT); perr == nil {
			difficulty = strconv.FormatFloat(pow.Difficulty, 'f', -1, 64)
		}
		fmt.Fprintf(os.Stderr, "pow: minted token in %s difficulty=%s len=%d\n",
			time.Since(start).Round(time.Millisecond), difficulty, len(token))
	}
	return token, nil
}

// resolveTarget turns the flags into the NVCF triple plus the body model id.
// Explicit -namespace/-slug/-function-id always win over the registry, so an
// endpoint the registry has not picked up yet is still callable. A
// "-model <function-id>@<model>" pin overrides just the registry function id,
// which is how a specific NVCF instance behind a known slug is selected.
func resolveTarget(c *config) (models.ModelInfo, string, error) {
	info := models.ModelInfo{
		Namespace:  c.namespace,
		Slug:       c.slug,
		FunctionID: c.functionID,
	}

	pin, base, hasPin := models.SplitFunctionRef(c.model)
	if hasPin {
		if err := models.ValidateFunctionRef(pin, base); err != nil {
			return models.ModelInfo{}, "", err
		}
	} else {
		base = c.model
	}

	reg, regErr := models.Lookup(base)
	if regErr != nil {
		if info.Slug == "" || info.FunctionID == "" {
			return models.ModelInfo{}, "", fmt.Errorf(
				"%w — no namespace/slug/function-id to derive; pass -slug and -function-id (see -list)", regErr)
		}
	} else {
		if info.Namespace == "" {
			info.Namespace = reg.Namespace
		}
		if info.Slug == "" {
			info.Slug = reg.Slug
		}
		if info.FunctionID == "" {
			info.FunctionID = reg.FunctionID
		}
		// Thinking capability only describes the registry model behind this
		// slug; a -slug override points at something else.
		if info.Slug == reg.Slug {
			info.Capability = reg.Capability
		}
	}
	if info.Namespace == "" {
		info.Namespace = models.Namespace
	}
	// -function-id still wins; the model-field pin only beats the registry value.
	if hasPin && c.functionID == "" {
		info.FunctionID = pin
	}

	model := base
	if model == "" {
		model = models.DefaultModel
	}
	return info, model, nil
}

// buildMessages assembles the chat messages from -messages (JSON array, inline
// or @file) or from -system/-prompt.
func buildMessages(c *config) ([]glm52.Message, error) {
	if c.messages != "" {
		raw, err := readArg(c.messages)
		if err != nil {
			return nil, err
		}
		var msgs []glm52.Message
		if err := json.Unmarshal(raw, &msgs); err != nil {
			return nil, fmt.Errorf("-messages: %w", err)
		}
		if len(msgs) == 0 {
			return nil, fmt.Errorf("-messages: empty array")
		}
		return msgs, nil
	}

	msgs := make([]glm52.Message, 0, 2)
	if c.system != "" {
		msgs = append(msgs, glm52.Message{Role: glm52.RoleSystem, Content: c.system})
	}
	msgs = append(msgs, glm52.Message{Role: glm52.RoleUser, Content: c.prompt})
	return msgs, nil
}

// readArg returns s as bytes, reading the file when s starts with "@".
func readArg(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "@") {
		return []byte(s), nil
	}
	raw, err := os.ReadFile(strings.TrimPrefix(s, "@"))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s, err)
	}
	return raw, nil
}

// requestBody mirrors what the client sends, for -curl output only.
func (c *config) requestBody(model string, msgs []glm52.Message) ([]byte, error) {
	req := glm52.ChatRequest{
		Model:       model,
		Messages:    msgs,
		Temperature: c.temp,
		TopP:        c.topP,
		MaxTokens:   c.maxTokens,
		Seed:        c.seed,
		Stream:      c.stream,
	}
	if c.thinking == "on" {
		req.ChatTemplateKwargs = map[string]any{"enable_thinking": true, "clear_thinking": false}
	}
	if c.stream {
		req.StreamOptions = &glm52.StreamOptions{IncludeUsage: true}
	}
	return json.Marshal(req)
}

// sendOnce performs one predict call through the repo client, with the
// invocation triple pinned via WithModelInfo so the registry is bypassed.
func sendOnce(ctx context.Context, c *config, info models.ModelInfo, model, token string, msgs []glm52.Message) error {
	opts := []glm52.Option{
		glm52.WithCaptchaToken(token),
		glm52.WithModelInfo(info),
		glm52.WithModel(model),
		glm52.WithDefaults(c.maxTokens, c.seed, c.temp, c.topP),
	}
	switch c.thinking {
	case "on":
		opts = append(opts, glm52.WithThinking(true))
	case "off":
		opts = append(opts, glm52.WithThinking(false))
	case "auto":
	default:
		return fmt.Errorf("-thinking must be auto|on|off, got %q", c.thinking)
	}
	client := glm52.New(opts...)

	start := time.Now()
	if !c.stream {
		resp, err := client.Chat(ctx, msgs)
		if err != nil {
			return err
		}
		if len(resp.Choices) == 0 {
			fmt.Fprintln(os.Stderr, "(no choices in response)")
			return nil
		}
		msg := resp.Choices[0].Message
		if msg.ReasoningContent != "" {
			fmt.Print(msg.ReasoningContent)
		}
		fmt.Print(msg.Content)
		fmt.Printf("\n\n[done %s finish=%s usage: %s]\n",
			time.Since(start).Round(100*time.Millisecond), resp.Choices[0].FinishReason, resp.Usage.Format())
		return nil
	}

	var (
		streamErr error
		usage     *glm52.Usage
	)
	err := client.StreamChat(ctx, msgs, func(ch glm52.StreamChunk) {
		if ch.Error != nil {
			if streamErr == nil {
				streamErr = ch.Error
			}
			return
		}
		if ch.Usage != nil {
			usage = ch.Usage
		}
		fmt.Print(ch.Reasoning)
		fmt.Print(ch.Content)
	})
	fmt.Println()
	if err == nil {
		err = streamErr
	}
	if err != nil {
		return err
	}
	fmt.Printf("[done %s usage: %s]\n", time.Since(start).Round(100*time.Millisecond), usage.Format())
	return nil
}

// curlCommand renders the exact request for copy-paste into a shell.
func curlCommand(info models.ModelInfo, token string, body []byte) string {
	var b strings.Builder
	b.WriteString("curl -N -sS ")
	b.WriteString(strconv.Quote(info.PredictEndpoint()) + " \\\n  ")
	hdrs := [][2]string{
		{"Content-Type", "application/json"},
		{"Accept", "text/event-stream"},
		{"nv-function-id", info.FunctionID},
		{"nv-captcha-token", token},
		{"Origin", "https://build.nvidia.com"},
		{"Referer", "https://build.nvidia.com/"},
	}
	for _, h := range hdrs {
		b.WriteString("-H " + shellQuote(h[0]+": "+h[1]) + " \\\n  ")
	}
	b.WriteString("-d " + shellQuote(string(body)))
	return b.String()
}

// shellQuote wraps s in single quotes so a shell passes it through verbatim.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// printRegistry lists the known namespace/slug/function-id triples.
func printRegistry() {
	all := models.All()
	ids := make([]string, 0, len(all))
	for id := range all {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		info := all[id]
		fmt.Printf("%-46s namespace=%s slug=%s function-id=%s\n", id, info.Namespace, info.Slug, info.FunctionID)
	}
	fmt.Printf("\n%d models; call any other endpoint with -slug + -function-id\n", len(ids))
}
