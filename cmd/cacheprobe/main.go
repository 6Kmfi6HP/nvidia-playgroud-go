// cacheprobe checks whether the NVIDIA playground predict API returns
// prompt-token cache fields in usage (OpenAI / Anthropic / DeepSeek shapes).
//
//	go run ./cmd/cacheprobe -auto
//	go run ./cmd/cacheprobe -captcha "P1_..." -stream=false
//	go run ./cmd/cacheprobe -proxy http://localhost:8080 -rounds=2
//
// Success criteria: print raw usage JSON and a clear YES/NO for cache fields.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	glm52 "glm52-nvidia"
	"glm52-nvidia/internal/captcha"
	"glm52-nvidia/internal/models"
)

// Known cache-related keys under usage (and one level of nested objects).
var cacheKeys = []string{
	"cached_tokens",
	"prompt_tokens_details",
	"completion_tokens_details",
	"prompt_cache_hit_tokens",
	"prompt_cache_miss_tokens",
	"cache_read_input_tokens",
	"cache_creation_input_tokens",
	"cache_creation",
	"cache_read",
	"input_tokens_details",
}

func main() {
	captchaFlag := flag.String("captcha", "", "one-shot hCaptcha token (only for -rounds=1)")
	auto := flag.Bool("auto", false, "solve captcha via pure-Go PoW (needed for multi-round upstream)")
	proxy := flag.String("proxy", "", "hit local OpenAI proxy instead of upstream (e.g. http://localhost:8080)")
	model := flag.String("model", glm52.DefaultModel, "model id")
	stream := flag.Bool("stream", true, "use SSE stream (usage usually in final chunk)")
	rounds := flag.Int("rounds", 2, "requests with shared prefix (2nd may show cache hit if supported)")
	prefixTokens := flag.Int("prefix-tokens", 1200, "approx size of shared system prefix (words≈tokens)")
	maxTokens := flag.Int("max-tokens", 16, "max_tokens (keep small; we only care about usage)")
	thinking := flag.Bool("thinking", false, "enable thinking (off by default to shrink responses)")
	flag.Parse()

	if *rounds < 1 {
		log.Fatal("-rounds must be >= 1")
	}
	if *proxy == "" && !*auto && *captchaFlag == "" {
		log.Fatal("specify -auto, -captcha, or -proxy")
	}
	if *proxy == "" && *rounds > 1 && !*auto {
		log.Fatal("multi-round upstream needs -auto (each request burns one captcha)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	info, err := models.Lookup(*model)
	if err != nil {
		log.Fatal(err)
	}
	endpoint := info.PredictEndpoint()
	viaProxy := *proxy != ""
	if viaProxy {
		endpoint = strings.TrimRight(*proxy, "/") + "/v1/chat/completions"
	}

	prefix := buildPrefix(*prefixTokens)
	fmt.Printf("endpoint=%s model=%s stream=%v rounds=%d prefix_chars=%d thinking=%v\n",
		endpoint, *model, *stream, *rounds, len(prefix), *thinking)
	fmt.Printf("looking_for=%v\n", cacheKeys)

	var anyCache bool
	for i := 1; i <= *rounds; i++ {
		if ctx.Err() != nil {
			break
		}
		token, err := resolveToken(ctx, *auto, *captchaFlag, viaProxy)
		if err != nil {
			log.Fatalf("round %d captcha: %v", i, err)
		}

		user := fmt.Sprintf("Reply with exactly one word: ping%d", i)
		body, err := buildBody(*model, prefix, user, *stream, *maxTokens, *thinking)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("\n=== round %d/%d ===\n", i, *rounds)
		usage, rawSnippets, status, dur, err := runOnce(ctx, endpoint, body, token, viaProxy, *stream)
		if err != nil {
			log.Fatalf("round %d: %v", i, err)
		}
		fmt.Printf("http_status=%d duration=%s\n", status, dur.Round(time.Millisecond))
		if len(rawSnippets) > 0 {
			fmt.Println("raw usage chunk(s):")
			for _, s := range rawSnippets {
				fmt.Println(s)
			}
		}
		hits := findCacheSignals(usage)
		if len(hits) == 0 {
			fmt.Println("cache_fields: NONE")
			if usage == nil {
				fmt.Println("usage: <missing>")
			} else {
				pretty, _ := json.MarshalIndent(usage, "", "  ")
				fmt.Printf("usage:\n%s\n", pretty)
			}
		} else {
			anyCache = true
			fmt.Printf("cache_fields: FOUND %v\n", hits)
			pretty, _ := json.MarshalIndent(usage, "", "  ")
			fmt.Printf("usage:\n%s\n", pretty)
		}
	}

	fmt.Println()
	fmt.Println("--- verdict ---")
	if anyCache {
		fmt.Println("YES: upstream usage includes at least one prompt-cache related field.")
	} else {
		fmt.Println("NO: upstream usage has no known prompt-cache fields (cached_tokens / prompt_tokens_details / prompt_cache_* / cache_*_input_tokens).")
		fmt.Println("Note: absence of fields ≠ caching disabled server-side; it only means the response does not expose cache accounting.")
	}
}

func resolveToken(ctx context.Context, auto bool, captchaFlag string, viaProxy bool) (string, error) {
	if viaProxy {
		return "", nil
	}
	if auto {
		return captcha.PowExtract()(ctx)
	}
	if captchaFlag != "" {
		return captchaFlag, nil
	}
	return "", fmt.Errorf("no captcha source")
}

func buildPrefix(approxTokens int) string {
	// ~1 token/word for ASCII filler; keep deterministic for cache-hit attempts.
	const word = "alpha "
	n := approxTokens
	if n < 64 {
		n = 64
	}
	var b strings.Builder
	b.Grow(n * len(word))
	b.WriteString("You are a helpful assistant. The following block is shared context for caching probes:\n")
	for i := 0; i < n; i++ {
		b.WriteString(word)
		if i%32 == 31 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func buildBody(model, system, user string, stream bool, maxTokens int, thinking bool) ([]byte, error) {
	req := map[string]any{
		"model":       model,
		"messages":    []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": user}},
		"temperature": 0,
		"top_p":       1,
		"max_tokens":  maxTokens,
		"seed":        42,
		"stream":      stream,
		"chat_template_kwargs": map[string]any{
			"enable_thinking": thinking,
			"clear_thinking":  false,
		},
	}
	if stream {
		req["stream_options"] = map[string]any{
			"include_usage":          true,
			"continuous_usage_stats": false,
		}
	}
	return json.Marshal(req)
}

func runOnce(ctx context.Context, endpoint string, body []byte, token string, viaProxy, stream bool) (usage map[string]any, snippets []string, status int, dur time.Duration, err error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	} else {
		req.Header.Set("Accept", "application/json")
	}
	if !viaProxy {
		var raw map[string]any
		_ = json.Unmarshal(body, &raw)
		model, _ := raw["model"].(string)
		mi, lookupErr := models.Lookup(model)
		if lookupErr != nil {
			return nil, nil, 0, 0, lookupErr
		}
		req.Header.Set("nv-function-id", mi.FunctionID)
		req.Header.Set("nv-captcha-token", token)
		req.Header.Set("Origin", "https://build.nvidia.com")
		req.Header.Set("Referer", "https://build.nvidia.com/")
	} else if token != "" {
		req.Header.Set("nv-captcha-token", token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, 0, time.Since(start), err
	}
	defer resp.Body.Close()
	status = resp.StatusCode
	dur = time.Since(start)

	if status >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, nil, status, dur, fmt.Errorf("http %d: %s", status, raw)
	}

	if !stream {
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, status, time.Since(start), err
		}
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, []string{string(raw)}, status, time.Since(start), err
		}
		u, _ := obj["usage"].(map[string]any)
		snip, _ := json.Marshal(obj["usage"])
		dur = time.Since(start)
		return u, []string{string(snip)}, status, dur, nil
	}

	usage, snippets, err = collectUsageSSE(resp.Body)
	dur = time.Since(start)
	return usage, snippets, status, dur, err
}

func collectUsageSSE(body io.Reader) (map[string]any, []string, error) {
	reader := bufio.NewReaderSize(body, 64*1024)
	var last map[string]any
	var snippets []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return last, snippets, err
		}
		line = strings.TrimRight(line, "\r\n")
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}
		var raw map[string]any
		if json.Unmarshal([]byte(data), &raw) != nil {
			continue
		}
		if u, ok := raw["usage"].(map[string]any); ok && u != nil {
			last = u
			pretty, _ := json.Marshal(u)
			snippets = append(snippets, string(pretty))
		}
	}
	return last, snippets, nil
}

// findCacheSignals returns dotted paths of known cache-related fields present
// in usage (including one nesting level, e.g. prompt_tokens_details.cached_tokens).
func findCacheSignals(usage map[string]any) []string {
	if usage == nil {
		return nil
	}
	keySet := map[string]struct{}{}
	for _, k := range cacheKeys {
		keySet[k] = struct{}{}
	}
	var hits []string
	seen := map[string]struct{}{}
	add := func(path string) {
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		hits = append(hits, path)
	}
	for k, v := range usage {
		if _, ok := keySet[k]; ok {
			add(k)
		}
		nested, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for nk := range nested {
			if _, ok := keySet[nk]; ok {
				add(k + "." + nk)
			}
		}
	}
	return hits
}
