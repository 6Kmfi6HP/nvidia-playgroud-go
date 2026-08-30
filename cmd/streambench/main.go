// cmd/streambench — measure SSE chunk timing against the predict API.
//
// Compares stream_options and reports TTFB / inter-arrival gaps so you can
// tell upstream cadence apart from local buffering.
//
//	go run ./cmd/streambench -auto -prompt "Count from 1 to 20."
//	go run ./cmd/streambench -captcha "P1_..." -continuous-usage
//	go run ./cmd/streambench -proxy http://localhost:8080 -concurrency 4
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
	"sort"
	"strings"
	"sync"
	"time"

	glm52 "glm52-nvidia"
	"glm52-nvidia/internal/captcha"
)

func main() {
	captchaFlag := flag.String("captcha", "", "one-shot hCaptcha token")
	auto := flag.Bool("auto", false, "solve captcha via pure-Go PoW")
	prompt := flag.String("prompt", "Count from 1 to 30, one number per line.", "user prompt")
	continuous := flag.Bool("continuous-usage", false, "set continuous_usage_stats=true")
	maxTokens := flag.Int("max-tokens", 256, "max_tokens")
	proxy := flag.String("proxy", "", "if set, hit local OpenAI proxy instead of upstream (e.g. http://localhost:8080)")
	concurrency := flag.Int("concurrency", 1, "parallel requests (requires -proxy; pool supplies captchas)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if *concurrency < 1 {
		log.Fatal("-concurrency must be >= 1")
	}
	if *concurrency > 1 && *proxy == "" {
		log.Fatal("-concurrency > 1 requires -proxy (local serve pool handles captchas)")
	}

	endpoint := glm52.PredictEndpoint
	if *proxy != "" {
		endpoint = strings.TrimRight(*proxy, "/") + "/v1/chat/completions"
	}

	body, err := json.Marshal(map[string]any{
		"model":       glm52.DefaultModel,
		"messages":    []map[string]string{{"role": "user", "content": *prompt}},
		"temperature": 0.2,
		"top_p":       1.0,
		"max_tokens":  *maxTokens,
		"seed":        42,
		"stream":      true,
		"stream_options": map[string]any{
			"include_usage":          true,
			"continuous_usage_stats": *continuous,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("endpoint=%s continuous_usage=%v max_tokens=%d concurrency=%d\n",
		endpoint, *continuous, *maxTokens, *concurrency)

	if *concurrency == 1 {
		token, err := resolveToken(ctx, *auto, *captchaFlag, *proxy != "")
		if err != nil {
			log.Fatal(err)
		}
		runOne(ctx, endpoint, body, token, *proxy != "")
		return
	}

	runConcurrent(ctx, endpoint, body, *concurrency)
}

func resolveToken(ctx context.Context, auto bool, captchaFlag string, viaProxy bool) (string, error) {
	if captchaFlag != "" {
		return captchaFlag, nil
	}
	if auto {
		return captcha.PowExtract()(ctx)
	}
	if viaProxy {
		return "", nil // serve -auto / header path
	}
	return "", fmt.Errorf("specify -captcha or -auto")
}

type runResult struct {
	Idx    int
	Status int
	TTFB   time.Duration
	Total  time.Duration
	Chunks int
	Err    string
}

func runOne(ctx context.Context, endpoint string, body []byte, token string, viaProxy bool) {
	start := time.Now()
	resp, err := doStream(ctx, endpoint, body, token, viaProxy)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	headerAt := time.Now()

	fmt.Printf("http_status=%d ttfb=%s ttfb_ms=%d content-type=%q\n",
		resp.StatusCode, headerAt.Sub(start).Round(time.Millisecond), headerAt.Sub(start).Milliseconds(), resp.Header.Get("Content-Type"))
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		log.Fatalf("upstream error: %s", raw)
	}

	stats := collectSSE(resp.Body, start, headerAt)
	printReport(stats)
}

func runConcurrent(ctx context.Context, endpoint string, body []byte, n int) {
	var wg sync.WaitGroup
	results := make([]runResult, n)
	startAll := time.Now()

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start := time.Now()
			resp, err := doStream(ctx, endpoint, body, "", true)
			if err != nil {
				results[i] = runResult{Idx: i, Err: err.Error(), Total: time.Since(start)}
				return
			}
			headerAt := time.Now()
			st := collectSSE(resp.Body, start, headerAt)
			_ = resp.Body.Close()
			rr := runResult{
				Idx:    i,
				Status: resp.StatusCode,
				TTFB:   headerAt.Sub(start),
				Total:  st.Total,
				Chunks: len(st.Events),
			}
			if resp.StatusCode >= 400 {
				rr.Err = fmt.Sprintf("http %d", resp.StatusCode)
			}
			results[i] = rr
		}(i)
	}
	wg.Wait()

	var ok int
	var ttfbs, totals []time.Duration
	fmt.Println()
	fmt.Println("--- concurrent summary ---")
	for _, rr := range results {
		status := "ok"
		if rr.Err != "" {
			status = "FAIL:" + rr.Err
		} else {
			ok++
			ttfbs = append(ttfbs, rr.TTFB)
			totals = append(totals, rr.Total)
		}
		fmt.Printf("#%d status=%d ttfb=%s ttfb_ms=%d total=%s chunks=%d %s\n",
			rr.Idx, rr.Status, rr.TTFB.Round(time.Millisecond), rr.TTFB.Milliseconds(), rr.Total.Round(time.Millisecond), rr.Chunks, status)
	}
	fmt.Printf("wall=%s success=%d/%d\n", time.Since(startAll).Round(time.Millisecond), ok, n)
	if len(ttfbs) > 0 {
		sort.Slice(ttfbs, func(i, j int) bool { return ttfbs[i] < ttfbs[j] })
		sort.Slice(totals, func(i, j int) bool { return totals[i] < totals[j] })
		fmt.Printf("ttfb: min=%s p50=%s max=%s\n",
			ttfbs[0].Round(time.Millisecond),
			percentile(ttfbs, 50).Round(time.Millisecond),
			ttfbs[len(ttfbs)-1].Round(time.Millisecond))
		fmt.Printf("total: min=%s p50=%s max=%s\n",
			totals[0].Round(time.Millisecond),
			percentile(totals, 50).Round(time.Millisecond),
			totals[len(totals)-1].Round(time.Millisecond))
	}
}

func doStream(ctx context.Context, endpoint string, body []byte, token string, viaProxy bool) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	if !viaProxy {
		req.Header.Set("nv-function-id", glm52.NVFunctionID)
		req.Header.Set("nv-captcha-token", token)
		req.Header.Set("Origin", "https://build.nvidia.com")
		req.Header.Set("Referer", "https://build.nvidia.com/")
	} else if token != "" {
		req.Header.Set("nv-captcha-token", token)
	}
	return http.DefaultClient.Do(req)
}

type chunkEvent struct {
	At          time.Time
	Gap         time.Duration
	Bytes       int
	ContentLen  int
	HasUsage    bool
	FinishReason string
	RawPreview  string
}

type streamStats struct {
	TTFB       time.Duration
	Total      time.Duration
	Events     []chunkEvent
	Content    strings.Builder
	DoneSeen   bool
}

func collectSSE(body io.Reader, start, headerAt time.Time) streamStats {
	st := streamStats{TTFB: headerAt.Sub(start)}
	reader := bufio.NewReaderSize(body, 64*1024)
	last := headerAt

	for {
		line, err := reader.ReadString('\n')
		now := time.Now()
		if err != nil {
			if err != io.EOF {
				log.Printf("read: %v", err)
			}
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		ev := chunkEvent{
			At:    now,
			Gap:   now.Sub(last),
			Bytes: len(data),
		}
		last = now

		if data == "[DONE]" {
			st.DoneSeen = true
			st.Events = append(st.Events, ev)
			break
		}

		var raw map[string]any
		if json.Unmarshal([]byte(data), &raw) == nil {
			if u, ok := raw["usage"]; ok && u != nil {
				ev.HasUsage = true
			}
			if choices, ok := raw["choices"].([]any); ok && len(choices) > 0 {
				if ch, ok := choices[0].(map[string]any); ok {
					if fr, ok := ch["finish_reason"].(string); ok {
						ev.FinishReason = fr
					}
					if delta, ok := ch["delta"].(map[string]any); ok {
						if c, ok := delta["content"].(string); ok {
							ev.ContentLen = len([]rune(c))
							st.Content.WriteString(c)
						}
					}
				}
			}
		}
		if len(data) > 80 {
			ev.RawPreview = data[:80] + "…"
		} else {
			ev.RawPreview = data
		}
		st.Events = append(st.Events, ev)
	}
	st.Total = time.Since(start)
	return st
}

func printReport(st streamStats) {
	gaps := make([]time.Duration, 0, len(st.Events))
	var contentChunks, usageChunks, emptyChunks int
	var contentRunes int
	var maxGap time.Duration
	var maxGapIdx int

	for i, ev := range st.Events {
		if i == 0 {
			continue // first gap is from headers → first data; still useful but separate
		}
		gaps = append(gaps, ev.Gap)
		if ev.Gap > maxGap {
			maxGap = ev.Gap
			maxGapIdx = i
		}
		if ev.ContentLen > 0 {
			contentChunks++
			contentRunes += ev.ContentLen
		} else if ev.HasUsage && ev.ContentLen == 0 {
			usageChunks++
		} else {
			emptyChunks++
		}
	}
	// count first event content too
	if len(st.Events) > 0 && st.Events[0].ContentLen > 0 {
		contentChunks++
		contentRunes += st.Events[0].ContentLen
	}

	fmt.Println()
	fmt.Println("--- timing ---")
	fmt.Printf("chunks=%d content_chunks=%d usage_only=%d empty/meta=%d done=%v\n",
		len(st.Events), contentChunks, usageChunks, emptyChunks, st.DoneSeen)
	fmt.Printf("total=%s content_runes≈%d\n", st.Total.Round(time.Millisecond), len([]rune(st.Content.String())))
	if len(gaps) > 0 {
		sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
		fmt.Printf("inter_chunk_gap: min=%s p50=%s p90=%s p99=%s max=%s (idx=%d)\n",
			gaps[0].Round(time.Millisecond),
			percentile(gaps, 50).Round(time.Millisecond),
			percentile(gaps, 90).Round(time.Millisecond),
			percentile(gaps, 99).Round(time.Millisecond),
			maxGap.Round(time.Millisecond), maxGapIdx)
	}

	fmt.Println()
	fmt.Println("--- first 12 chunk arrivals ---")
	n := 12
	if len(st.Events) < n {
		n = len(st.Events)
	}
	for i := 0; i < n; i++ {
		ev := st.Events[i]
		fmt.Printf("#%02d gap=%6s bytes=%4d content_runes=%2d usage=%v finish=%q\n",
			i, ev.Gap.Round(time.Millisecond), ev.Bytes, ev.ContentLen, ev.HasUsage, ev.FinishReason)
	}

	out := st.Content.String()
	if len([]rune(out)) > 200 {
		r := []rune(out)
		out = string(r[:200]) + "…"
	}
	fmt.Println()
	fmt.Println("--- assembled content (truncated) ---")
	fmt.Println(out)
}

func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p * (len(sorted) - 1)) / 100
	return sorted[idx]
}
