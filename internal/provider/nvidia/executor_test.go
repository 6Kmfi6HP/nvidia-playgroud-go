package nvidia

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"glm52-nvidia/internal/captcha"
	"glm52-nvidia/internal/models"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	clipexec "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"

	_ "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator/builtin"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newExecutorLeasePool(t *testing.T, tokens ...string) (*captcha.Pool, *atomic.Int32) {
	t.Helper()
	return newExecutorLeasePoolWithTTL(t, time.Minute, tokens...)
}

func newExecutorLeasePoolWithTTL(t *testing.T, ttl time.Duration, tokens ...string) (*captcha.Pool, *atomic.Int32) {
	t.Helper()

	var extracts atomic.Int32
	pool := captcha.NewPool(t.Context(), func(ctx context.Context) (string, error) {
		i := int(extracts.Load())
		if i < len(tokens) {
			extracts.Add(1)
			return tokens[i], nil
		}
		<-ctx.Done()
		return "", ctx.Err()
	}, captcha.PoolConfig{Size: 1, Workers: 1, TTL: ttl})
	t.Cleanup(pool.Close)
	takeCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	lease, err := pool.TakeLease(takeCtx)
	if err != nil {
		t.Fatalf("wait for captcha pool: %v", err)
	}
	lease.Release()
	return pool, &extracts
}

func receiveTestValue[T any](t *testing.T, ch <-chan T, name string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
		var zero T
		return zero
	}
}

func leaseTestRequest() (clipexec.Request, clipexec.Options) {
	return clipexec.Request{
		Model:   "moonshotai/kimi-k3",
		Payload: []byte(`{"model":"moonshotai/kimi-k3","messages":[{"role":"user","content":"hi"}]}`),
	}, clipexec.Options{SourceFormat: sdktranslator.FormatOpenAI}
}

func requireReturnedPoolToken(t *testing.T, pool *captcha.Pool, extracts *atomic.Int32) {
	t.Helper()

	if got := extracts.Load(); got != 1 {
		t.Fatalf("extract calls=%d want 1", got)
	}
	takeCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	lease, err := pool.TakeLease(takeCtx)
	if err != nil {
		t.Fatal(err)
	}
	got := lease.Token()
	lease.Commit()
	if got != "tok-1" {
		t.Fatalf("returned token=%q want tok-1", got)
	}
}

func TestIsRetryableCaptchaFailure(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{
			name:   "nvidia invalid token",
			status: http.StatusBadRequest,
			body:   `{"requestStatus":{"statusCode":"INVALID_REQUEST","statusDescription":"Token is invalid","requestId":"abc"}}`,
			want:   true,
		},
		{
			name:   "case insensitive token",
			status: http.StatusBadRequest,
			body:   `{"requestStatus":{"statusDescription":"token is Invalid"}}`,
			want:   true,
		},
		{
			name:   "generic captcha body",
			status: http.StatusForbidden,
			body:   `{"error":"hcaptcha rejected the token"}`,
			want:   true,
		},
		{
			name:   "missing captcha wording",
			status: http.StatusBadRequest,
			body:   `{"error":"missing-captcha"}`,
			want:   true,
		},
		{
			name:   "unrelated client error",
			status: http.StatusBadRequest,
			body:   `{"requestStatus":{"statusCode":"INVALID_REQUEST","statusDescription":"bad prompt"}}`,
			want:   false,
		},
		{
			name:   "empty body client error",
			status: http.StatusBadRequest,
			body:   ``,
			want:   false,
		},
		{
			name:   "5xx not retryable as captcha",
			status: http.StatusBadGateway,
			body:   `{"error":"hcaptcha is down"}`,
			want:   false,
		},
		{
			name:   "2xx never retryable",
			status: http.StatusOK,
			body:   `{"error":"hcaptcha"}`,
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryableCaptchaFailure(tc.status, []byte(tc.body)); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestAcquireInflight(t *testing.T) {
	e := NewExecutor(Options{MaxInflight: 1, InflightWait: 0})
	rel1, err := e.acquireInflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.acquireInflight(context.Background())
	if err == nil {
		t.Fatal("expected full")
	}
	rel1()
	rel2, err := e.acquireInflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rel2()
}

func TestExecuteUnknownModel(t *testing.T) {
	e := NewExecutor(Options{FlagCaptcha: "tok"})
	_, err := e.Execute(context.Background(), nil, clipexec.Request{
		Model:   "no-such-org/never",
		Payload: []byte(`{"model":"no-such-org/never","messages":[{"role":"user","content":"hi"}]}`),
	}, clipexec.Options{SourceFormat: sdktranslator.FormatOpenAI})
	if err == nil {
		t.Fatal("expected error")
	}
	ae, ok := err.(*coreauth.Error)
	if !ok {
		t.Fatalf("err type %T", err)
	}
	if ae.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("status=%d", ae.HTTPStatus)
	}
	if !strings.Contains(ae.Message, "no-such-org/never") {
		t.Fatalf("msg=%q", ae.Message)
	}
}

func TestExecuteStreamMockUpstream(t *testing.T) {
	var hits int
	var gotToken, gotFunction string
	var gotBody []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotToken = r.Header.Get("nv-captcha-token")
		gotFunction = r.Header.Get("nv-function-id")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer up.Close()

	info, err := models.Lookup("moonshotai/kimi-k3")
	if err != nil {
		t.Fatal(err)
	}

	e := NewExecutor(Options{
		FlagCaptcha: "P1_test",
		HTTPClient:  up.Client(),
		PredictURL:  func(models.ModelInfo) string { return up.URL },
	})

	stream, err := e.ExecuteStream(context.Background(), nil, clipexec.Request{
		Model:   "moonshotai/kimi-k3",
		Payload: []byte(`{"model":"moonshotai/kimi-k3","messages":[{"role":"user","content":"hi"}],"stream":true}`),
	}, clipexec.Options{
		Stream:       true,
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      http.Header{},
	})
	if err != nil {
		t.Fatal(err)
	}
	var payloads [][]byte
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			t.Fatal(chunk.Err)
		}
		payloads = append(payloads, chunk.Payload)
	}
	if hits != 1 {
		t.Fatalf("hits=%d", hits)
	}
	if gotToken != "P1_test" {
		t.Fatalf("token=%q", gotToken)
	}
	if gotFunction != info.FunctionID {
		t.Fatalf("function-id=%q want %q", gotFunction, info.FunctionID)
	}
	var body map[string]any
	if err := json.Unmarshal(gotBody, &body); err != nil {
		t.Fatal(err)
	}
	if body["stream"] != true {
		t.Fatalf("upstream stream flag=%v", body["stream"])
	}
	joined := string(bytes.Join(payloads, nil))
	if !strings.Contains(joined, "ok") {
		t.Fatalf("payloads=%q", joined)
	}
}

func TestUpstreamRetryOnInvalidToken(t *testing.T) {
	var hits int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		tok := r.Header.Get("nv-captcha-token")
		if tok == "bad" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"requestStatus":{"statusCode":"INVALID_REQUEST","statusDescription":"Token is invalid","requestId":"x"}}`))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer up.Close()

	client := up.Client()
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}`)
	tokens := []string{"bad", "good"}
	var upResp *http.Response
	for i, tok := range tokens {
		req, _ := http.NewRequest(http.MethodPost, up.URL, bytes.NewReader(body))
		req.Header.Set("nv-captcha-token", tok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode >= 400 {
			raw, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if isRetryableCaptchaFailure(resp.StatusCode, raw) && i+1 < len(tokens) {
				continue
			}
			t.Fatalf("unexpected error body=%s", raw)
		}
		upResp = resp
		break
	}
	if upResp == nil {
		t.Fatal("no successful upstream response")
	}
	if hits != 2 {
		t.Fatalf("hits=%d want 2", hits)
	}
	defer upResp.Body.Close()
	raw, _ := io.ReadAll(upResp.Body)
	if !strings.Contains(string(raw), "ok") {
		t.Fatalf("body=%q", raw)
	}
}

func TestExecutePoolLease_InflightRejectedReturnsToken(t *testing.T) {
	pool, extracts := newExecutorLeasePool(t, "tok-1")
	var transportHits atomic.Int32
	executor := NewExecutor(Options{
		Pool:        pool,
		MaxInflight: 1,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			transportHits.Add(1)
			return nil, errors.New("unexpected transport call")
		})},
	})
	release, err := executor.acquireInflight(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	req, opts := leaseTestRequest()

	_, err = executor.Execute(t.Context(), nil, req, opts)

	var authErr *coreauth.Error
	if !errors.As(err, &authErr) {
		t.Fatalf("error type=%T want *coreauth.Error", err)
	}
	if authErr.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want %d", authErr.HTTPStatus, http.StatusServiceUnavailable)
	}
	if transportHits.Load() != 0 {
		t.Fatalf("transport hits=%d want 0", transportHits.Load())
	}
	requireReturnedPoolToken(t, pool, extracts)
}

func TestExecutePoolLease_WaitsForInflightBeforeTakingToken(t *testing.T) {
	pool, extracts := newExecutorLeasePool(t, "tok-1")
	executor := NewExecutor(Options{
		Pool:         pool,
		MaxInflight:  1,
		InflightWait: time.Minute,
	})
	releaseInflight, err := executor.acquireInflight(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan struct{})
	var waits atomic.Int32
	executor.beforeInflightWait = func() {
		if waits.Add(1) == 1 {
			close(waiting)
		}
	}
	req, opts := leaseTestRequest()
	errCh := make(chan error, 1)

	go func() {
		_, executeErr := executor.Execute(t.Context(), nil, req, opts)
		errCh <- executeErr
	}()

	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("request did not wait for an in-flight slot")
	}
	if got := pool.Ready(); got != 1 {
		t.Fatalf("ready pool tokens while waiting=%d want 1", got)
	}
	if got := extracts.Load(); got != 1 {
		t.Fatalf("token extracts while waiting=%d want 1", got)
	}

	cancelCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cancelErrCh := make(chan error, 1)
	go func() {
		_, executeErr := executor.Execute(cancelCtx, nil, req, opts)
		cancelErrCh <- executeErr
	}()
	cancel()
	err = receiveTestValue(t, cancelErrCh, "cancel waiting request result")

	var authErr *coreauth.Error
	if !errors.As(err, &authErr) {
		t.Fatalf("error type=%T want *coreauth.Error", err)
	}
	if authErr.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want %d", authErr.HTTPStatus, http.StatusServiceUnavailable)
	}
	if got := extracts.Load(); got != 1 {
		t.Fatalf("extract calls=%d want 1", got)
	}

	releaseInflight()
	select {
	case err := <-errCh:
		t.Fatalf("first request returned before captcha resolution: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestExecutePoolLease_InflightCanceledReturnsToken(t *testing.T) {
	pool, extracts := newExecutorLeasePool(t, "tok-1")
	var transportHits atomic.Int32
	executor := NewExecutor(Options{
		Pool:         pool,
		MaxInflight:  1,
		InflightWait: time.Minute,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			transportHits.Add(1)
			return nil, errors.New("unexpected transport call")
		})},
	})
	releaseInflight, err := executor.acquireInflight(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer releaseInflight()
	waiting := make(chan struct{})
	resume := make(chan struct{})
	executor.beforeInflightWait = func() {
		close(waiting)
		receiveTestValue(t, resume, "resume inflight cancellation")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, opts := leaseTestRequest()
	errCh := make(chan error, 1)
	go func() {
		_, executeErr := executor.Execute(ctx, nil, req, opts)
		errCh <- executeErr
	}()

	receiveTestValue(t, waiting, "inflight wait barrier")
	cancel()
	close(resume)
	err = receiveTestValue(t, errCh, "inflight cancellation result")

	var authErr *coreauth.Error
	if !errors.As(err, &authErr) {
		t.Fatalf("error type=%T want *coreauth.Error", err)
	}
	if authErr.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want %d", authErr.HTTPStatus, http.StatusServiceUnavailable)
	}
	if transportHits.Load() != 0 {
		t.Fatalf("transport hits=%d want 0", transportHits.Load())
	}
	requireReturnedPoolToken(t, pool, extracts)
}

func TestExecutePoolLease_ContextCanceledBeforeDoReturnsToken(t *testing.T) {
	pool, extracts := newExecutorLeasePool(t, "tok-1")
	var transportHits atomic.Int32
	executor := NewExecutor(Options{
		Pool: pool,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			transportHits.Add(1)
			return nil, errors.New("unexpected transport call")
		})},
	})
	requestReady := make(chan struct{})
	resume := make(chan struct{})
	executor.beforeSend = func() {
		close(requestReady)
		receiveTestValue(t, resume, "resume pre-Do cancellation")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, opts := leaseTestRequest()
	errCh := make(chan error, 1)
	go func() {
		_, executeErr := executor.Execute(ctx, nil, req, opts)
		errCh <- executeErr
	}()

	receiveTestValue(t, requestReady, "request ready barrier")
	cancel()
	close(resume)
	err := receiveTestValue(t, errCh, "pre-Do cancellation result")

	var authErr *coreauth.Error
	if !errors.As(err, &authErr) {
		t.Fatalf("error type=%T want *coreauth.Error", err)
	}
	if authErr.HTTPStatus != http.StatusRequestTimeout {
		t.Fatalf("status=%d want %d", authErr.HTTPStatus, http.StatusRequestTimeout)
	}
	if transportHits.Load() != 0 {
		t.Fatalf("transport hits=%d want 0", transportHits.Load())
	}
	requireReturnedPoolToken(t, pool, extracts)
}

func TestExecutePoolLease_ExpiredAfterInflightWaitSendsFreshToken(t *testing.T) {
	const ttl = 100 * time.Millisecond
	pool, extracts := newExecutorLeasePoolWithTTL(t, ttl, "tok-1", "tok-2")
	sentTokens := make(chan string, 2)
	executor := NewExecutor(Options{
		Pool:         pool,
		MaxInflight:  1,
		InflightWait: time.Minute,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			sentTokens <- req.Header.Get("nv-captcha-token")
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(
					`{"id":"1","choices":[{"message":{"role":"assistant","content":"ok"}}]}`,
				)),
			}, nil
		})},
	})
	releaseInflight, err := executor.acquireInflight(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan struct{})
	resume := make(chan struct{})
	var waits atomic.Int32
	executor.beforeInflightWait = func() {
		if waits.Add(1) != 1 {
			return
		}
		close(waiting)
		receiveTestValue(t, resume, "resume expired lease execution")
	}
	req, opts := leaseTestRequest()
	errCh := make(chan error, 1)
	go func() {
		_, executeErr := executor.Execute(t.Context(), nil, req, opts)
		errCh <- executeErr
	}()

	receiveTestValue(t, waiting, "inflight wait barrier")
	releaseInflight()
	// Simulate another caller taking and expiring the first token while this
	// request is still between the in-flight gate and captcha resolution.
	lease, err := pool.TakeLease(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	receiveTestValue(t, time.After(5*ttl), "lease TTL expiry")
	if lease.Commit() {
		t.Fatal("expired lease unexpectedly committed")
	}
	releaseInflight, err = executor.acquireInflight(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	releaseInflight()
	close(resume)
	if executeErr := receiveTestValue(t, errCh, "fresh token execution result"); executeErr != nil {
		t.Fatal(executeErr)
	}

	if got := receiveTestValue(t, sentTokens, "upstream captcha token"); got != "tok-2" {
		t.Fatalf("sent token=%q want tok-2", got)
	}
	if got := len(sentTokens); got != 0 {
		t.Fatalf("additional upstream calls=%d want 0", got)
	}
	if got := extracts.Load(); got != 2 {
		t.Fatalf("successful extracts=%d want 2", got)
	}
}

func TestExecutePoolLease_InvalidRequestReturnsToken(t *testing.T) {
	pool, extracts := newExecutorLeasePool(t, "tok-1")
	var transportHits atomic.Int32
	executor := NewExecutor(Options{
		Pool: pool,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			transportHits.Add(1)
			return nil, errors.New("unexpected transport call")
		})},
		PredictURL: func(models.ModelInfo) string { return ":" },
	})
	req, opts := leaseTestRequest()

	_, err := executor.Execute(t.Context(), nil, req, opts)

	if err == nil {
		t.Fatal("expected request construction error")
	}
	if transportHits.Load() != 0 {
		t.Fatalf("transport hits=%d want 0", transportHits.Load())
	}
	requireReturnedPoolToken(t, pool, extracts)
}

func TestExecutePoolLease_TransportErrorCommitsToken(t *testing.T) {
	pool, extracts := newExecutorLeasePool(t, "tok-1", "tok-2")
	sentinel := errors.New("sentinel transport error")
	var transportHits atomic.Int32
	executor := NewExecutor(Options{
		Pool: pool,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			transportHits.Add(1)
			if got := req.Header.Get("nv-captcha-token"); got != "tok-1" {
				t.Errorf("sent token=%q want tok-1", got)
			}
			return nil, sentinel
		})},
	})
	req, opts := leaseTestRequest()

	_, err := executor.Execute(t.Context(), nil, req, opts)

	var authErr *coreauth.Error
	if !errors.As(err, &authErr) {
		t.Fatalf("error type=%T want *coreauth.Error", err)
	}
	if authErr.HTTPStatus != http.StatusBadGateway {
		t.Fatalf("status=%d want %d", authErr.HTTPStatus, http.StatusBadGateway)
	}
	takeCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	lease, err := pool.TakeLease(takeCtx)
	if err != nil {
		t.Fatal(err)
	}
	token := lease.Token()
	lease.Commit()
	if token != "tok-2" {
		t.Fatalf("next token=%q want tok-2", token)
	}
	if got := extracts.Load(); got != 2 {
		t.Fatalf("extract calls=%d want 2", got)
	}
	if transportHits.Load() != 1 {
		t.Fatalf("transport hits=%d want 1", transportHits.Load())
	}
}

func TestExecutePoolLease_RetryableCaptchaUsesFreshToken(t *testing.T) {
	pool, _ := newExecutorLeasePool(t, "bad", "good")
	received := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token := req.Header.Get("nv-captcha-token")
		received <- token
		if token == "bad" {
			w.WriteHeader(http.StatusBadRequest)
			if _, err := w.Write([]byte(`{"requestStatus":{"statusCode":"INVALID_REQUEST","statusDescription":"Token is invalid","requestId":"x"}}`)); err != nil {
				t.Errorf("write bad-token body: %v", err)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"id":"1","choices":[{"message":{"role":"assistant","content":"ok"}}]}`)); err != nil {
			t.Errorf("write success body: %v", err)
		}
	}))
	defer upstream.Close()
	executor := NewExecutor(Options{
		Pool:       pool,
		HTTPClient: upstream.Client(),
		PredictURL: func(models.ModelInfo) string { return upstream.URL },
	})
	req, opts := leaseTestRequest()

	resp, err := executor.Execute(t.Context(), nil, req, opts)

	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp.Payload), "ok") {
		t.Fatalf("payload=%s", resp.Payload)
	}
	got := []string{<-received, <-received}
	if got[0] != "bad" || got[1] != "good" {
		t.Fatalf("upstream tokens=%q want [bad good]", got)
	}
	select {
	case token := <-received:
		t.Fatalf("unexpected third upstream token %q", token)
	default:
	}
}

func TestTranslatorClaudeToOpenAIChatShape(t *testing.T) {
	claude := []byte(`{"model":"moonshotai/kimi-k3","max_tokens":64,"messages":[{"role":"user","content":"Hi"}],"stream":false}`)
	out := sdktranslator.TranslateRequest(sdktranslator.FormatClaude, sdktranslator.FormatOpenAI, "moonshotai/kimi-k3", claude, false)
	if len(out) == 0 {
		t.Fatal("empty translation")
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("not json: %v body=%s", err, out)
	}
	if _, ok := raw["messages"]; !ok {
		t.Fatalf("expected messages in openai chat shape, got %s", out)
	}
	if raw["model"] != "moonshotai/kimi-k3" {
		t.Fatalf("model=%v", raw["model"])
	}
}

func TestTranslatorResponsesToOpenAIChatShape(t *testing.T) {
	responses := []byte(`{"model":"moonshotai/kimi-k3","input":"Hi","stream":false}`)
	out := sdktranslator.TranslateRequest(sdktranslator.FormatOpenAIResponse, sdktranslator.FormatOpenAI, "moonshotai/kimi-k3", responses, false)
	if len(out) == 0 {
		t.Fatal("empty translation")
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("not json: %v body=%s", err, out)
	}
	if _, ok := raw["messages"]; !ok {
		t.Fatalf("expected messages in openai chat shape, got %s", out)
	}
}

func TestRegistryModelsSorted(t *testing.T) {
	ms := RegistryModels()
	if len(ms) == 0 {
		t.Fatal("empty")
	}
	for i := 1; i < len(ms); i++ {
		if ms[i-1].ID > ms[i].ID {
			t.Fatalf("not sorted: %q before %q", ms[i-1].ID, ms[i].ID)
		}
	}
	byID := map[string]bool{}
	for _, m := range ms {
		if m.Type != providerKey {
			t.Errorf("type=%q for %q", m.Type, m.ID)
		}
		byID[m.ID] = true
	}
	for _, want := range []string{"moonshotai/kimi-k3", "deepseek-ai/deepseek-v4-pro-0813"} {
		if !byID[want] {
			t.Errorf("missing %q", want)
		}
	}
	if byID["moonshotai/kimi-k2.6"] {
		t.Error("runtime-only model should be absent")
	}
}

func TestExecuteUsesHeaderCaptcha(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("nv-captcha-token") != "from-header" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	}))
	defer up.Close()

	e := NewExecutor(Options{
		HTTPClient: up.Client(),
		PredictURL: func(models.ModelInfo) string { return up.URL },
	})
	hdr := make(http.Header)
	hdr.Set("nv-captcha-token", "from-header")
	resp, err := e.Execute(context.Background(), nil, clipexec.Request{
		Model:   "moonshotai/kimi-k3",
		Payload: []byte(`{"model":"moonshotai/kimi-k3","messages":[{"role":"user","content":"hi"}]}`),
	}, clipexec.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      hdr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp.Payload), "hi") {
		t.Fatalf("payload=%s", resp.Payload)
	}
}

func TestExecuteTranslatesReasoningEffortForUpstreamModel(t *testing.T) {
	var upstreamBody map[string]any
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&upstreamBody); err != nil {
			t.Errorf("decode upstream request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer up.Close()

	executor := NewExecutor(Options{
		FlagCaptcha: "test-token",
		HTTPClient:  up.Client(),
		PredictURL:  func(models.ModelInfo) string { return up.URL },
	})
	_, err := executor.Execute(context.Background(), nil, clipexec.Request{
		Model: "deepseek-ai/deepseek-v4-pro-0813",
		Payload: []byte(`{
			"model":"deepseek-ai/deepseek-v4-pro-0813",
			"messages":[{"role":"user","content":"solve"}],
			"reasoning_effort":"xhigh"
		}`),
	}, clipexec.Options{SourceFormat: sdktranslator.FormatOpenAI})
	if err != nil {
		t.Fatal(err)
	}

	kwargs, ok := upstreamBody["chat_template_kwargs"].(map[string]any)
	if !ok {
		t.Fatalf("upstream chat_template_kwargs missing: %#v", upstreamBody)
	}
	if got := kwargs["reasoning_effort"]; got != "max" {
		t.Fatalf("upstream reasoning_effort=%#v want max", got)
	}
	if _, ok := upstreamBody["reasoning_effort"]; ok {
		t.Fatalf("generic reasoning_effort leaked upstream: %#v", upstreamBody)
	}
}

func TestExecute_sendsResponsesSamplingFieldsToPlayground(t *testing.T) {
	// Given: a capture server standing in for the NVIDIA Chat Completions endpoint.
	var upstreamBody map[string]json.RawMessage
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&upstreamBody); err != nil {
			t.Errorf("decode upstream request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer up.Close()
	executor := NewExecutor(Options{
		FlagCaptcha: "test-token",
		HTTPClient:  up.Client(),
		PredictURL:  func(models.ModelInfo) string { return up.URL },
	})

	// When: a Responses request uses Chat-compatible sampling and attribution fields.
	_, err := executor.Execute(context.Background(), nil, clipexec.Request{
		Model: "moonshotai/kimi-k3",
		Payload: []byte(`{
			"model":"moonshotai/kimi-k3",
			"input":"hello",
			"temperature":0.25,
			"top_p":0.8,
			"user":"user-42",
			"service_tier":"default"
		}`),
	}, clipexec.Options{SourceFormat: sdktranslator.FormatOpenAIResponse})
	if err != nil {
		t.Fatal(err)
	}

	// Then: the captured canonical Chat request retains every compatible field.
	for field, want := range map[string]string{
		"temperature":  "0.25",
		"top_p":        "0.8",
		"user":         `"user-42"`,
		"service_tier": `"default"`,
	} {
		if got := string(upstreamBody[field]); got != want {
			t.Errorf("%s=%s want %s; body=%v", field, got, want, upstreamBody)
		}
	}
	if string(upstreamBody["stream"]) != "false" {
		t.Fatalf("stream=%s", upstreamBody["stream"])
	}
}

func TestExecute_forwardsResponsesStoreWithoutRejecting(t *testing.T) {
	// Given: a Playground server that records whether it was contacted.
	hits := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)); err != nil {
			return
		}
	}))
	defer up.Close()
	executor := NewExecutor(Options{
		FlagCaptcha: "test-token",
		HTTPClient:  up.Client(),
		PredictURL:  func(models.ModelInfo) string { return up.URL },
	})

	// When: a Responses request includes store (unsupported by NVIDIA, but must not be rejected).
	_, err := executor.Execute(context.Background(), nil, clipexec.Request{
		Model: "moonshotai/kimi-k3",
		Payload: []byte(`{
			"model":"moonshotai/kimi-k3",
			"input":"hello",
			"store":true
		}`),
	}, clipexec.Options{SourceFormat: sdktranslator.FormatOpenAIResponse})

	// Then: the request proceeds to NVIDIA instead of returning unsupported_feature.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hits != 1 {
		t.Fatalf("upstream hits=%d", hits)
	}
}

// pinnedFunction is a function id that is not in the registry, so any test that
// sees it proves the per-request pin won over the registry value.
const pinnedFunction = "4f1a2b3c-0000-4000-8000-000000000001"

func TestPreparePayloadFunctionPin(t *testing.T) {
	reg, err := models.Lookup("moonshotai/kimi-k3")
	if err != nil {
		t.Fatal(err)
	}
	e := NewExecutor(Options{})

	cases := []struct {
		name         string
		model        string
		headerPin    string
		headerSlug   string
		headerNS     string
		wantFunction string
		wantSlug     string
		wantNS       string
		wantBody     string
		wantErr      string
	}{
		{
			name:         "no pin uses the registry value",
			model:        "moonshotai/kimi-k3",
			wantFunction: reg.FunctionID,
			wantBody:     "moonshotai/kimi-k3",
		},
		{
			name:         "body pin overrides the function id",
			model:        pinnedFunction + "@moonshotai/kimi-k3",
			wantFunction: pinnedFunction,
			wantBody:     "moonshotai/kimi-k3",
		},
		{
			name:         "header pin overrides the function id",
			model:        "moonshotai/kimi-k3",
			headerPin:    pinnedFunction,
			wantFunction: pinnedFunction,
			wantBody:     "moonshotai/kimi-k3",
		},
		{
			name:         "body pin wins over header pin",
			model:        pinnedFunction + "@moonshotai/kimi-k3",
			headerPin:    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			wantFunction: pinnedFunction,
			wantBody:     "moonshotai/kimi-k3",
		},
		{
			name:         "blank header pin is ignored",
			model:        "moonshotai/kimi-k3",
			headerPin:    "   ",
			wantFunction: reg.FunctionID,
			wantBody:     "moonshotai/kimi-k3",
		},
		{
			name:         "invalid header pin is a client error",
			model:        "moonshotai/kimi-k3",
			headerPin:    "pinned id",
			wantFunction: reg.FunctionID,
			wantErr:      "nv-function-id",
		},
		{
			name:         "pinned unlisted model synthesizes the target",
			model:        pinnedFunction + "@qwen3.8-2.4t-a95b",
			wantFunction: pinnedFunction,
			wantSlug:     "qwen3.8-2.4t-a95b",
			wantBody:     "qwen3.8-2.4t-a95b",
		},
		{
			name:         "publisher/ slug ref keeps only the slug",
			model:        pinnedFunction + "@qwen/qwen3.8-2.4t-a95b",
			wantFunction: pinnedFunction,
			wantSlug:     "qwen3.8-2.4t-a95b",
			wantBody:     "qwen/qwen3.8-2.4t-a95b",
		},
		{
			name:         "header slug + function id synthesize the target",
			model:        "moonshotai/kimi-k3",
			headerPin:    pinnedFunction,
			headerSlug:   "qwen3.8-2.4t-a95b",
			headerNS:     "customns",
			wantFunction: pinnedFunction,
			wantSlug:     "qwen3.8-2.4t-a95b",
			wantNS:       "customns",
			wantBody:     "qwen3.8-2.4t-a95b",
		},
		{
			name:       "header slug without a function id is a client error",
			model:      "moonshotai/kimi-k3",
			headerSlug: "qwen3.8-2.4t-a95b",
			wantErr:    "nv-function-id",
		},
		{
			name:       "invalid header slug is a client error",
			model:      "moonshotai/kimi-k3",
			headerPin:  pinnedFunction,
			headerSlug: "bad slug",
			wantErr:    "nv-function-slug",
		},
		{
			name:    "empty pinned model is a client error",
			model:   pinnedFunction + "@",
			wantErr: "missing model id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.headerPin != "" {
				headers.Set(headerFunctionID, tc.headerPin)
			}
			if tc.headerSlug != "" {
				headers.Set(headerFunctionSlug, tc.headerSlug)
			}
			if tc.headerNS != "" {
				headers.Set(headerFunctionNamespace, tc.headerNS)
			}
			body, info, err := e.preparePayload(clipexec.Request{
				Model:   tc.model,
				Payload: []byte(`{"model":"` + tc.model + `","messages":[{"role":"user","content":"hi"}]}`),
			}, clipexec.Options{SourceFormat: sdktranslator.FormatOpenAI, Headers: headers}, false)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				var ae *coreauth.Error
				if !errors.As(err, &ae) || ae.HTTPStatus != http.StatusBadRequest {
					t.Fatalf("err = %v, want a 400 coreauth.Error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if info.FunctionID != tc.wantFunction {
				t.Fatalf("function id = %q, want %q", info.FunctionID, tc.wantFunction)
			}
			if tc.wantSlug != "" && info.Slug != tc.wantSlug {
				t.Fatalf("slug = %q, want %q", info.Slug, tc.wantSlug)
			}
			if tc.wantNS != "" && info.Namespace != tc.wantNS {
				t.Fatalf("namespace = %q, want %q", info.Namespace, tc.wantNS)
			}
			var probe struct {
				Model string `json:"model"`
			}
			if err := json.Unmarshal(body, &probe); err != nil {
				t.Fatal(err)
			}
			if probe.Model != tc.wantBody {
				t.Fatalf("body model = %q, want %q (the pin must not reach upstream)", probe.Model, tc.wantBody)
			}
		})
	}
}

func TestExecuteStreamSendsPinnedFunctionID(t *testing.T) {
	var gotFunction, gotBodyModel string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFunction = r.Header.Get("nv-function-id")
		var body map[string]any
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("io.ReadAll(r.Body) error = %v", err)
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("json.Unmarshal(request body) error = %v", err)
		}
		gotBodyModel, _ = body["model"].(string)
		w.Header().Set("Content-Type", "text/event-stream")
		if _, err := io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n"); err != nil {
			t.Errorf("io.WriteString: %v", err)
		}
	}))
	defer up.Close()

	e := NewExecutor(Options{
		FlagCaptcha: "P1_test",
		HTTPClient:  up.Client(),
		PredictURL:  func(models.ModelInfo) string { return up.URL },
	})

	pinned := pinnedFunction + "@moonshotai/kimi-k3"
	stream, err := e.ExecuteStream(context.Background(), nil, clipexec.Request{
		Model:   pinned,
		Payload: []byte(`{"model":"` + pinned + `","messages":[{"role":"user","content":"hi"}],"stream":true}`),
	}, clipexec.Options{
		Stream:       true,
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      http.Header{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			t.Fatal(chunk.Err)
		}
	}
	if gotFunction != pinnedFunction {
		t.Fatalf("upstream nv-function-id = %q, want %q", gotFunction, pinnedFunction)
	}
	if gotBodyModel != "moonshotai/kimi-k3" {
		t.Fatalf("upstream body model = %q, want the unpinned model id", gotBodyModel)
	}
}
