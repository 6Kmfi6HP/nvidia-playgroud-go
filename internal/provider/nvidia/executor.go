package nvidia

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	glm52 "glm52-nvidia"
	"glm52-nvidia/internal/captcha"
	"glm52-nvidia/internal/models"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	clipexec "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

const providerKey = "nvidia"

// headerFunctionID is the NVCF function header: set on every upstream predict
// request, and read back from inbound gateway requests so a client can pin the
// instance it wants. headerCaptchaToken is the one-shot hCaptcha passcode.
//
// headerFunctionSlug / headerFunctionNamespace name a predict target the
// registry does not list (functions NVIDIA serves without a playground page):
// both travel as inbound headers — set by the gateway middleware when a body
// pin's model id is unknown, or directly by clients — and let the executor
// synthesize the invocation triple instead of rejecting the request.
const (
	headerFunctionID        = "nv-function-id"
	headerFunctionSlug      = "nv-function-slug"
	headerFunctionNamespace = "nv-function-namespace"
	headerCaptchaToken      = "nv-captcha-token"
)

// Options configures the Nvidia playground executor.
type Options struct {
	FlagCaptcha  string
	Coalesce     time.Duration
	MaxInflight  int
	InflightWait time.Duration
	CaptchaWait  time.Duration
	HTTPClient   *http.Client
	Pool         *captcha.Pool

	// PredictURL optionally overrides models.ModelInfo.PredictEndpoint (tests).
	PredictURL func(models.ModelInfo) string
}

// Executor implements coreauth.ProviderExecutor for NVIDIA playground predict.
type Executor struct {
	coalesce     time.Duration
	httpClient   *http.Client
	inflight     chan struct{}
	inflightWait time.Duration
	captchaWait  time.Duration
	pool         *captcha.Pool
	predictURL   func(models.ModelInfo) string

	beforeInflightWait func()
	beforeSend         func()

	mu          sync.Mutex
	flagCaptcha string
}

// NewExecutor builds an Executor from Options.
func NewExecutor(opts Options) *Executor {
	e := &Executor{
		coalesce:     opts.Coalesce,
		httpClient:   opts.HTTPClient,
		inflightWait: opts.InflightWait,
		captchaWait:  opts.CaptchaWait,
		pool:         opts.Pool,
		predictURL:   opts.PredictURL,
		flagCaptcha:  opts.FlagCaptcha,
	}
	if e.httpClient == nil {
		e.httpClient = http.DefaultClient
	}
	if opts.MaxInflight > 0 {
		e.inflight = make(chan struct{}, opts.MaxInflight)
	}
	return e
}

// Identifier returns the provider key.
func (e *Executor) Identifier() string { return providerKey }

// Pool returns the captcha pool (may be nil).
func (e *Executor) Pool() *captcha.Pool { return e.pool }

// PrepareRequest is a no-op for playground auth (captcha is per-request).
func (e *Executor) PrepareRequest(_ *http.Request, _ *coreauth.Auth) error { return nil }

// Refresh returns auth unchanged.
func (e *Executor) Refresh(_ context.Context, a *coreauth.Auth) (*coreauth.Auth, error) {
	return a, nil
}

// HttpRequest injects nothing and executes via the shared client.
func (e *Executor) HttpRequest(ctx context.Context, a *coreauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("nvidia executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if err := e.PrepareRequest(httpReq, a); err != nil {
		return nil, err
	}
	return e.httpClient.Do(httpReq)
}

// Execute handles non-streaming chat completions against NVIDIA predict.
func (e *Executor) Execute(ctx context.Context, _ *coreauth.Auth, req clipexec.Request, opts clipexec.Options) (clipexec.Response, error) {
	body, info, err := e.preparePayload(req, opts, false)
	if err != nil {
		return clipexec.Response{}, err
	}
	upResp, release, err := e.doPredict(ctx, info, body, opts)
	if err != nil {
		return clipexec.Response{}, err
	}
	defer release()
	defer upResp.Body.Close()

	raw, err := io.ReadAll(upResp.Body)
	if err != nil {
		return clipexec.Response{}, err
	}
	from := sdktranslator.FormatOpenAI
	to := clipexec.ResponseFormatOrSource(opts)
	out := sdktranslator.TranslateNonStream(ctx, from, to, req.Model, opts.OriginalRequest, body, raw, nil)
	return clipexec.Response{Payload: out, Headers: upResp.Header.Clone()}, nil
}

// ExecuteStream handles streaming chat completions against NVIDIA predict.
func (e *Executor) ExecuteStream(ctx context.Context, _ *coreauth.Auth, req clipexec.Request, opts clipexec.Options) (*clipexec.StreamResult, error) {
	body, info, err := e.preparePayload(req, opts, true)
	if err != nil {
		return nil, err
	}
	upResp, release, err := e.doPredict(ctx, info, body, opts)
	if err != nil {
		return nil, err
	}

	out := make(chan clipexec.StreamChunk, 16)
	go func() {
		defer close(out)
		defer release()
		defer upResp.Body.Close()

		from := sdktranslator.FormatOpenAI
		to := clipexec.ResponseFormatOrSource(opts)
		var param any

		emitLine := func(line string) error {
			chunks := sdktranslator.TranslateStream(ctx, from, to, req.Model, opts.OriginalRequest, body, []byte(line), &param)
			for _, chunk := range chunks {
				select {
				case out <- clipexec.StreamChunk{Payload: chunk}:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		}

		if err := coalesceSSEEvents(upResp.Body, e.coalesce, emitLine); err != nil && ctx.Err() == nil {
			select {
			case out <- clipexec.StreamChunk{Err: err}:
			case <-ctx.Done():
			}
		}
	}()

	return &clipexec.StreamResult{Headers: upResp.Header.Clone(), Chunks: out}, nil
}

func (e *Executor) preparePayload(req clipexec.Request, opts clipexec.Options, stream bool) ([]byte, models.ModelInfo, error) {
	from := opts.SourceFormat
	if from == "" {
		from = sdktranslator.FormatOpenAI
	}
	model := req.Model
	payload, err := translateToChat(from, model, req.Payload, stream)
	if err != nil {
		return nil, models.ModelInfo{}, requestErr(http.StatusBadRequest, "invalid json body")
	}

	body, err := NormalizeRequestBody(payload)
	if err != nil {
		return nil, models.ModelInfo{}, requestErr(http.StatusBadRequest, "invalid json body")
	}

	// Ensure stream flag matches the execution mode after translation.
	body, err = forceStreamFlag(body, stream)
	if err != nil {
		return nil, models.ModelInfo{}, requestErr(http.StatusBadRequest, "invalid json body")
	}

	var modelProbe struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &modelProbe)
	lookupModel := modelProbe.Model
	if lookupModel == "" {
		lookupModel = model
	}

	info, canonical, err := resolveInvokeTarget(lookupModel, opts.Headers)
	if err != nil {
		// Both shapes reaching here are client errors: an unknown model id, or a
		// malformed "<function-id>@" pin.
		return nil, models.ModelInfo{}, requestErr(http.StatusBadRequest, err.Error())
	}
	// A "<function-id>@<model>" pin is gateway routing syntax: the upstream
	// body must carry the plain registry model id.
	if canonical != modelProbe.Model {
		body, err = setBodyModel(body, canonical)
		if err != nil {
			return nil, models.ModelInfo{}, requestErr(http.StatusBadRequest, "invalid json body")
		}
	}
	return body, info, nil
}

// resolveInvokeTarget looks up the predict target for a model id, applying a
// per-request NVCF function-id pin. The pin comes from the model field
// ("<function-id>@<publisher>/<slug>", which wins) or from the inbound
// nv-function-id header; the gateway middleware rewrites a body pin into that
// header so cliproxy's model routing still sees a known model id.
//
// When the pinned model is not in the registry — functions NVIDIA serves
// without a playground page — the target is synthesized from the pin instead
// of rejected. The same is possible without a body pin via nv-function-slug
// (plus nv-function-id) headers, optionally with nv-function-namespace.
func resolveInvokeTarget(model string, headers http.Header) (models.ModelInfo, string, error) {
	pin, base, hasPin := models.SplitFunctionRef(model)
	if hasPin {
		if err := models.ValidateFunctionRef(pin, base); err != nil {
			return models.ModelInfo{}, "", err
		}
	} else {
		base = model
	}

	// Header-named unlisted target (middleware rewrite of an unknown body pin,
	// or a client that can only set headers): everything comes from headers.
	if slug := strings.TrimSpace(headers.Get(headerFunctionSlug)); slug != "" && !hasPin {
		info, err := synthesizeHeaderTarget(headers, slug)
		if err != nil {
			return models.ModelInfo{}, "", err
		}
		// The upstream body carries the slug ref, not the carrier model id the
		// gateway routed on.
		return info, slug, nil
	}

	info, err := models.Lookup(base)
	if err != nil {
		if hasPin {
			// Pinned model the registry does not list: build the triple from
			// the pin instead of rejecting (unknown model has no routing path
			// here unless the middleware rewrote it, which already failed).
			info, serr := synthesizePinned(pin, base, headers)
			if serr != nil {
				return models.ModelInfo{}, "", serr
			}
			return info, base, nil
		}
		return models.ModelInfo{}, "", err
	}
	if hasPin {
		info.FunctionID = pin
		return info, base, nil
	}

	if hdr := strings.TrimSpace(headers.Get(headerFunctionID)); hdr != "" {
		if !models.ValidFunctionID(hdr) {
			return models.ModelInfo{}, "", models.InvalidFunctionIDError(hdr)
		}
		info.FunctionID = hdr
	}
	return info, model, nil
}

// synthesizeHeaderTarget builds the invocation triple from the nv-function-*
// headers alone. slug must look like a predict slug; the function id is
// required; the namespace header is optional (defaulting to the shared
// playground namespace).
func synthesizeHeaderTarget(headers http.Header, slug string) (models.ModelInfo, error) {
	if !models.ValidSlugRef(slug) {
		return models.ModelInfo{}, fmt.Errorf("invalid %s %q: use up to 256 characters from [A-Za-z0-9._/-]", headerFunctionSlug, slug)
	}
	pin := strings.TrimSpace(headers.Get(headerFunctionID))
	if !models.ValidFunctionID(pin) {
		return models.ModelInfo{}, fmt.Errorf("%s requires a valid %s header (got %q)", headerFunctionSlug, headerFunctionID, pin)
	}
	return models.SynthesizeFunctionRef(pin, slug, strings.TrimSpace(headers.Get(headerFunctionNamespace))), nil
}

// synthesizePinned builds the invocation triple for "<function-id>@<model>"
// when the model portion is not in the registry: the model string is the
// slug ref and the pin is the function id. The optional namespace header
// overrides the shared playground namespace.
func synthesizePinned(pin, base string, headers http.Header) (models.ModelInfo, error) {
	if !models.ValidSlugRef(base) {
		return models.ModelInfo{}, fmt.Errorf("invalid model %q for a function pin: use up to 256 characters from [A-Za-z0-9._/-]", base)
	}
	return models.SynthesizeFunctionRef(pin, base, strings.TrimSpace(headers.Get(headerFunctionNamespace))), nil
}

func setBodyModel(body []byte, model string) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	raw["model"] = model
	return json.Marshal(raw)
}

func forceStreamFlag(body []byte, stream bool) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	raw["stream"] = stream
	if stream {
		opts, _ := raw["stream_options"].(map[string]any)
		if opts == nil {
			opts = map[string]any{}
			raw["stream_options"] = opts
		}
		if _, ok := opts["include_usage"]; !ok {
			opts["include_usage"] = true
		}
		opts["continuous_usage_stats"] = false
	}
	return json.Marshal(raw)
}

func (e *Executor) doPredict(ctx context.Context, info models.ModelInfo, body []byte, opts clipexec.Options) (*http.Response, func(), error) {
	clientToken := ""
	if opts.Headers != nil {
		clientToken = opts.Headers.Get(headerCaptchaToken)
	}
	maxAttempts := 1
	if clientToken == "" && e.pool != nil {
		maxAttempts = 3
	}

	var release func()
	cleanup := func() {
		if release != nil {
			release()
			release = nil
		}
	}

	endpoint := info.PredictEndpoint()
	if e.predictURL != nil {
		endpoint = e.predictURL(info)
	}

	var upResp *http.Response
	staleLeases := 0
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		token, lease, err := e.resolveCaptcha(ctx, clientToken, attempt == 1)
		if err != nil {
			cleanup()
			return nil, nil, captchaErr(err)
		}

		rel, err := e.acquireInflight(ctx)
		if err != nil {
			if lease != nil {
				lease.Release()
			}
			cleanup()
			return nil, nil, &coreauth.Error{
				Code:       "request_scoped",
				Message:    err.Error(),
				HTTPStatus: http.StatusServiceUnavailable,
			}
		}
		release = rel

		upReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			cleanup()
			if lease != nil {
				lease.Release()
			}
			return nil, nil, err
		}
		upReq.Header.Set("Content-Type", "application/json")
		upReq.Header.Set("Accept", "text/event-stream")
		upReq.Header.Set(headerFunctionID, info.FunctionID)
		upReq.Header.Set(headerCaptchaToken, token)
		upReq.Header.Set("Origin", "https://build.nvidia.com")
		upReq.Header.Set("Referer", "https://build.nvidia.com/")

		if e.beforeSend != nil {
			e.beforeSend()
		}
		if err := ctx.Err(); err != nil {
			cleanup()
			if lease != nil {
				lease.Release()
			}
			return nil, nil, captchaErr(err)
		}
		if lease != nil && !lease.Commit() {
			cleanup()
			staleLeases++
			if staleLeases >= maxAttempts {
				return nil, nil, &coreauth.Error{
					Code:       "request_scoped",
					Message:    "captcha token invalid or expired; retry the request",
					HTTPStatus: http.StatusUnauthorized,
				}
			}
			attempt--
			continue
		}
		upResp, err = e.httpClient.Do(upReq)
		if err != nil {
			cleanup()
			return nil, nil, &coreauth.Error{
				Code:       "upstream_error",
				Message:    fmt.Sprintf("upstream: %v", err),
				HTTPStatus: http.StatusBadGateway,
			}
		}

		if upResp.StatusCode < 400 {
			return upResp, cleanup, nil
		}

		raw, _ := io.ReadAll(io.LimitReader(upResp.Body, 4<<10))
		status := upResp.StatusCode
		_ = upResp.Body.Close()
		upResp = nil
		release()
		release = nil

		retryable := isRetryableCaptchaFailure(status, raw)
		if retryable && attempt < maxAttempts {
			log.Printf("upstream captcha failure status=%d (attempt %d/%d); fetching a fresh token",
				status, attempt, maxAttempts)
			continue
		}
		if retryable {
			return nil, nil, &coreauth.Error{
				Code:       "request_scoped",
				Message:    "captcha token invalid or expired; retry the request",
				HTTPStatus: http.StatusUnauthorized,
			}
		}
		msg := strings.TrimSpace(string(raw))
		if msg == "" {
			msg = "upstream request failed"
		}
		return nil, nil, &coreauth.Error{
			Code:       "upstream_error",
			Message:    msg,
			HTTPStatus: http.StatusBadGateway,
		}
	}
	return nil, nil, &coreauth.Error{
		Code:       "request_scoped",
		Message:    "captcha token invalid or expired; retry the request",
		HTTPStatus: http.StatusUnauthorized,
	}
}

func (e *Executor) acquireInflight(ctx context.Context) (release func(), err error) {
	if e.inflight == nil {
		return func() {}, nil
	}
	release = func() { <-e.inflight }

	if e.inflightWait <= 0 {
		select {
		case e.inflight <- struct{}{}:
			return release, nil
		default:
			return nil, fmt.Errorf("max in-flight upstream streams reached; retry later")
		}
	}

	timer := time.NewTimer(e.inflightWait)
	defer timer.Stop()
	if e.beforeInflightWait != nil {
		e.beforeInflightWait()
	}
	select {
	case e.inflight <- struct{}{}:
		return release, nil
	case <-timer.C:
		return nil, fmt.Errorf("max in-flight upstream streams reached; retry later")
	case <-ctx.Done():
		return nil, fmt.Errorf("client cancelled before a stream slot opened")
	}
}

func (e *Executor) resolveCaptcha(ctx context.Context, clientToken string, allowFlag bool) (string, *captcha.TokenLease, error) {
	if clientToken != "" {
		return clientToken, nil, nil
	}

	if allowFlag {
		e.mu.Lock()
		flagToken := e.flagCaptcha
		if flagToken != "" {
			e.flagCaptcha = ""
		}
		e.mu.Unlock()
		if flagToken != "" {
			return flagToken, nil, nil
		}
	}

	if e.pool != nil {
		takeCtx := ctx
		var cancel context.CancelFunc
		if e.captchaWait > 0 {
			takeCtx, cancel = context.WithTimeout(ctx, e.captchaWait)
			defer cancel()
		}
		if e.pool.Ready() == 0 {
			waitFor := "indefinitely"
			if e.captchaWait > 0 {
				waitFor = e.captchaWait.String()
			}
			log.Printf("captcha pool empty; waiting up to %s (errors will surface from workers)", waitFor)
		}
		lease, err := e.pool.TakeLease(takeCtx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				fills, takes, errs, expired := e.pool.Stats()
				return "", nil, fmt.Errorf("captcha pool empty after %s (ready=%d fills=%d takes=%d errors=%d expired=%d); retry later",
					e.captchaWait, e.pool.Ready(), fills, takes, errs, expired)
			}
			return "", nil, err
		}
		token := lease.Token()
		return token, lease, nil
	}
	return "", nil, fmt.Errorf("captcha token required: send nv-captcha-token, or restart with -captcha / -auto")
}

func captchaErr(err error) error {
	status := http.StatusUnauthorized
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "captcha pool empty after") {
		status = http.StatusServiceUnavailable
	} else if errors.Is(err, context.Canceled) {
		status = http.StatusRequestTimeout
	}
	return &coreauth.Error{
		Code:       "request_scoped",
		Message:    err.Error(),
		HTTPStatus: status,
	}
}

func requestErr(status int, msg string) error {
	return &coreauth.Error{
		Code:       "request_scoped",
		Message:    msg,
		HTTPStatus: status,
	}
}

// isRetryableCaptchaFailure reports whether an upstream 4xx is a captcha /
// hCaptcha token failure fixed by fetching a fresh token and retrying.
func isRetryableCaptchaFailure(status int, raw []byte) bool {
	if status < 400 || status >= 500 {
		return false
	}
	if len(raw) == 0 {
		return false
	}
	var er glm52.ErrorResponse
	if json.Unmarshal(raw, &er) == nil {
		desc := strings.ToLower(er.RequestStatus.StatusDescription)
		if strings.Contains(desc, "token is invalid") || strings.Contains(desc, "invalid token") {
			return true
		}
		if er.RequestStatus.StatusCode == "INVALID_REQUEST" && strings.Contains(desc, "token") {
			return true
		}
	}
	low := strings.ToLower(string(raw))
	if strings.Contains(low, "token is invalid") {
		return true
	}
	return strings.Contains(low, "captcha") || strings.Contains(low, "hcaptcha")
}
