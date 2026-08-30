package main

// Per-request NVCF function-id targeting at the gateway edge.
//
// The playground predict call is keyed by namespace/slug plus the
// nv-function-id header, and NVIDIA aliases several backend versions onto one
// slug. The registry stores exactly one function id per model id, so a client
// that wants a specific instance has to say so per request. Two inbound forms
// are accepted on the JSON chat endpoints:
//
//	{"model": "1586112a-925c-48af-8631-7c815dbd749c@moonshotai/kimi-k3", ...}
//	nv-function-id: 1586112a-925c-48af-8631-7c815dbd749c
//
// cliproxy routes a request by exact model id before any executor sees it, so
// the "@function-id" prefix cannot reach the handler: this middleware splits
// the pin off the body, validates it against the registry, and republishes it
// as the nv-function-id header. The nvidia executor then reads that header and
// overrides the registry value (internal/provider/nvidia/executor.go).
//
// The body pin wins over a header pin when both are sent, because it names the
// target in the same field that selects the model.
//
// A pinned model the registry does not list (functions NVIDIA serves without
// a playground page) is not rejected: the middleware rewrites the body model
// to the gateway's registered default so cliproxy can route the request, and
// carries the real target in the nv-function-id + nv-function-slug headers.
// The executor then synthesizes the predict target from the headers.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"glm52-nvidia/internal/models"

	"github.com/gin-gonic/gin"
	sdkginhandlers "github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// functionIDHeader is the NVCF function header: accepted inbound, rewritten
// from a body pin, and read by the nvidia executor. functionSlugHeader names
// the predict slug for pinned targets the registry does not list (set by this
// middleware from an unknown "<pin>@<model>" or directly by clients);
// functionNamespaceHeader optionally overrides the shared namespace.
const (
	functionIDHeader        = "nv-function-id"
	functionSlugHeader      = "nv-function-slug"
	functionNamespaceHeader = "nv-function-namespace"
)

// pinnablePaths are the JSON chat endpoints whose request body carries a
// top-level "model" field. Model listings, uploads and websocket upgrades are
// passed through untouched.
var pinnablePaths = map[string]struct{}{
	"/v1/chat/completions":                 {},
	"/v1/completions":                      {},
	"/v1/messages":                         {},
	"/v1/messages/count_tokens":            {},
	"/v1/responses":                        {},
	"/v1/responses/compact":                {},
	"/backend-api/codex/responses":         {},
	"/backend-api/codex/responses/compact": {},
}

// functionPinMiddleware rewrites "<function-id>@<model>" request bodies into a
// plain model id plus an nv-function-id header, and rejects malformed pins
// with 400 before cliproxy's router turns them into a confusing 502.
func functionPinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		req := c.Request
		if req == nil || req.Body == nil || req.Method != http.MethodPost || !isPinnablePath(req.URL.Path) {
			c.Next()
			return
		}
		// Compressed bodies are decoded by the handlers themselves, so the pin
		// would have to be applied after decoding; leave those alone.
		if strings.TrimSpace(req.Header.Get("Content-Encoding")) != "" || !isJSONContent(req.Header.Get("Content-Type")) {
			c.Next()
			return
		}

		raw, err := io.ReadAll(req.Body)
		if cerr := req.Body.Close(); cerr != nil && err == nil {
			err = cerr
		}
		if err != nil {
			// Partial read: hand back what arrived and let the handler report it.
			req.Body = io.NopCloser(bytes.NewReader(raw))
			c.Next()
			return
		}

		body, pin, slug, perr := applyFunctionPin(raw, strings.TrimSpace(req.Header.Get(functionIDHeader)))
		if perr != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, sdkginhandlers.ErrorResponse{
				Error: sdkginhandlers.ErrorDetail{Message: perr.Error(), Type: "invalid_request_error"},
			})
			return
		}
		if pin != "" {
			req.Header.Set(functionIDHeader, pin)
		}
		if slug != "" {
			req.Header.Set(functionSlugHeader, slug)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		c.Next()
	}
}

// applyFunctionPin returns the body to serve, the function id to publish in
// the nv-function-id header, and — for pinned targets the registry does not
// list — the slug ref to publish in nv-function-slug. An empty pin means
// "nothing to pin" and body is raw, unchanged.
func applyFunctionPin(raw []byte, headerPin string) (body []byte, pin, slug string, err error) {
	pin, base, hasPin := models.SplitFunctionRef(gjson.GetBytes(raw, "model").String())
	if !hasPin {
		if headerPin != "" && !models.ValidFunctionID(headerPin) {
			return raw, "", "", models.InvalidFunctionIDError(headerPin)
		}
		return raw, "", "", nil
	}
	if err := models.ValidateFunctionRef(pin, base); err != nil {
		return nil, "", "", err
	}
	if _, err := models.Lookup(base); err == nil {
		// Registered model: plain pin; the real model id still routes.
		rewritten, serr := sjson.SetBytes(raw, "model", base)
		if serr != nil {
			return nil, "", "", serr
		}
		return rewritten, pin, "", nil
	}
	// Unlisted pinned target: cliproxy can only route registered models, so
	// the body carries the gateway default and the real target travels in the
	// nv-function-id / nv-function-slug headers. The executor synthesizes the
	// model info from them and restores the slug in the upstream body.
	if !models.ValidSlugRef(base) {
		return nil, "", "", fmt.Errorf("invalid pinned model %q: use up to 256 characters from [A-Za-z0-9._/-]", base)
	}
	rewritten, err := sjson.SetBytes(raw, "model", models.DefaultModel)
	if err != nil {
		return nil, "", "", err
	}
	return rewritten, pin, base, nil
}

func isPinnablePath(path string) bool {
	_, ok := pinnablePaths[path]
	return ok
}

// isJSONContent accepts the JSON bodies these endpoints take, including
// clients that omit Content-Type entirely.
func isJSONContent(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	return ct == "" || strings.Contains(ct, "json")
}
