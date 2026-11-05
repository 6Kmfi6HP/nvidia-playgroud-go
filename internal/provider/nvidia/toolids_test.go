package nvidia

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	clipexec "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

const toolCallFrame = `{"id":"c1","choices":[{"index":0,"delta":{"role":"assistant",` +
	`"reasoning_content":"think","tool_calls":[{"index":0,"id":"%s","type":"function",` +
	`"function":{"name":"Bash","arguments":"{\"command\":\"echo one\"}"}}]}}]}`

func TestToolCallIDRewriter_MakesRepeatedUpstreamIDsUnique(t *testing.T) {
	first := NewToolCallIDRewriter().RewritePayload([]byte(strings.Replace(toolCallFrame, "%s", "Bash:0", 1)))
	second := NewToolCallIDRewriter().RewritePayload([]byte(strings.Replace(toolCallFrame, "%s", "Bash:0", 1)))

	idOf := func(t *testing.T, raw []byte) string {
		t.Helper()
		var body struct {
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						ID string `json:"id"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("rewritten payload is not valid JSON: %v", err)
		}
		return body.Choices[0].Delta.ToolCalls[0].ID
	}

	a, b := idOf(t, first), idOf(t, second)
	if a == "Bash:0" || b == "Bash:0" {
		t.Fatalf("upstream id was not rewritten: %q, %q", a, b)
	}
	if a == b {
		t.Fatalf("two responses produced the same id %q; the conversation-wide dup is not fixed", a)
	}
}

func TestToolCallIDRewriter_MapsSameUpstreamIDStably(t *testing.T) {
	r := NewToolCallIDRewriter()
	one := string(r.RewritePayload([]byte(strings.Replace(toolCallFrame, "%s", "Bash:0", 1))))
	two := string(r.RewritePayload([]byte(strings.Replace(toolCallFrame, "%s", "Bash:1", 1))))
	three := string(r.RewritePayload([]byte(strings.Replace(toolCallFrame, "%s", "Bash:0", 1))))
	if !strings.Contains(one, `"id":"call_x2a_`) {
		t.Fatalf("first frame id not rewritten: %s", one)
	}
	if !strings.Contains(two, `"id":"call_x2a_`) || !strings.Contains(three, `"id":"call_x2a_`) {
		t.Fatalf("later frames not rewritten: %s | %s", two, three)
	}
	if idIn(t, one) != idIn(t, three) {
		t.Fatalf("same upstream id mapped to different values within one response")
	}
	if idIn(t, one) == idIn(t, two) {
		t.Fatalf("different upstream ids in one response collided")
	}
}

func idIn(t *testing.T, raw string) string {
	t.Helper()
	var body struct {
		Choices []struct {
			Delta struct {
				ToolCalls []struct {
					ID string `json:"id"`
				} `json:"tool_calls"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return body.Choices[0].Delta.ToolCalls[0].ID
}

func TestToolCallIDRewriter_LeavesOtherFramesByteIdentical(t *testing.T) {
	r := NewToolCallIDRewriter()
	for _, frame := range []string{
		`{"choices":[{"delta":{"content":"hello"}}]}`,
		`{"choices":[{"delta":{"reasoning_content":"a \"quoted\" thought"}}]}`,
		`{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"total_tokens":7}}`,
		`{"type":"message_stop"}`,
	} {
		if got := string(r.RewritePayload([]byte(frame))); got != frame {
			t.Fatalf("frame changed:\n want %s\n  got %s", frame, got)
		}
	}
}

func TestToolCallIDRewriter_PreservesSpacingAndReasoning(t *testing.T) {
	frame := `{"choices": [{"delta": {"reasoning_content": "keep  me", "tool_calls": [{"id": "Bash:0", "function": {"name": "Bash"}}]}}]}`
	got := string(NewToolCallIDRewriter().RewritePayload([]byte(frame)))
	if !strings.Contains(got, `"reasoning_content": "keep  me"`) {
		t.Fatalf("reasoning text or spacing changed: %s", got)
	}
	if strings.Contains(got, `"Bash:0"`) {
		t.Fatalf("id not rewritten in the spaced form: %s", got)
	}
	if !strings.Contains(got, `"id": "call_x2a_`) {
		t.Fatalf("spaced id form not preserved: %s", got)
	}
}

func TestToolCallIDRewriter_RewritesNonStreamingMessage(t *testing.T) {
	frame := `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"Bash:0","function":{"name":"Bash"}},{"id":"Bash:1","function":{"name":"Bash"}}]}}]}`
	got := string(NewToolCallIDRewriter().RewritePayload([]byte(frame)))
	if strings.Contains(got, "Bash:0") || strings.Contains(got, "Bash:1") {
		t.Fatalf("non-stream tool ids not rewritten: %s", got)
	}
}

func TestToolCallIDRewriter_SameIDTwiceInOnePayload(t *testing.T) {
	payload := `{"choices":[{"message":{"role":"assistant","tool_calls":[` +
		`{"id":"Bash:0","function":{"name":"Bash"}},` +
		`{"id":"Bash:0","function":{"name":"Bash"}}]}}]}`
	got := string(NewToolCallIDRewriter().RewritePayload([]byte(payload)))
	var body struct {
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					ID string `json:"id"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(got), &body); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, got)
	}
	tcs := body.Choices[0].Message.ToolCalls
	if len(tcs) != 2 {
		t.Fatalf("tool_calls = %d, want 2", len(tcs))
	}
	if tcs[0].ID == "Bash:0" || tcs[1].ID == "Bash:0" {
		t.Fatalf("upstream id survived: %v", tcs)
	}
	if tcs[0].ID == tcs[1].ID {
		t.Fatalf("two calls in one body share the generated id %q", tcs[0].ID)
	}
}

func TestToolCallIDRewriter_HandlesSpacedAndEscapedForms(t *testing.T) {
	spaced := `{"choices":[{"message":{"tool_calls":[{"id": "Bash:0"},{"id": "Bash:1"}]}}]}`
	got := string(NewToolCallIDRewriter().RewritePayload([]byte(spaced)))
	if strings.Contains(got, `"Bash:0"`) || strings.Contains(got, `"Bash:1"`) {
		t.Fatalf("spaced ids not rewritten: %s", got)
	}
	if !strings.Contains(got, `"id": "call_x2a_`) {
		t.Fatalf("spaced form lost: %s", got)
	}

	escaped := "{\"choices\":[{\"message\":{\"tool_calls\":[{\"id\":\"Bas\\u0068:0\"}]}}]}"
	if got := string(NewToolCallIDRewriter().RewritePayload([]byte(escaped))); got != escaped {
		t.Fatalf("escaped id frame must be left untouched:\n want %s\n  got %s", escaped, got)
	}
}

func TestDecodeToolCallID_RoundTrip(t *testing.T) {
	r := NewToolCallIDRewriter()
	for _, orig := range []string{"Bash:0", "call_abc123", "fn|with|pipes", "调用:0", strings.Repeat("x", 200)} {
		gen := r.Rewrite(orig, 0, true)
		if gen == orig {
			t.Fatalf("id %q was not rewritten", orig)
		}
		if got := DecodeToolCallID(gen); got != orig {
			t.Fatalf("round trip failed: %q -> %q -> %q", orig, gen, got)
		}
	}
}

func TestDecodeToolCallID_PassthroughForUnknownIDs(t *testing.T) {
	for _, id := range []string{
		"",
		"Bash:0",
		"call_9x8y7z",
		generatedToolIDPrefix,            // prefix only, nothing to decode
		generatedToolIDPrefix + "!!!",    // invalid base64
		generatedToolIDPrefix + "eA",     // valid base64, wrong inner shape
		generatedToolIDPrefix + "MXx8fA", // "1|||"-adjacent shapes: empty original
	} {
		if got := DecodeToolCallID(id); got != id {
			t.Fatalf("DecodeToolCallID(%q) = %q, want passthrough", id, got)
		}
	}

	r := NewToolCallIDRewriter()
	gen := r.Rewrite("Bash:0", 0, true)
	if got := r.Rewrite(gen, 0, true); got != gen {
		t.Fatalf("generated id was double-rewritten: %q -> %q", gen, got)
	}

	a := r.Rewrite("Bash:0", 0, true)
	b := r.Rewrite("Bash:0", 1, true)
	if a == b {
		t.Fatalf("indexed calls collided under the new encoding: %q", a)
	}
	if DecodeToolCallID(a) != "Bash:0" || DecodeToolCallID(b) != "Bash:0" {
		t.Fatalf("indexed decode mismatch: %q -> %q, %q -> %q", a, DecodeToolCallID(a), b, DecodeToolCallID(b))
	}
}

func TestDecodeClaudeToolCallIDs(t *testing.T) {
	minted := NewToolCallIDRewriter().Rewrite("Bash:0", 0, true)
	raw := []byte(`{"model":"m","max_tokens":5,"messages":[` +
		`{"role":"user","content":"run ls"},` +
		`{"role":"assistant","content":[{"type":"tool_use","id":"` + minted + `","name":"Bash","input":{"cmd":"ls"}}]},` +
		`{"role":"user","content":[{"type":"tool_result","tool_use_id":"` + minted + `","content":"file1"},{"type":"text","text":"done"}]}]}`)
	out := DecodeClaudeToolCallIDs(raw)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	msgs := m["messages"].([]any)
	asst := msgs[1].(map[string]any)["content"].([]any)[0].(map[string]any)
	user := msgs[2].(map[string]any)["content"].([]any)[0].(map[string]any)
	if asst["id"] != "Bash:0" {
		t.Fatalf("tool_use.id = %q, want Bash:0", asst["id"])
	}
	if user["tool_use_id"] != "Bash:0" {
		t.Fatalf("tool_result.tool_use_id = %q, want Bash:0", user["tool_use_id"])
	}
	if asst["name"] != "Bash" {
		t.Fatalf("tool name must not be touched, got %q", asst["name"])
	}
	if bytes.Contains(out, []byte("call_x2a_")) {
		t.Fatalf("minted id survived: %s", out)
	}

	// Native ids pass through unchanged.
	native := []byte(`{"model":"m","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"f","input":{}}]}]}`)
	if got := DecodeClaudeToolCallIDs(native); string(got) != string(native) {
		t.Fatalf("native ids modified: %s", got)
	}
}

func TestDecodeOpenAIToolCallIDs(t *testing.T) {
	minted := NewToolCallIDRewriter().Rewrite("Bash:0", 0, true)
	raw := []byte(`{"model":"m","messages":[` +
		`{"role":"assistant","tool_calls":[{"id":"` + minted + `","type":"function","function":{"name":"Bash"}}]},` +
		`{"role":"tool","tool_call_id":"` + minted + `","content":"result"}]}`)
	out := DecodeOpenAIToolCallIDs(raw)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	msgs := m["messages"].([]any)
	asst := msgs[0].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)
	toolMsg := msgs[1].(map[string]any)
	if asst["id"] != "Bash:0" {
		t.Fatalf("tool_calls[0].id = %q, want Bash:0", asst["id"])
	}
	if toolMsg["tool_call_id"] != "Bash:0" {
		t.Fatalf("tool_call_id = %q, want Bash:0", toolMsg["tool_call_id"])
	}
}

func TestExecutor_Execute_RewritesToolCallIDs(t *testing.T) {
	respBody := `{"id":"chatcmpl-1","choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"Bash:0","type":"function","function":{"name":"Bash","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(respBody)),
		}, nil
	})

	exec := NewExecutor(Options{
		FlagCaptcha: "test-token",
		HTTPClient:  &http.Client{Transport: transport},
	})

	// Claude protocol request
	claudeReq := []byte(`{"model":"moonshotai/kimi-k3","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`)
	res, err := exec.Execute(context.Background(), &coreauth.Auth{}, clipexec.Request{
		Model:   "moonshotai/kimi-k3",
		Payload: claudeReq,
	}, clipexec.Options{
		SourceFormat: sdktranslator.FormatClaude,
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	out := string(res.Payload)
	if strings.Contains(out, "Bash:0") {
		t.Fatalf("tool call id was not rewritten in Claude response: %s", out)
	}
	if !strings.Contains(out, "call_x2a_") {
		t.Fatalf("expected call_x2a_ prefix in Claude response: %s", out)
	}
}

func TestExecutor_ExecuteStream_RewritesToolCallIDs(t *testing.T) {
	sseFrames := "data: " + strings.Replace(toolCallFrame, "%s", "Bash:0", 1) + "\n\n" +
		"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n" +
		"data: [DONE]\n\n"

	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(sseFrames)),
		}, nil
	})

	exec := NewExecutor(Options{
		FlagCaptcha: "test-token",
		HTTPClient:  &http.Client{Transport: transport},
	})

	openAIReq := []byte(`{"model":"moonshotai/kimi-k3","messages":[{"role":"user","content":"hi"}],"stream":true}`)
	streamRes, err := exec.ExecuteStream(context.Background(), &coreauth.Auth{}, clipexec.Request{
		Model:   "moonshotai/kimi-k3",
		Payload: openAIReq,
	}, clipexec.Options{
		Stream:       true,
		SourceFormat: sdktranslator.FormatOpenAI,
	})
	if err != nil {
		t.Fatalf("ExecuteStream failed: %v", err)
	}

	var allOutput string
	for chunk := range streamRes.Chunks {
		if chunk.Err != nil {
			t.Fatalf("chunk error: %v", chunk.Err)
		}
		allOutput += string(chunk.Payload)
	}

	if strings.Contains(allOutput, "Bash:0") {
		t.Fatalf("stream tool call id was not rewritten: %s", allOutput)
	}
	if !strings.Contains(allOutput, "call_x2a_") {
		t.Fatalf("stream output missing call_x2a_ prefix: %s", allOutput)
	}
}

func TestExecutor_ExecuteStream_ClaudeProtocol_RewritesToolCallIDs(t *testing.T) {
	sseFrames := "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n" +
		"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"Bash:0\",\"type\":\"function\",\"function\":{\"name\":\"Bash\",\"arguments\":\"\"}}]}}]}\n\n" +
		"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"cmd\\\":\\\"ls\\\"}\"}}]}}]}\n\n" +
		"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n" +
		"data: [DONE]\n\n"

	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(sseFrames)),
		}, nil
	})

	exec := NewExecutor(Options{
		FlagCaptcha: "test-token",
		HTTPClient:  &http.Client{Transport: transport},
	})

	claudeReq := []byte(`{"model":"moonshotai/kimi-k3","max_tokens":100,"stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	streamRes, err := exec.ExecuteStream(context.Background(), &coreauth.Auth{}, clipexec.Request{
		Model:   "moonshotai/kimi-k3",
		Payload: claudeReq,
	}, clipexec.Options{
		Stream:          true,
		OriginalRequest: claudeReq,
		SourceFormat:    sdktranslator.FormatClaude,
	})
	if err != nil {
		t.Fatalf("ExecuteStream failed: %v", err)
	}

	var allOutput string
	for chunk := range streamRes.Chunks {
		if chunk.Err != nil {
			t.Fatalf("chunk error: %v", chunk.Err)
		}
		allOutput += string(chunk.Payload)
	}

	if strings.Contains(allOutput, "Bash:0") {
		t.Fatalf("stream tool call id was not rewritten in Claude stream: %s", allOutput)
	}
	if !strings.Contains(allOutput, "call_x2a_") {
		t.Fatalf("stream output missing call_x2a_ prefix in Claude stream: %s", allOutput)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
