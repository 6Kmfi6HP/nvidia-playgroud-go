// Tool-call id uniqueness. Some upstreams (moonshotai/kimi-k3) derive OpenAI
// tool-call ids from the function name and the call index ("Bash:0"), so the
// same id reappears on every turn of a conversation. Claude Code removes every
// tool_use block whose id it has already seen in that conversation; when that
// empties the assistant message, it injects the bare text
// "[Tool use interrupted]".
// Replacing each emitted id with a per-response value that cannot have been
// seen before removes the collision at the source.

package nvidia

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// generatedToolIDPrefix marks ids this package produced. It is also the fast
// path guard: an id already carrying the prefix needs no rewrite. Generated
// ids are self-contained: the original upstream id heads the generated value
// (prefix + base64.RawURLEncoding of [v1, "index|id"|"id", salt]), so a later
// request that references the call — a Claude tool_result block's
// tool_use_id — can be restored server-side without any cross-request table
// (DecodeToolCallID). The trailing per-response salt keeps ids for the same
// upstream call distinct across turns (conversation-keying clients drop
// repeats; see the file header), and sits last so decoding never has to hunt
// for a plain-text id inside the payload. RawURLEncoding's alphabet
// (A–Z a–z 0–9 - _) matches the character set providers accept for tool-call
// ids, so the encoded value is echo-safe verbatim, and the prefix keeps it
// from ever colliding with a genuine upstream id.
const generatedToolIDPrefix = "call_x2a_"

// ToolCallIDRewriter rewrites the tool-call ids of one response. It is not safe
// for concurrent use; the response stream drives it from a single goroutine.
type ToolCallIDRewriter struct {
	seed   uint64
	mapped map[string]string // call key -> generated id, per response
}

// NewToolCallIDRewriter returns a rewriter for one response, seeded so two
// responses never emit the same id for the same upstream call.
func NewToolCallIDRewriter() *ToolCallIDRewriter {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure: no usable entropy, cannot mint unique ids
	}
	return &ToolCallIDRewriter{
		seed:   binary.BigEndian.Uint64(b[:]),
		mapped: make(map[string]string),
	}
}

// Rewrite returns the generated id for one upstream tool-call id. The same
// (index, id) pair always maps to the same result, so a streamed call stays
// stable across the frames that re-send its id, while two different calls that
// happen to share an id do not collide. An id this rewriter already generated
// is returned unchanged.
func (r *ToolCallIDRewriter) Rewrite(original string, index int, hasIndex bool) string {
	key := original
	if hasIndex {
		key = fmt.Sprintf("%d\x00%s", index, original)
	}
	return r.rewriteKey(key, original)
}

// rewriteKey is Rewrite's body under an explicit map key: RewritePayload keys
// calls the upstream gave no index to by their occurrence in the payload, so a
// body listing the same id twice still yields two distinct generated ids.
// The discriminator mirrors the map key's leading segment ("<index>" /
// "#<occurrence>") paired with the original id, so two calls sharing an
// upstream id never encode to the same value while the payload stays
// self-contained for DecodeToolCallID. The salt is appended last: framed
// "<v>|<disc>|<original>|<salt hex>", all inside the base64 payload, so any
// truncated copy round-trips as an opaque (unmatched) id instead of
// decoding to a wrong call.
//
// The generated id embeds the original (see generatedToolIDPrefix) so the
// mapping survives the response boundary; the in-memory table only serves
// stability within this one response.
func (r *ToolCallIDRewriter) rewriteKey(key, original string) string {
	if original == "" || bytes.HasPrefix([]byte(original), []byte(generatedToolIDPrefix)) {
		return original
	}
	if v, ok := r.mapped[key]; ok {
		return v
	}
	disc, _, _ := bytes.Cut([]byte(key), []byte{0}) // "<index>" or "#<occurrence>"
	r.seed++
	payload := fmt.Sprintf("1|%s|%s|%x", disc, original, r.seed)
	v := generatedToolIDPrefix + base64.RawURLEncoding.EncodeToString([]byte(payload))
	r.mapped[key] = v
	return v
}

// DecodeToolCallID reverses a gateway-generated tool-call id (see
// generatedToolIDPrefix) back to the original upstream id. Non-generated ids
// are returned unchanged, so callers can apply it unconditionally and leave
// native ids untouched; a value that only imitates the prefix but does not
// decode is passed through as-is (idempotent, never destructive).
func DecodeToolCallID(id string) string {
	if !bytes.HasPrefix([]byte(id), []byte(generatedToolIDPrefix)) {
		return id
	}
	raw, err := base64.RawURLEncoding.DecodeString(id[len(generatedToolIDPrefix):])
	if err != nil || len(raw) == 0 {
		return id
	}
	// "1|<disc>|<original>|<salt>" — the original id may itself contain
	// "|", so only the first two and the last separator are structural.
	rest, ok := bytes.CutPrefix(raw, []byte("1|"))
	if !ok {
		return id
	}
	last := bytes.LastIndexByte(rest, '|')
	if last <= 0 || last == len(rest)-1 {
		return id
	}
	middle := rest[:last] // "<disc>|<original>"
	i := bytes.IndexByte(middle, '|')
	if i < 0 || i+1 >= len(middle) {
		return id
	}
	return string(middle[i+1:])
}

// DecodeClaudeToolCallIDs rewrites gateway-minted tool-call ids in a Claude
// request body back to the upstream originals (assistant tool_use.id and user
// tool_result.tool_use_id). Native ids pass through unchanged
// (DecodeToolCallID is a no-op on them), so applying it unconditionally is
// safe. Tool names live in the name namespace, not the id one, and are left
// untouched (tool_use.name, tool_choice.function.name).
func DecodeClaudeToolCallIDs(body []byte) []byte {
	msgs := gjson.GetBytes(body, "messages")
	if !msgs.IsArray() {
		return body
	}
	out := body
	var failed bool
	decode := func(path, id string) bool {
		if restored := DecodeToolCallID(id); restored != id {
			next, err := sjson.SetBytes(out, path, restored)
			if err != nil {
				failed = true
				return false
			}
			out = next
		}
		return true
	}
	msgs.ForEach(func(mi, msg gjson.Result) bool {
		msg.Get("content").ForEach(func(ci, block gjson.Result) bool {
			base := "messages." + mi.String() + ".content." + ci.String()
			switch block.Get("type").String() {
			case "tool_use":
				return decode(base+".id", block.Get("id").String())
			case "tool_result":
				return decode(base+".tool_use_id", block.Get("tool_use_id").String())
			}
			return true
		})
		return !failed
	})
	if failed {
		return body
	}
	return out
}

// DecodeOpenAIToolCallIDs rewrites gateway-minted tool-call ids in an OpenAI
// request body back to the upstream originals (assistant tool_calls[].id and
// tool role message tool_call_id). Native ids pass through unchanged.
func DecodeOpenAIToolCallIDs(body []byte) []byte {
	msgs := gjson.GetBytes(body, "messages")
	if !msgs.IsArray() {
		return body
	}
	out := body
	var failed bool
	decode := func(path, id string) bool {
		if restored := DecodeToolCallID(id); restored != id {
			next, err := sjson.SetBytes(out, path, restored)
			if err != nil {
				failed = true
				return false
			}
			out = next
		}
		return true
	}
	msgs.ForEach(func(mi, msg gjson.Result) bool {
		base := "messages." + mi.String()
		if msg.Get("role").String() == "tool" {
			decode(base+".tool_call_id", msg.Get("tool_call_id").String())
		}
		tcs := msg.Get("tool_calls")
		if tcs.IsArray() {
			tcs.ForEach(func(ti, tc gjson.Result) bool {
				return decode(base+".tool_calls."+ti.String()+".id", tc.Get("id").String())
			})
		}
		return !failed
	})
	if failed {
		return body
	}
	return out
}

// toolCallIDs is the minimal shape needed to find tool-call ids in an OpenAI
// chat-completions body or stream chunk (non-streaming "message" and streaming
// "delta").
type toolCallIDs struct {
	Choices []struct {
		Delta struct {
			ToolCalls []toolCallRef `json:"tool_calls"`
		} `json:"delta"`
		Message struct {
			ToolCalls []toolCallRef `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
}

// toolCallRef is one tool_call entry: the id to rewrite plus the call index the
// upstream assigned. Streaming chunks always carry "index" (it is how the
// client reassembles a call across frames); non-streaming message entries
// usually omit it, and then the id alone is the key.
type toolCallRef struct {
	ID    string `json:"id"`
	Index *int   `json:"index"`
}

// RewritePayload rewrites the tool-call ids in one OpenAI JSON payload (a whole
// non-streaming body, or one SSE data frame) and returns it unchanged when
// there is nothing to do. Only the id values are substituted, so every other
// byte of the frame — reasoning fields, number formatting, key order — stays
// exactly as the upstream sent it.
//
// Edits are located in the original payload and applied in one pass. Rewriting
// the buffer in place would move the later occurrences out from under the
// search, so a payload listing the same id twice could only ever have its first
// call rewritten.
func (r *ToolCallIDRewriter) RewritePayload(payload []byte) []byte {
	if r == nil {
		return payload
	}
	// Fast path and anchor in one scan: every tool-call id field sits after
	// the first "tool_calls" key. Anchoring the search there keeps an
	// unrelated sibling "id" (a chunk or message id that happens to equal a
	// tool-call id) out of the occurrence count.
	anchor := bytes.Index(payload, []byte(`"tool_calls"`))
	if anchor < 0 {
		return payload
	}
	var body toolCallIDs
	if err := json.Unmarshal(payload, &body); err != nil {
		return payload
	}
	var refs []toolCallRef
	for _, choice := range body.Choices {
		refs = append(refs, choice.Delta.ToolCalls...)
		refs = append(refs, choice.Message.ToolCalls...)
	}

	type edit struct {
		start, end int
		generated  string
	}
	edits := make([]edit, 0, len(refs))
	// occurrence counts refs sharing an id; the n-th such ref is the n-th
	// occurrence of that id in the payload, because both follow call order.
	occurrence := make(map[string]int)
	for _, tc := range refs {
		n := occurrence[tc.ID]
		occurrence[tc.ID] = n + 1
		if tc.ID == "" || bytes.HasPrefix([]byte(tc.ID), []byte(generatedToolIDPrefix)) {
			continue
		}
		key := fmt.Sprintf("#%d\x00%s", n, tc.ID)
		if tc.Index != nil {
			key = fmt.Sprintf("%d\x00%s", *tc.Index, tc.ID)
		}
		generated := r.rewriteKey(key, tc.ID)
		fieldStart, fieldEnd, prefix, ok := nthIDField(payload[anchor:], tc.ID, n)
		if !ok {
			// The JSON decoder read this id but its bytes are not the plain
			// `"id":"<value>"` form (escaped characters, say). Leaving it alone
			// beats corrupting the frame.
			continue
		}
		edits = append(edits, edit{
			start:     anchor + fieldStart + prefix,
			end:       anchor + fieldEnd - 1, // drop the closing quote
			generated: generated,
		})
	}
	if len(edits) == 0 {
		return payload
	}
	out := make([]byte, 0, len(payload)+16*len(edits))
	prev := 0
	for _, e := range edits {
		if e.start < prev {
			continue // overlapping match: keep the edit already applied
		}
		out = append(out, payload[prev:e.start]...)
		out = append(out, e.generated...)
		prev = e.end
	}
	return append(out, payload[prev:]...)
}

// nthIDField locates the n-th (0-based) `"id":"value"` field in b, accepting the
// compact and the spaced separator. It returns the field's byte range and the
// separator length, or ok=false when the payload has fewer occurrences.
func nthIDField(b []byte, value string, n int) (start, end, prefix int, ok bool) {
	patterns := [][]byte{[]byte(`"id":"` + value + `"`), []byte(`"id": "` + value + `"`)}
	pos := 0
	for k := 0; ; k++ {
		best := -1
		bestLen := 0
		for _, pat := range patterns {
			i := bytes.Index(b[pos:], pat)
			if i >= 0 && (best < 0 || i < best) {
				best, bestLen = i, len(pat)
			}
		}
		if best < 0 {
			return 0, 0, 0, false
		}
		if k == n {
			return pos + best, pos + best + bestLen, bestLen - len(value) - 1, true
		}
		pos += best + bestLen
	}
}
