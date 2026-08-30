package waftoken

// Crypto-config extraction from an AWS WAF challenge.js via the embedded
// V8 (v8go). This replaces the Node.js subprocess used by the reference
// implementation so the gateway stays browser-free and node-free.

import (
	_ "embed"
	"encoding/json"
	"fmt"

	v8 "github.com/tommie/v8go"
)

//go:embed extract.js
var extractJS string

// cryptoConfig is the parsed output of extractConfig(script).
type cryptoConfig struct {
	Key           string            `json:"key"`
	Identifier    string            `json:"identifier"`
	TypeNames     map[string]string `json:"typeNames"`
	SignalVersion string            `json:"signalVersion"`
}

// extractCryptoConfig runs the pure-JS extractor over challengeScript and
// returns the AES key + identifier + challenge type names. An isolate is
// created per call (solving is rare: once per refresh interval).
func extractCryptoConfig(challengeScript string) (*cryptoConfig, error) {
	iso := v8.NewIsolate()
	defer iso.Dispose()

	ctx := v8.NewContext(iso)
	defer ctx.Close()

	// Inject the challenge script as a JS string literal, load the
	// extractor, and invoke it.
	code := "var __script = " + jsQuote(challengeScript) + ";\n" +
		extractJS + "\nJSON.stringify(extractConfig(__script));"
	val, err := ctx.RunScript(code, "waftoken_extract.js")
	if err != nil {
		return nil, fmt.Errorf("waftoken: run extractor: %w", err)
	}
	raw := val.String()

	var cfg cryptoConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("waftoken: parse extractor output: %w (raw: %.200s)", err, raw)
	}
	if cfg.Key == "" {
		return nil, fmt.Errorf("waftoken: no AES key found in challenge.js")
	}
	if cfg.Identifier == "" {
		return nil, fmt.Errorf("waftoken: no identifier found in challenge.js")
	}
	return &cfg, nil
}

// jsQuote renders s as a double-quoted JS string literal with proper
// escaping (V8 JS strings can contain \uXXXX escapes).
func jsQuote(s string) string {
	b := []byte{'"'}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b = append(b, '\\', '"')
		case c == '\\':
			b = append(b, '\\', '\\')
		case c == '\n':
			b = append(b, '\\', 'n')
		case c == '\r':
			b = append(b, '\\', 'r')
		case c == '\t':
			b = append(b, '\\', 't')
		case c < 0x20 || c >= 0x7f:
			b = append(b, fmt.Sprintf("\\u%04x", c)...)
		default:
			b = append(b, c)
		}
	}
	return string(append(b, '"'))
}
