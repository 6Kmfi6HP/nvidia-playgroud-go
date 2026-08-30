// Package hcaptchapow implements the pure-Go proof-of-work core used by the
// hCaptcha solver, with no external dependencies: PoW JWT parsing, hashcash
// stamp minting, CRC-32 rand computation and XXH64 hashing.
package hcaptchapow

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Pow is the decoded payload of an hCaptcha PoW JWT (challenge type "w").
type Pow struct {
	FingerprintType float64 `json:"f,omitempty"` // fingerprint type
	Difficulty      float64 `json:"s,omitempty"` // proof-of-work difficulty
	Type            string  `json:"t,omitempty"` // challenge type ("w")
	PowData         string  `json:"d,omitempty"` // pow data / resource
	Location        string  `json:"l,omitempty"` // asset location
	Signature       string  `json:"i,omitempty"` // signature
	Timestamp       float64 `json:"e,omitempty"` // issued-at timestamp
	N               string  `json:"n,omitempty"` // solver type ("hsw")
	Timeout         float64 `json:"c,omitempty"` // timeout, ms
}

// ParsePow decodes the payload of an hCaptcha PoW JWT
// (header.payload.signature with a base64url payload) and validates its
// required claims: non-empty strings t, d, l, i, n and non-zero s, e, c.
// The signature is not verified.
func ParsePow(token string) (*Pow, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("hcaptchapow: pow jwt must have three dot-separated parts")
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("hcaptchapow: decode pow jwt payload: %w", err)
	}
	var p Pow
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("hcaptchapow: decode pow jwt payload json: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// decodeSegment base64url-decodes one JWT segment. Raw encoding is the JWT
// standard; padded encoding is accepted as a fallback.
func decodeSegment(seg string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(seg)
}

func (p *Pow) validate() error {
	switch {
	case p.Type == "":
		return errors.New("hcaptchapow: pow jwt missing claim t")
	case p.PowData == "":
		return errors.New("hcaptchapow: pow jwt missing claim d")
	case p.Location == "":
		return errors.New("hcaptchapow: pow jwt missing claim l")
	case p.Signature == "":
		return errors.New("hcaptchapow: pow jwt missing claim i")
	case p.N == "":
		return errors.New("hcaptchapow: pow jwt missing claim n")
	case p.Difficulty == 0:
		return errors.New("hcaptchapow: pow jwt missing or zero claim s")
	case p.Timestamp == 0:
		return errors.New("hcaptchapow: pow jwt missing or zero claim e")
	case p.Timeout == 0:
		return errors.New("hcaptchapow: pow jwt missing or zero claim c")
	}
	return nil
}
