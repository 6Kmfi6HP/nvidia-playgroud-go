package nvidia

import (
	"encoding/json"
	"fmt"

	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func translateToChat(source sdktranslator.Format, model string, request []byte, stream bool) ([]byte, error) {
	switch source {
	case sdktranslator.FormatClaude:
		request = DecodeClaudeToolCallIDs(request)
	case sdktranslator.FormatOpenAI:
		request = DecodeOpenAIToolCallIDs(request)
	}

	var sourceBody map[string]json.RawMessage
	if err := json.Unmarshal(request, &sourceBody); err != nil {
		return nil, fmt.Errorf("decode source request: %w", err)
	}

	translated := sdktranslator.TranslateRequest(source, sdktranslator.FormatOpenAI, model, request, stream)
	if len(translated) == 0 {
		translated = request
	}
	var chatBody map[string]json.RawMessage
	if err := json.Unmarshal(translated, &chatBody); err != nil {
		return nil, fmt.Errorf("decode translated request: %w", err)
	}

	switch source {
	case sdktranslator.FormatOpenAIResponse:
		copyRawFields(chatBody, sourceBody, "temperature", "top_p", "user", "service_tier")
		if text, ok := sourceBody["text"]; ok {
			responseFormat, err := responsesTextFormat(text)
			if err != nil {
				return nil, err
			}
			if len(responseFormat) != 0 {
				chatBody["response_format"] = responseFormat
			}
		}
	case sdktranslator.FormatClaude:
		copyRawFields(chatBody, sourceBody, "temperature", "top_p")
	}

	return json.Marshal(chatBody)
}

func copyRawFields(destination, source map[string]json.RawMessage, fields ...string) {
	for _, field := range fields {
		if value, ok := source[field]; ok {
			destination[field] = value
		}
	}
}

func responsesTextFormat(raw json.RawMessage) (json.RawMessage, error) {
	var text struct {
		Format json.RawMessage `json:"format"`
	}
	if err := json.Unmarshal(raw, &text); err != nil {
		return nil, fmt.Errorf("decode text.format: %w", err)
	}
	if len(text.Format) == 0 || string(text.Format) == "null" {
		return nil, nil
	}

	var format struct {
		Type   string          `json:"type"`
		Name   string          `json:"name"`
		Strict bool            `json:"strict"`
		Schema json.RawMessage `json:"schema"`
	}
	if err := json.Unmarshal(text.Format, &format); err != nil {
		return nil, fmt.Errorf("decode text.format: %w", err)
	}
	if format.Type != "json_schema" {
		return text.Format, nil
	}
	return json.Marshal(struct {
		Type       string `json:"type"`
		JSONSchema struct {
			Name   string          `json:"name"`
			Strict bool            `json:"strict"`
			Schema json.RawMessage `json:"schema"`
		} `json:"json_schema"`
	}{
		Type: "json_schema",
		JSONSchema: struct {
			Name   string          `json:"name"`
			Strict bool            `json:"strict"`
			Schema json.RawMessage `json:"schema"`
		}{
			Name:   format.Name,
			Strict: format.Strict,
			Schema: format.Schema,
		},
	})
}
