package nvidia

import "strings"

type reasoningKind uint8

const (
	reasoningEffort reasoningKind = iota
	reasoningToggle
	reasoningEffortAndToggle
	reasoningMiniMax
)

type reasoningProfile struct {
	kind         reasoningKind
	levels       []string
	defaultLevel string
}

// reasoningProfiles is keyed by registry model ids. Models removed from the
// anonymous catalog in 2026-08 (glm-5.2, gpt-oss-*, qwen3.5-397b, ...) were
// dropped together with their profiles; refresh this map when the catalog
// changes (TestReasoningProfilesReferenceRegisteredModels enforces it).
var reasoningProfiles = map[string]reasoningProfile{
	"deepseek-ai/deepseek-v4-flash-0731": {kind: reasoningEffort, levels: []string{"none", "high", "max"}, defaultLevel: "high"},
	"deepseek-ai/deepseek-v4-pro-0813":   {kind: reasoningEffort, levels: []string{"none", "high", "max"}, defaultLevel: "high"},
	"nvidia/nemotron-3-ultra-550b-a55b":  {kind: reasoningEffort, levels: []string{"none", "medium", "high"}, defaultLevel: "high"},
	"google/diffusiongemma-26b-a4b-it":   {kind: reasoningToggle},
	"minimaxai/minimax-m3":               {kind: reasoningMiniMax},
}

var effortRanks = map[string]int{
	"none":    0,
	"minimal": 1,
	"low":     2,
	"medium":  3,
	"high":    4,
	"xhigh":   5,
	"max":     6,
}

func normalizeThinking(raw map[string]any) {
	model, _ := raw["model"].(string)
	profile, supported := reasoningProfiles[model]
	kw, hadKwargs := raw["chat_template_kwargs"].(map[string]any)
	if kw == nil {
		kw = map[string]any{}
	}

	effort, hasEffort := requestedEffort(raw, kw, profile.defaultLevel)
	enabled, hasEnabled := requestedThinkingEnabled(raw, kw)
	clearThinking, hasClearThinking := requestedClearThinking(raw, kw)

	delete(raw, "thinking")
	delete(raw, "enable_thinking")
	delete(raw, "clear_thinking")
	delete(raw, "reasoning_effort")

	if supported {
		switch profile.kind {
		case reasoningEffort:
			delete(kw, "enable_thinking")
			if hasEffort {
				kw["reasoning_effort"] = mapEffort(effort, profile)
			} else if hasEnabled {
				kw["reasoning_effort"] = mapEnabled(enabled, profile)
			}
		case reasoningToggle:
			delete(kw, "reasoning_effort")
			if hasEnabled {
				kw["enable_thinking"] = enabled
			} else if hasEffort {
				kw["enable_thinking"] = effortEnablesThinking(effort)
			}
		case reasoningEffortAndToggle:
			if hasEnabled {
				kw["enable_thinking"] = enabled
			} else if hasEffort {
				kw["enable_thinking"] = effortEnablesThinking(effort)
			}
			if hasEffort && (!hasEnabled || enabled) && effortEnablesThinking(effort) {
				kw["reasoning_effort"] = mapEffort(effort, profile)
			} else {
				delete(kw, "reasoning_effort")
			}
		case reasoningMiniMax:
			delete(kw, "enable_thinking")
			delete(kw, "reasoning_effort")
			if hasEffort {
				kw["thinking_mode"] = miniMaxThinkingMode(effort)
			} else if hasEnabled {
				kw["thinking_mode"] = "disabled"
				if enabled {
					kw["thinking_mode"] = "enabled"
				}
			}
		}
		if hasClearThinking && (profile.kind == reasoningToggle || profile.kind == reasoningEffortAndToggle) {
			kw["clear_thinking"] = clearThinking
		}
	}

	if len(kw) > 0 || hadKwargs {
		raw["chat_template_kwargs"] = kw
	} else {
		delete(raw, "chat_template_kwargs")
	}
}

func requestedEffort(raw, kw map[string]any, defaultLevel string) (string, bool) {
	for _, value := range []any{kw["reasoning_effort"], raw["reasoning_effort"]} {
		if effort, ok := value.(string); ok && strings.TrimSpace(effort) != "" {
			return normalizeEffort(effort, defaultLevel), true
		}
	}
	if thinking, ok := raw["thinking"].(map[string]any); ok {
		if effort, ok := thinking["reasoning_effort"].(string); ok && strings.TrimSpace(effort) != "" {
			return normalizeEffort(effort, defaultLevel), true
		}
	}
	return "", false
}

func requestedThinkingEnabled(raw, kw map[string]any) (bool, bool) {
	if enabled, ok := kw["enable_thinking"].(bool); ok {
		return enabled, true
	}
	if thinking, ok := raw["thinking"].(map[string]any); ok {
		if typ, ok := thinking["type"].(string); ok {
			switch strings.ToLower(strings.TrimSpace(typ)) {
			case "enabled", "enable", "on":
				return true, true
			case "disabled", "disable", "off":
				return false, true
			}
		}
	}
	enabled, ok := raw["enable_thinking"].(bool)
	return enabled, ok
}

func requestedClearThinking(raw, kw map[string]any) (any, bool) {
	if value, ok := kw["clear_thinking"]; ok {
		return value, true
	}
	if thinking, ok := raw["thinking"].(map[string]any); ok {
		if value, ok := thinking["clear_thinking"]; ok {
			return value, true
		}
	}
	value, ok := raw["clear_thinking"]
	return value, ok
}

func normalizeEffort(effort, defaultLevel string) string {
	normalized := strings.ToLower(strings.TrimSpace(effort))
	if _, ok := effortRanks[normalized]; ok {
		return normalized
	}
	return defaultLevel
}

func mapEffort(effort string, profile reasoningProfile) string {
	requestedRank := effortRanks[effort]
	for _, level := range profile.levels {
		if effortRanks[level] >= requestedRank {
			return level
		}
	}
	return profile.levels[len(profile.levels)-1]
}

func mapEnabled(enabled bool, profile reasoningProfile) string {
	if !enabled {
		return mapEffort("none", profile)
	}
	return profile.defaultLevel
}

func effortEnablesThinking(effort string) bool {
	return effort != "none"
}

func miniMaxThinkingMode(effort string) string {
	switch effort {
	case "none":
		return "disabled"
	case "minimal", "low", "medium":
		return "adaptive"
	default:
		return "enabled"
	}
}
