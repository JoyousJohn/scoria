package main

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/JoyousJohn/scoria/internal/analyzer/openrouter"
)

type providerPreset struct {
	id      string
	name    string
	baseURL string
}

var providerPresets = []providerPreset{
	{"openrouter", "OpenRouter", openrouter.DefaultBaseURL},
	{"openai", "OpenAI", "https://api.openai.com/v1"},
	{"gemini", "Google Gemini", "https://generativelanguage.googleapis.com/v1beta/openai"},
	{"deepseek", "DeepSeek", "https://api.deepseek.com"},
	{"together", "Together AI", "https://api.together.xyz/v1"},
	{"fireworks", "Fireworks AI", "https://api.fireworks.ai/inference/v1"},
	{"deepinfra", "DeepInfra", "https://api.deepinfra.com/v1/openai"},
	{"groq", "Groq", "https://api.groq.com/openai/v1"},
}

func lookupProvider(id string) (providerPreset, bool) {
	for _, preset := range providerPresets {
		if strings.EqualFold(preset.id, strings.TrimSpace(id)) {
			return preset, true
		}
	}
	return providerPreset{}, false
}

func providerIDs() string {
	ids := make([]string, 0, len(providerPresets))
	for _, preset := range providerPresets {
		ids = append(ids, preset.id)
	}
	return strings.Join(ids, ", ")
}

func resolveProviderBase(id, baseURL string) (string, error) {
	if base := strings.TrimSpace(baseURL); base != "" {
		return base, nil
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return "", nil
	}
	preset, ok := lookupProvider(id)
	if !ok {
		return "", fmt.Errorf("unknown -provider %q (want %s, or -provider list)", id, providerIDs())
	}
	return preset.baseURL, nil
}

func providerIndexForBase(base string) int {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return 1
	}
	for i, preset := range providerPresets {
		if strings.EqualFold(base, strings.TrimRight(preset.baseURL, "/")) {
			return i + 1
		}
	}
	return len(providerPresets) + 1
}

func endpointLabel(base string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return "openrouter.ai"
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" {
		return base
	}
	return parsed.Host
}
