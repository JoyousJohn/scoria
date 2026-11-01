package main

import (
	"strings"
	"testing"

	"github.com/JoyousJohn/scoria/internal/analyzer/openrouter"
)

func TestProviderPresetsAreUniqueAndHTTPS(t *testing.T) {
	seen := make(map[string]bool, len(providerPresets))
	for _, preset := range providerPresets {
		if preset.id == "" || preset.name == "" || preset.baseURL == "" {
			t.Fatalf("incomplete preset: %#v", preset)
		}
		if seen[preset.id] {
			t.Fatalf("duplicate preset id %q", preset.id)
		}
		seen[preset.id] = true
		if !strings.HasPrefix(preset.baseURL, "https://") {
			t.Fatalf("preset %q is not HTTPS: %s", preset.id, preset.baseURL)
		}
		if err := openrouter.ValidateBaseURL(preset.baseURL); err != nil {
			t.Fatalf("preset %q: %v", preset.id, err)
		}
	}
	if providerPresets[0].baseURL != openrouter.DefaultBaseURL {
		t.Fatalf("default preset = %q, want %q", providerPresets[0].baseURL, openrouter.DefaultBaseURL)
	}
}

func TestResolveProviderBase(t *testing.T) {
	base, err := resolveProviderBase("openai", "")
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://api.openai.com/v1" {
		t.Fatalf("base = %q", base)
	}

	base, err = resolveProviderBase("openai", "https://custom.example/v1/")
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://custom.example/v1/" {
		t.Fatalf("explicit base should win: %q", base)
	}

	if _, err := resolveProviderBase("nope", ""); err == nil {
		t.Fatal("unknown provider should fail")
	}

	base, err = resolveProviderBase("", "")
	if err != nil || base != "" {
		t.Fatalf("base = %q, err = %v; want empty default", base, err)
	}
}

func TestProviderIndexForBase(t *testing.T) {
	if got := providerIndexForBase(""); got != 1 {
		t.Fatalf("default index = %d, want 1", got)
	}
	if got := providerIndexForBase("https://api.openai.com/v1/"); got != 2 {
		t.Fatalf("openai index = %d, want 2", got)
	}
	if got := providerIndexForBase("http://127.0.0.1:11434/v1"); got != len(providerPresets)+1 {
		t.Fatalf("custom index = %d", got)
	}
}

func TestEndpointLabel(t *testing.T) {
	if got := endpointLabel(""); got != "openrouter.ai" {
		t.Fatalf("label = %q", got)
	}
	if got := endpointLabel("https://api.example.com/v1"); got != "api.example.com" {
		t.Fatalf("label = %q", got)
	}
}
