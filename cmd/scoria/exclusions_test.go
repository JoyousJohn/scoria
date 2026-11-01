package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JoyousJohn/scoria/internal/exclude"
)

func TestParseExclusionFile(t *testing.T) {
	input := "# comment\n\n" +
		"dir relative\n" +
		"dir \"C:\\Path With Spaces\"\n" +
		"glob *.bak\n" +
		"ext .tmp\n" +
		"name Thumbs.db\n"
	rules, err := parseExclusionFile(strings.NewReader(input), `C:\base`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 5 {
		t.Fatalf("rules = %#v", rules)
	}
	if rules[0].Kind != exclude.Subtree || rules[0].Pattern != filepath.Join(`C:\base`, "relative") {
		t.Fatalf("relative dir = %#v", rules[0])
	}
	if rules[1].Pattern != `C:\Path With Spaces` {
		t.Fatalf("quoted dir = %#v", rules[1])
	}
	if rules[2].Kind != exclude.Glob || rules[2].Pattern != "*.bak" {
		t.Fatalf("glob = %#v", rules[2])
	}
	if rules[3].Kind != exclude.Extension || rules[3].Pattern != ".tmp" {
		t.Fatalf("ext = %#v", rules[3])
	}
	if rules[4].Kind != exclude.Name || rules[4].Pattern != "Thumbs.db" {
		t.Fatalf("name = %#v", rules[4])
	}
}

func TestParseExclusionFileRejectsUnknownDirective(t *testing.T) {
	if _, err := parseExclusionFile(strings.NewReader("wat value\n"), `C:\base`); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildExclusionRulesAddsCustomRulesToPreset(t *testing.T) {
	all, custom, source, configRules, err := buildExclusionRules(exclusionFlags{
		dirs:     stringList{`C:\Temp`},
		globs:    stringList{"*.bak"},
		exts:     stringList{".log"},
		names:    stringList{"Thumbs.db"},
		noConfig: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(custom) != 4 {
		t.Fatalf("custom = %#v", custom)
	}
	if len(all) != len(exclude.DefaultRules())+4 {
		t.Fatalf("all = %d", len(all))
	}
	if source != "" || configRules != 0 {
		t.Fatalf("unexpected config: %q %d", source, configRules)
	}
}

func TestBuildExclusionRulesLoadsDefaultConfig(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("APPDATA", configRoot)
	configDir := filepath.Join(configRoot, "Scoria")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, "exclusions.txt")
	writeExclusionTestFile(t, configPath, "ext .bak\n")

	all, custom, source, configRules, err := buildExclusionRules(exclusionFlags{})
	if err != nil {
		t.Fatal(err)
	}
	if source != configPath || configRules != 1 {
		t.Fatalf("config = %q %d", source, configRules)
	}
	if len(custom) != 1 || len(all) != len(exclude.DefaultRules())+1 {
		t.Fatalf("rules = %d custom=%d", len(all), len(custom))
	}
}

func TestBuildExclusionRulesExplicitConfigReplacesDefault(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("APPDATA", configRoot)
	configDir := filepath.Join(configRoot, "Scoria")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExclusionTestFile(t, filepath.Join(configDir, "exclusions.txt"), "ext .bak\n")
	explicit := filepath.Join(t.TempDir(), "explicit.txt")
	writeExclusionTestFile(t, explicit, "ext .log\n")

	_, custom, source, configRules, err := buildExclusionRules(exclusionFlags{config: explicit})
	if err != nil {
		t.Fatal(err)
	}
	if source != explicit || configRules != 1 {
		t.Fatalf("config = %q %d", source, configRules)
	}
	if len(custom) != 1 || custom[0].Pattern != ".log" {
		t.Fatalf("custom = %#v", custom)
	}
}

func TestBuildExclusionRulesNoConfigSkipsDefault(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("APPDATA", configRoot)
	configDir := filepath.Join(configRoot, "Scoria")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExclusionTestFile(t, filepath.Join(configDir, "exclusions.txt"), "ext .bak\n")

	_, custom, source, configRules, err := buildExclusionRules(exclusionFlags{noConfig: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(custom) != 0 || source != "" || configRules != 0 {
		t.Fatalf("custom=%d source=%q rules=%d", len(custom), source, configRules)
	}
}

func writeExclusionTestFile(t *testing.T, path, content string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(content); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
