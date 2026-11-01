package main

import (
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
	all, custom, err := buildExclusionRules(exclusionFlags{
		dirs:  stringList{`C:\Temp`},
		globs: stringList{"*.bak"},
		exts:  stringList{".log"},
		names: stringList{"Thumbs.db"},
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
}
