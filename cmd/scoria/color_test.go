package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/JoyousJohn/scoria/internal/rules"
)

func TestColorizerDisabledIsPlain(t *testing.T) {
	disabled := &colorizer{}
	cases := []struct {
		name string
		got  string
	}{
		{"heading", disabled.heading("x")},
		{"muted", disabled.muted("x")},
		{"accent", disabled.accent("x")},
		{"warning", disabled.warning("x")},
		{"failure", disabled.failure("x")},
		{"success", disabled.success("x")},
	}
	for _, tc := range cases {
		if tc.got != "x" {
			t.Fatalf("%s = %q, want plain x", tc.name, tc.got)
		}
	}
}

func TestNilColorizerIsPlain(t *testing.T) {
	var c *colorizer
	if got := c.heading("x"); got != "x" {
		t.Fatalf("nil heading = %q", got)
	}
	if got := c.success("x"); got != "x" {
		t.Fatalf("nil success = %q", got)
	}
}

func TestColorizerEnabledEmitsSGR(t *testing.T) {
	c := &colorizer{enabled: true}
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"heading", c.heading("x"), "\x1b[1mx\x1b[0m"},
		{"muted", c.muted("x"), "\x1b[2mx\x1b[0m"},
		{"accent", c.accent("x"), "\x1b[36mx\x1b[0m"},
		{"warning", c.warning("x"), "\x1b[33mx\x1b[0m"},
		{"failure", c.failure("x"), "\x1b[31mx\x1b[0m"},
		{"success", c.success("x"), "\x1b[32mx\x1b[0m"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Fatalf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestColorDisabledByEnv(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "")
	if colorDisabledByEnv() {
		t.Fatal("color should be allowed by default")
	}

	t.Setenv("NO_COLOR", "1")
	if !colorDisabledByEnv() {
		t.Fatal("NO_COLOR should disable color")
	}

	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if !colorDisabledByEnv() {
		t.Fatal("TERM=dumb should disable color")
	}
}

func TestColoredSkipCounts(t *testing.T) {
	c := &colorizer{enabled: true}
	if got, want := coloredCount(c, 0), "\x1b[2m0\x1b[0m"; got != want {
		t.Fatalf("zero count = %q, want %q", got, want)
	}
	if got, want := coloredCount(c, 12), "\x1b[33m12\x1b[0m"; got != want {
		t.Fatalf("nonzero count = %q, want %q", got, want)
	}
	if got, want := coloredBytes(c, 0), "\x1b[2m0 B\x1b[0m"; got != want {
		t.Fatalf("zero bytes = %q, want %q", got, want)
	}
	if got, want := coloredBytes(c, 2<<20), "\x1b[33m2.00 MiB\x1b[0m"; got != want {
		t.Fatalf("nonzero bytes = %q, want %q", got, want)
	}
}

func TestRecommendationsDimConfidenceAndAvoidSuccessColor(t *testing.T) {
	var buf bytes.Buffer
	recs := []rules.Recommendation{{
		ID:         "c1",
		Title:      "Old file",
		Confidence: rules.High,
		Items:      1,
		Bytes:      1024,
		Detail:     "detail",
	}}
	printRecommendations(&buf, &colorizer{enabled: true}, recs, false)
	out := buf.String()
	if !strings.Contains(out, "\x1b[2mhigh\x1b[0m") {
		t.Fatalf("confidence should be muted: %q", out)
	}
	if strings.Contains(out, "\x1b[32m") {
		t.Fatalf("recommendations must not use success green: %q", out)
	}
}
