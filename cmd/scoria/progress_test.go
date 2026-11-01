package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/JoyousJohn/scoria/internal/scan"
)

func TestProgressLineDrawsAndClears(t *testing.T) {
	var out bytes.Buffer
	p := &progressLine{out: &out, enabled: true}

	p.update(scan.Progress{Entries: 1234, Elapsed: 2 * time.Second, EntriesPerSecond: 617})
	if !strings.Contains(out.String(), "scanned 1,234 entries") {
		t.Fatalf("missing entry count: %q", out.String())
	}
	if !strings.Contains(out.String(), "617/s") {
		t.Fatalf("missing rate: %q", out.String())
	}

	width := p.width
	p.finish()
	if p.width != 0 {
		t.Fatalf("width = %d", p.width)
	}
	if !strings.HasSuffix(out.String(), "\r") {
		t.Fatalf("missing carriage return: %q", out.String())
	}
	if !strings.Contains(out.String(), strings.Repeat(" ", width)) {
		t.Fatal("did not clear with spaces")
	}
}

func TestProgressLineDisabledWritesNothing(t *testing.T) {
	var out bytes.Buffer
	p := &progressLine{out: &out}
	p.update(scan.Progress{Entries: 1, Elapsed: time.Second, EntriesPerSecond: 1})
	p.finish()
	if out.Len() != 0 {
		t.Fatalf("output = %q", out.String())
	}
}

func TestValidProgressMode(t *testing.T) {
	for _, mode := range []string{"auto", "always", "never", "AUTO"} {
		if !validProgressMode(mode) {
			t.Fatalf("%q should be valid", mode)
		}
	}
	for _, mode := range []string{"", "sometimes"} {
		if validProgressMode(mode) {
			t.Fatalf("%q should be invalid", mode)
		}
	}
}
