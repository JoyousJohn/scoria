package analyzer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/JoyousJohn/scoria/internal/digest"
)

func sampleDigest() *digest.Digest {
	return &digest.Digest{
		Version:     digest.Version,
		GeneratedAt: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
		Root:        `C:\Users\Ada\Private`,
		Totals: digest.Totals{
			Entries: 10, UniqueFiles: 9, Files: 10, Directories: 3,
			LogicalBytes: 4096, UniqueBytes: 4000, EmptyFiles: 1, HardlinkExtra: 1,
		},
		Extensions: []digest.Extension{{Ext: ".docx", Files: 4, Bytes: 100}},
		Recommendations: []digest.Recommendation{{
			ID: "c1", Rule: "junk-dir", Title: "Generated directory: node_modules",
			Detail: "Looks generated.", Confidence: "medium", Priority: 80,
			Items: 10, Bytes: 2 << 20,
			Examples: []string{`project\node_modules`, `C:\Users\Ada\Private\project\node_modules`},
		}},
	}
}

func TestBuildPayloadOmitsPaths(t *testing.T) {
	payload := BuildPayload(sampleDigest())
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, bad := range []string{
		"Ada",
		"Private",
		`project\node_modules`,
		`C:\Users`,
		"examples",
	} {
		if strings.Contains(text, bad) {
			t.Fatalf("payload leaked %q: %s", bad, text)
		}
	}
	if payload.Version != PayloadVersion {
		t.Fatalf("version = %d", payload.Version)
	}
	if len(payload.Candidates) != 1 || payload.Candidates[0].ID != "c1" {
		t.Fatalf("candidates = %#v", payload.Candidates)
	}
	if payload.Candidates[0].SizeBucket != "1-10 MiB" {
		t.Fatalf("size bucket = %q", payload.Candidates[0].SizeBucket)
	}
	if !strings.Contains(text, "Generated directory: node_modules") {
		t.Fatal("pattern-level title missing")
	}
}

func TestRulesOnlyReturnsStableRanks(t *testing.T) {
	payload := BuildPayload(sampleDigest())
	result, err := (RulesOnly{}).Analyze(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if result.Analyzer != "rules-only" {
		t.Fatalf("analyzer = %q", result.Analyzer)
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "c1" || result.Findings[0].Rank != 1 {
		t.Fatalf("findings = %#v", result.Findings)
	}
}

func TestSizeBucket(t *testing.T) {
	cases := map[int64]string{
		0:         "0",
		1 << 19:   "<1 MiB",
		1 << 20:   "1-10 MiB",
		10 << 20:  "10-100 MiB",
		100 << 20: "100 MiB-1 GiB",
		1 << 30:   "1-10 GiB",
		10 << 30:  ">=10 GiB",
	}
	for bytes, want := range cases {
		if got := sizeBucket(bytes); got != want {
			t.Errorf("sizeBucket(%d) = %q, want %q", bytes, got, want)
		}
	}
}

func TestDiscoveryCollectorAggregatesAncestorNames(t *testing.T) {
	c := NewDiscoveryCollector(`C:\root`)
	c.Sink(`C:\root\project\node_modules\pkg\a.js`, 100, time.Time{})
	c.Sink(`C:\root\project\node_modules\pkg\b.js`, 50, time.Time{})
	c.Sink(`C:\root\DerivedData\Build\x.bin`, 200, time.Time{})
	c.Sink(`C:\root\Windows\System32\secret.dll`, 999, time.Time{})

	names := c.Result(10)
	if len(names) == 0 {
		t.Fatal("no names")
	}
	if names[0].Name != "DerivedData" && names[0].Name != "Build" {
		t.Fatalf("top name = %#v", names[0])
	}
	for _, name := range names {
		if name.Name == "Windows" || name.Name == "System32" {
			t.Fatalf("protected path leaked into discovery: %#v", name)
		}
	}
}

func TestBuildDiscoveryPayloadOmitsPaths(t *testing.T) {
	payload := BuildDiscoveryPayload(sampleDigest(), []DirectoryName{
		{Name: "DerivedData", Files: 2, Bytes: 300},
		{Name: "node_modules", Files: 1, Bytes: 100},
	})
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "Ada") || strings.Contains(text, `C:\Users`) {
		t.Fatalf("payload leaked a path: %s", text)
	}
	if len(payload.DirectoryNames) != 1 || payload.DirectoryNames[0].Name != "DerivedData" {
		t.Fatalf("directory names = %#v", payload.DirectoryNames)
	}
}

func TestValidateDiscovery(t *testing.T) {
	payload := DiscoveryPayload{DirectoryNames: []DirectoryName{
		{Name: "DerivedData", Files: 2, Bytes: 300},
	}}
	result, err := ValidateDiscovery(payload, DiscoveryResult{Patterns: []DiscoveryFinding{{
		Kind: "dir-basename", Name: "DerivedData", Confidence: "medium", Reason: "Xcode build cache",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Patterns) != 1 || result.Patterns[0].Files != 2 || result.Patterns[0].Bytes != 300 {
		t.Fatalf("patterns = %#v", result.Patterns)
	}
	if _, err := ValidateDiscovery(payload, DiscoveryResult{Patterns: []DiscoveryFinding{{
		Kind: "dir-basename", Name: "node_modules", Confidence: "medium", Reason: "covered",
	}}}); err == nil {
		t.Fatal("expected covered-name error")
	}
	if _, err := ValidateDiscovery(payload, DiscoveryResult{Patterns: []DiscoveryFinding{{
		Kind: "dir-basename", Name: "Unknown", Confidence: "medium", Reason: "x",
	}}}); err == nil {
		t.Fatal("expected unknown-name error")
	}
}
