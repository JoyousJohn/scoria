package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/JoyousJohn/scoria/internal/digest"
)

func sampleDigest() *digest.Digest {
	at := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	return &digest.Digest{
		Version:     digest.Version,
		GeneratedAt: at,
		Root:        `C:\Users\Tester`,
		Scan: digest.Scan{
			Workers: 16, TopN: 20, CountLinks: true, GoVersion: "go1.27.3",
			ElapsedMS: 1234, EntriesPerSecond: 98765, Sort: "priority",
		},
		Totals: digest.Totals{
			Entries: 10, UniqueFiles: 9, LogicalBytes: 4096, UniqueBytes: 4000,
			Files: 10, Directories: 3, EmptyFiles: 1, HardlinkExtra: 1,
		},
		Extensions:  []digest.Extension{{Ext: ".txt", Files: 4, Bytes: 100}},
		Largest:     []digest.File{{Path: `a\big.bin`, Size: 2048, ModTime: at}},
		Stalest:     []digest.File{{Path: `b\old.txt`, Size: 1, ModTime: at.Add(-48 * time.Hour)}},
		Directories: []digest.Directory{{Path: "a", Files: 2, Bytes: 2048}},
		Excluded: []digest.Exclusion{{
			Rule: "*.kdbx", Kind: "extension", Sensitive: true, Files: 2, Bytes: 512,
		}},
		Recommendations: []digest.Recommendation{{
			ID: "c1", Rule: "junk-dir", Title: "Generated directory: node_modules",
			Detail: "Looks generated.", Confidence: "medium", Priority: 80,
			Items: 10, Bytes: 1024, Examples: []string{`app\node_modules`},
		}},
		DuplicateCheck: &digest.DuplicateCheck{
			Candidates: 3, Hashed: 2, BytesRead: 4096, ReadErrors: 1, SkippedProtected: 2, SkippedHardlinks: 1,
		},
		Skipped: digest.Skipped{
			ReparsePoints: 2, ReparsePointFiles: 1, ReparsePointDirs: 1,
			PermissionDeniedDirs: 3, FileAccessDenied: 4, FileOpenErrors: 5,
			CloudPlaceholders: 6, CloudPlaceholderBytes: 700,
			LongPathNames: 1, OtherErrors: 2,
		},
	}
}

func TestRenderIncludesReportSections(t *testing.T) {
	var out bytes.Buffer
	if err := Render(&out, sampleDigest()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := out.String()
	for _, want := range []string{
		"<!doctype html>",
		"Storage review",
		"Generated directory: node_modules",
		`data-sort="size"`,
		"Duplicate verification",
		"Protected paths",
		"Nothing was deleted, moved, or renamed.",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(html, "https://") || strings.Contains(html, "http://") {
		t.Fatal("report must not reference external resources")
	}
}

func TestRenderEscapesUserControlledPaths(t *testing.T) {
	doc := sampleDigest()
	doc.Root = `C:\<script>alert(1)</script>`
	doc.Largest = []digest.File{{Path: `x<script>alert(2)</script>`, Size: 1}}
	var out bytes.Buffer
	if err := Render(&out, doc); err != nil {
		t.Fatalf("Render: %v", err)
	}
	html := out.String()
	if strings.Contains(html, "x<script>alert(2)</script>") {
		t.Fatal("path was not HTML-escaped")
	}
	if !strings.Contains(html, "x&lt;script&gt;alert(2)&lt;/script&gt;") {
		t.Fatal("escaped path missing")
	}
}
