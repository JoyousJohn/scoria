package digest

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func sample() *Digest {
	at := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	return &Digest{
		Version:     Version,
		GeneratedAt: at,
		Root:        `C:\Users\Tester`,
		Scan: Scan{
			Workers:          16,
			TopN:             20,
			CountLinks:       true,
			GoVersion:        "go1.27.3",
			ElapsedMS:        1234,
			EntriesPerSecond: 98765.5,
			Sort:             "priority",
		},
		Totals: Totals{
			Entries: 10, UniqueFiles: 9, LogicalBytes: 4096, UniqueBytes: 4000,
			Files: 10, Directories: 3, EmptyFiles: 1, HardlinkExtra: 1,
		},
		Extensions:  []Extension{{Ext: ".txt", Files: 4, Bytes: 100}},
		Largest:     []File{{Path: `a\big.bin`, Size: 2048, ModTime: at}},
		Stalest:     []File{{Path: `b\old.txt`, Size: 1, ModTime: at.Add(-48 * time.Hour)}},
		Directories: []Directory{{Path: "a", Files: 2, Bytes: 2048}},
		SizeCounts:  []SizeCount{{Size: 1, Count: 3}, {Size: 2048, Count: 1}},
		Excluded: []Exclusion{{
			Rule: "*.kdbx", Kind: "extension", Sensitive: true, Files: 2, Bytes: 512,
		}},
		Recommendations: []Recommendation{{
			ID: "c1", Rule: "junk-dir", Title: "Generated directory: node_modules",
			Detail: "Looks generated.", Confidence: "medium", Priority: 80,
			Items: 10, Bytes: 1024, Examples: []string{`app\node_modules`},
		}},
		Analysis: &Analysis{
			Analyzer: "openrouter", Model: "openai/test",
			Findings: []AnalysisFinding{{ID: "c1", Title: "Generated directory: node_modules", Rank: 1, Explanation: "Verify before acting."}},
		},
		DuplicateCheck: &DuplicateCheck{
			Candidates: 3, Hashed: 2, BytesRead: 4096, ReadErrors: 1, SkippedProtected: 2, SkippedHardlinks: 1,
		},
		Skipped: Skipped{
			ReparsePoints: 2, ReparsePointFiles: 1, ReparsePointDirs: 1,
			PermissionDeniedDirs: 3, FileAccessDenied: 4, FileOpenErrors: 5,
			CloudPlaceholders: 6, CloudPlaceholderBytes: 700,
			LongPathNames: 1, OtherErrors: 2,
		},
	}
}

func TestDigestJSONRoundTrip(t *testing.T) {
	in := sample()
	encoded, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Digest
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(*in, out) {
		t.Fatalf("round trip mismatch:\n in=%#v\nout=%#v", *in, out)
	}
	if out.Version != Version {
		t.Fatalf("version = %d", out.Version)
	}
	if out.Root != in.Root {
		t.Fatalf("root = %q", out.Root)
	}
}
