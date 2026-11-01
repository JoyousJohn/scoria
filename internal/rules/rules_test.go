package rules

import (
	"testing"
	"time"

	"github.com/JoyousJohn/scoria/internal/aggregate"
	"github.com/JoyousJohn/scoria/internal/dupes"
	"github.com/JoyousJohn/scoria/internal/junk"
	"github.com/JoyousJohn/scoria/internal/protected"
)

func TestProtectedPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{`C:\Windows\System32\driver.sys`, true},
		{`D:\Program Files\App\app.exe`, true},
		{`C:\Users\me\pagefile.sys`, true},
		{`C:\System Volume Information\file`, true},
		{`C:\$Recycle.Bin\file`, true},
		{`C:\Recovery\file`, true},
		{`C:\Windows.old\file`, true},
		{`C:\Users\me\Projects\video.mkv`, false},
		{`D:\Projects\recovery\notes.txt`, false},
		{`\\?\C:\Windows\System32\driver.sys`, true},
	}
	for _, tc := range cases {
		if got := protected.IsPath(tc.path); got != tc.want {
			t.Errorf("protected.IsPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestAnalyzeBuildsCandidatesAndFiltersProtectedPaths(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	old := now.AddDate(-3, 0, 0)
	agg := &aggregate.Aggregate{
		Largest: []aggregate.FileEntry{
			{Path: `Windows\System32\driver.sys`, Size: 500 << 20},
			{Path: `Users\me\video.mkv`, Size: 400 << 20},
			{Path: `Users\me\small.bin`, Size: 1 << 20},
		},
		Stalest: []aggregate.FileEntry{
			{Path: `Windows\System32\old.dll`, Size: 10 << 20, ModTime: old},
			{Path: `Users\me\old.txt`, Size: 10 << 20, ModTime: old},
		},
		Junk: []aggregate.JunkEntry{
			{Kind: junk.NodeModules, Files: 100, Bytes: 200 << 20, Example: `project\node_modules`},
			{Kind: junk.Build, Files: 10, Bytes: 50 << 20, Example: `Windows\build`},
		},
		Extensions: []aggregate.ExtEntry{{Ext: ".tmp", Files: 4, Bytes: 2 << 20}},
		SizeCounts: []aggregate.SizeCount{{Size: 2 << 20, Count: 3}},
	}

	recs := Analyze(`C:\Data`, agg, Options{
		Now:               now,
		LargeFileBytes:    100 << 20,
		StaleAfter:        2 * 365 * 24 * time.Hour,
		MaxFileCandidates: 5,
	})

	if !hasExample(recs, "large-file", `Users\me\video.mkv`) {
		t.Fatal("missing large video recommendation")
	}
	if hasExample(recs, "large-file", `Windows\System32\driver.sys`) {
		t.Fatal("protected large file was recommended")
	}
	if !hasExample(recs, "old-file", `Users\me\old.txt`) {
		t.Fatal("missing old user file recommendation")
	}
	if hasExample(recs, "old-file", `Windows\System32\old.dll`) {
		t.Fatal("protected old file was recommended")
	}
	if !hasExample(recs, "junk-dir", `project\node_modules`) {
		t.Fatal("missing node_modules recommendation")
	}
	if hasExample(recs, "junk-dir", `Windows\build`) {
		t.Fatal("protected junk directory was recommended")
	}
	if !hasRule(recs, "junk-extension") {
		t.Fatal("missing temp-extension recommendation")
	}
	if !hasRule(recs, "duplicate-candidates") {
		t.Fatal("missing duplicate-candidate recommendation")
	}
	for _, r := range recs {
		for _, example := range r.Examples {
			if protected.IsPath(absolute(`C:\Data`, example)) {
				t.Fatalf("recommendation %q contains protected example %q", r.Rule, example)
			}
		}
	}
}

func TestAnalyzeUsesVerifiedDuplicateGroups(t *testing.T) {
	agg := &aggregate.Aggregate{
		SizeCounts: []aggregate.SizeCount{{Size: 2 << 20, Count: 3}},
	}
	check := &dupes.Result{
		Groups: []dupes.Group{{
			Size: 2 << 20, Count: 2, Wasted: 2 << 20,
			Paths: []string{`a.bin`, `b.bin`},
		}},
	}
	recs := Analyze(`D:\Projects`, agg, Options{
		Now:            time.Now(),
		MinGroupBytes:  1,
		DuplicateCheck: check,
	})
	if !hasRule(recs, "verified-duplicates") {
		t.Fatalf("missing verified duplicate recommendation: %#v", recs)
	}
	if hasRule(recs, "duplicate-candidates") {
		t.Fatal("size-only duplicate rule should be replaced by the verified result")
	}
}

func TestAnalyzeSuppressesPathlessRulesOnDriveRoot(t *testing.T) {
	agg := &aggregate.Aggregate{
		Extensions: []aggregate.ExtEntry{{Ext: ".tmp", Files: 1, Bytes: 2 << 20}},
		SizeCounts: []aggregate.SizeCount{{Size: 2 << 20, Count: 2}},
	}
	recs := Analyze(`C:\`, agg, Options{Now: time.Now()})
	if hasRule(recs, "junk-extension") || hasRule(recs, "duplicate-candidates") {
		t.Fatalf("pathless rules should be suppressed for a drive root: %#v", recs)
	}
}

func hasExample(recs []Recommendation, rule, example string) bool {
	for _, r := range recs {
		if r.Rule != rule {
			continue
		}
		for _, e := range r.Examples {
			if e == example {
				return true
			}
		}
	}
	return false
}

func hasRule(recs []Recommendation, rule string) bool {
	for _, r := range recs {
		if r.Rule == rule {
			return true
		}
	}
	return false
}
