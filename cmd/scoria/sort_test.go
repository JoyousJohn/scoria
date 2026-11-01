package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/JoyousJohn/scoria/internal/rules"
)

func TestSortRecommendations(t *testing.T) {
	recs := []rules.Recommendation{
		{ID: "c1", Rule: "large-file", Title: "large", Priority: rules.PriorityLargeFile, Bytes: 500},
		{ID: "c2", Rule: "junk-dir", Title: "junk", Priority: rules.PriorityJunkDir, Bytes: 100},
		{ID: "c3", Rule: "old-file", Title: "old", Priority: rules.PriorityOldFile, Bytes: 900},
	}

	sortRecommendations(recs, "priority")
	if recs[0].ID != "c2" || recs[1].ID != "c3" || recs[2].ID != "c1" {
		t.Fatalf("priority order = %q, %q, %q", recs[0].ID, recs[1].ID, recs[2].ID)
	}

	sortRecommendations(recs, "size")
	if recs[0].ID != "c3" || recs[1].ID != "c1" || recs[2].ID != "c2" {
		t.Fatalf("size order = %q, %q, %q", recs[0].ID, recs[1].ID, recs[2].ID)
	}
}

func TestValidSortMode(t *testing.T) {
	for _, mode := range []string{"priority", "size", "SIZE"} {
		if !validSortMode(mode) {
			t.Fatalf("%q should be valid", mode)
		}
	}
	for _, mode := range []string{"", "biggest"} {
		if validSortMode(mode) {
			t.Fatalf("%q should be invalid", mode)
		}
	}
}

func TestRunSortMenuReprintsBySize(t *testing.T) {
	recs := []rules.Recommendation{
		{ID: "c1", Rule: "large-file", Title: "large", Priority: rules.PriorityLargeFile, Bytes: 500},
		{ID: "c2", Rule: "junk-dir", Title: "junk", Priority: rules.PriorityJunkDir, Bytes: 100},
	}
	var out, prompts bytes.Buffer
	r := bufio.NewReader(strings.NewReader("s\nq\n"))
	runSortMenu(r, &out, &prompts, nil, nil, recs, false, "priority")
	if !strings.Contains(out.String(), "sorted by size") {
		t.Fatalf("missing size sort output: %q", out.String())
	}
	if recs[0].ID != "c1" {
		t.Fatalf("recommendations not sorted by size: %#v", recs)
	}
	if !strings.Contains(prompts.String(), "current: priority") {
		t.Fatalf("missing prompt: %q", prompts.String())
	}
}
