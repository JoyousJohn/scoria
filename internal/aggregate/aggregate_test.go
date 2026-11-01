package aggregate

import (
	"testing"
	"time"
)

func TestShardKeepsBoundedTopN(t *testing.T) {
	s := NewShard(2)
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	s.AddFile("a", "one.bin", ".bin", 10, base.Add(3*time.Hour), true)
	s.AddFile("a", "two.bin", ".bin", 30, base.Add(1*time.Hour), true)
	s.AddFile("a", "three.bin", ".bin", 20, base.Add(2*time.Hour), true)
	s.AddFile("b", "old.txt", ".txt", 1, base, true)

	if len(s.largest) != 2 {
		t.Fatalf("largest len = %d", len(s.largest))
	}
	if s.largest[0].Size != 30 || s.largest[1].Size != 20 {
		t.Fatalf("largest = %#v", s.largest)
	}
	if len(s.stalest) != 2 || !s.stalest[0].ModTime.Equal(base) {
		t.Fatalf("stalest = %#v", s.stalest)
	}
	if s.totals.Entries != 4 || s.totals.LogicalBytes != 61 {
		t.Fatalf("totals = %#v", s.totals)
	}
	if len(s.sizes) != 4 {
		t.Fatalf("sizes = %#v", s.sizes)
	}
}

func TestCollectorMergesShardsAndHardlinkAccounting(t *testing.T) {
	c := NewCollector(3)
	a := NewShard(3)
	a.AddFile("x", "a.txt", ".txt", 100, time.Unix(1, 0), true)
	a.AddFile("x", "b.txt", ".txt", 100, time.Unix(2, 0), false)
	a.AddDir("x", 2, 200)
	a.AddJunkDir("node_modules", "x")
	a.AddExcluded("ext:.kdbx", "*.kdbx", "extension", true, false, 50)

	b := NewShard(3)
	b.AddFile("y", "c.bin", ".bin", 50, time.Unix(3, 0), true)
	b.AddDir("y", 1, 50)
	b.AddJunkFile("node_modules", 50)
	b.AddJunkFile("node_modules", 25)
	b.AddExcluded("ext:.kdbx", "*.kdbx", "extension", true, false, 25)
	b.SkipReparse(true)
	b.SkipPermissionDeniedDir()

	c.Merge(a)
	c.Merge(b)
	got := c.Snapshot()

	if got.Totals.Entries != 3 || got.Totals.UniqueFiles != 2 {
		t.Fatalf("totals = %#v", got.Totals)
	}
	if got.Totals.HardlinkExtra != 1 {
		t.Fatalf("hardlink extra = %d", got.Totals.HardlinkExtra)
	}
	if got.Totals.UniqueBytes != 150 {
		t.Fatalf("unique bytes = %d", got.Totals.UniqueBytes)
	}
	if len(got.Extensions) != 2 || got.Extensions[0].Ext != ".txt" {
		t.Fatalf("extensions = %#v", got.Extensions)
	}
	if len(got.SizeCounts) != 2 || got.SizeCounts[1].Count != 2 {
		t.Fatalf("size counts = %#v", got.SizeCounts)
	}
	if len(got.Excluded) != 1 || got.Excluded[0].Bytes != 75 || got.Excluded[0].Files != 2 {
		t.Fatalf("excluded = %#v", got.Excluded)
	}
	if len(got.Junk) != 1 || got.Junk[0].Kind != "node_modules" || got.Junk[0].Files != 2 || got.Junk[0].Bytes != 75 || got.Junk[0].Example != "x" {
		t.Fatalf("junk = %#v", got.Junk)
	}
	if got.Skipped.ReparsePointDirs != 1 || got.Skipped.PermissionDeniedDirs != 1 {
		t.Fatalf("skipped = %#v", got.Skipped)
	}
	if len(got.Directories) != 2 || got.Directories[0].Path != "x" {
		t.Fatalf("directories = %#v", got.Directories)
	}
}
