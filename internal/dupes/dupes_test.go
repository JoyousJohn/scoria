package dupes

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoyousJohn/scoria/internal/aggregate"
)

func TestCollectorFindsVerifiedDuplicateGroup(t *testing.T) {
	root := t.TempDir()
	one := bytes.Repeat([]byte("A"), 1<<20)
	two := bytes.Repeat([]byte("C"), 1<<20)
	a := filepath.Join(root, "a.bin")
	b := filepath.Join(root, "b.bin")
	c := filepath.Join(root, "c.bin")
	writeFile(t, a, one)
	writeFile(t, b, one)
	writeFile(t, c, two)

	coll := NewCollector([]aggregate.SizeCount{
		{Size: 1 << 20, Count: 3},
	}, Options{Root: root})
	coll.Sink(a, 1<<20, time.Time{})
	coll.Sink(b, 1<<20, time.Time{})
	coll.Sink(c, 1<<20, time.Time{})

	got := coll.Result()
	if len(got.Groups) != 1 {
		t.Fatalf("groups = %#v", got.Groups)
	}
	group := got.Groups[0]
	if group.Size != 1<<20 || group.Count != 2 || group.Wasted != 1<<20 {
		t.Fatalf("group = %#v", group)
	}
	if len(group.Paths) != 2 || group.Paths[0] != "a.bin" || group.Paths[1] != "b.bin" {
		t.Fatalf("paths = %#v", group.Paths)
	}
	if got.Candidates != 3 || got.Hashed != 2 {
		t.Fatalf("stats = %#v", got)
	}
}

func TestCollectorSkipsHardlinksAndProtectedPaths(t *testing.T) {
	root := t.TempDir()
	data := bytes.Repeat([]byte("B"), 1<<20)
	a := filepath.Join(root, "a.bin")
	link := filepath.Join(root, "a-link.bin")
	writeFile(t, a, data)
	if err := os.Link(a, link); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	protectedDir := filepath.Join(root, "Windows")
	if err := os.Mkdir(protectedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	protectedFile := filepath.Join(protectedDir, "p.bin")
	writeFile(t, protectedFile, data)

	coll := NewCollector([]aggregate.SizeCount{
		{Size: 1 << 20, Count: 3},
	}, Options{})
	coll.Sink(a, 1<<20, time.Time{})
	coll.Sink(link, 1<<20, time.Time{})
	coll.Sink(protectedFile, 1<<20, time.Time{})

	got := coll.Result()
	if got.SkippedHardlinks != 1 {
		t.Fatalf("hardlink skips = %d", got.SkippedHardlinks)
	}
	if got.SkippedProtected != 1 {
		t.Fatalf("protected skips = %d", got.SkippedProtected)
	}
	if got.Candidates != 1 {
		t.Fatalf("candidates = %d", got.Candidates)
	}
	if len(got.Groups) != 0 {
		t.Fatalf("unexpected groups: %#v", got.Groups)
	}
}

func TestCollectorSkipsFilesBelowMinimum(t *testing.T) {
	root := t.TempDir()
	data := bytes.Repeat([]byte("D"), 512<<10)
	a := filepath.Join(root, "a.bin")
	b := filepath.Join(root, "b.bin")
	writeFile(t, a, data)
	writeFile(t, b, data)

	coll := NewCollector([]aggregate.SizeCount{
		{Size: 512 << 10, Count: 2},
	}, Options{})
	coll.Sink(a, 512<<10, time.Time{})
	coll.Sink(b, 512<<10, time.Time{})

	if got := coll.CandidateCount(); got != 0 {
		t.Fatalf("candidates = %d", got)
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
