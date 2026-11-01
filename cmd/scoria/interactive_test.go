package main

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JoyousJohn/scoria/internal/scan"
)

func TestPromptOptionsDefaults(t *testing.T) {
	var out bytes.Buffer
	defaults := scan.Options{Root: ".", Workers: 0, TopN: 20, CountLinks: true}
	got, jsonOut, err := promptOptions(bufio.NewReader(strings.NewReader("\n\n\n\n\n")), &out, nil, defaults, false)
	if err != nil {
		t.Fatalf("promptOptions: %v", err)
	}
	if !sameOptions(got, defaults) {
		t.Fatalf("options = %#v", got)
	}
	if jsonOut {
		t.Fatal("json should default to false")
	}
}

func TestPromptOptionsOverrides(t *testing.T) {
	var out bytes.Buffer
	defaults := scan.Options{Root: ".", Workers: 0, TopN: 20, CountLinks: true}
	got, jsonOut, err := promptOptions(bufio.NewReader(strings.NewReader("C:\\Windows\nn\n50\n8\n2\n")), &out, nil, defaults, false)
	if err != nil {
		t.Fatalf("promptOptions: %v", err)
	}
	want := scan.Options{Root: `C:\Windows`, Workers: 8, TopN: 50, CountLinks: false}
	if !sameOptions(got, want) {
		t.Fatalf("options = %#v, want %#v", got, want)
	}
	if !jsonOut {
		t.Fatal("json should be true")
	}
}

func TestPromptOptionsRetriesMissingRoot(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	defaults := scan.Options{Root: ".", Workers: 0, TopN: 20, CountLinks: true}
	input := "Z:\\definitely-not-here\n" + dir + "\n\n\n\n\n"
	got, _, err := promptOptions(bufio.NewReader(strings.NewReader(input)), &out, nil, defaults, false)
	if err != nil {
		t.Fatalf("promptOptions: %v", err)
	}
	if got.Root != filepath.Clean(dir) {
		t.Fatalf("root = %q, want %q", got.Root, filepath.Clean(dir))
	}
	if !strings.Contains(out.String(), "Cannot use") {
		t.Fatalf("output did not contain root error: %q", out.String())
	}
}

func TestAskRootAcceptsDriveNumberAndQuotes(t *testing.T) {
	dir := t.TempDir()
	drives := []driveChoice{{root: dir, label: "Temp"}}
	var out bytes.Buffer

	r := bufio.NewReader(strings.NewReader("1\n"))
	got, err := askRoot(r, &out, nil, "Root directory", ".", drives)
	if err != nil {
		t.Fatalf("askRoot number: %v", err)
	}
	if got != filepath.Clean(dir) {
		t.Fatalf("root = %q, want %q", got, filepath.Clean(dir))
	}

	out.Reset()
	r = bufio.NewReader(strings.NewReader(`"` + dir + `"` + "\n"))
	got, err = askRoot(r, &out, nil, "Root directory", ".", drives)
	if err != nil {
		t.Fatalf("askRoot quoted: %v", err)
	}
	if got != filepath.Clean(dir) {
		t.Fatalf("root = %q, want %q", got, filepath.Clean(dir))
	}
}

func TestPromptOptionsShowsHardlinkHelpThenAcceptsAnswer(t *testing.T) {
	var out bytes.Buffer
	defaults := scan.Options{Root: ".", Workers: 0, TopN: 20, CountLinks: true}
	got, _, err := promptOptions(bufio.NewReader(strings.NewReader("\n?\ny\n\n\n\n")), &out, nil, defaults, false)
	if err != nil {
		t.Fatalf("promptOptions: %v", err)
	}
	if !got.CountLinks {
		t.Fatal("count links should be true")
	}
	if !strings.Contains(out.String(), "A hard link is a second name") {
		t.Fatalf("output did not contain help: %q", out.String())
	}
	if !strings.Contains(out.String(), "[Y/n/?]") {
		t.Fatalf("output did not advertise help: %q", out.String())
	}
}

func TestPromptOptionsRetriesInvalidAnswers(t *testing.T) {
	var out bytes.Buffer
	defaults := scan.Options{Root: ".", Workers: 0, TopN: 20, CountLinks: true}
	got, jsonOut, err := promptOptions(bufio.NewReader(strings.NewReader("\nmaybe\ny\n-1\n10\n8\n9\nconsole\n")), &out, nil, defaults, false)
	if err != nil {
		t.Fatalf("promptOptions: %v", err)
	}
	want := scan.Options{Root: ".", Workers: 8, TopN: 10, CountLinks: true}
	if !sameOptions(got, want) {
		t.Fatalf("options = %#v, want %#v", got, want)
	}
	if jsonOut {
		t.Fatal("json should be false")
	}
	if !strings.Contains(out.String(), "Please enter a non-negative integer.") {
		t.Fatalf("output did not contain retry message: %q", out.String())
	}
}

func sameOptions(a, b scan.Options) bool {
	return a.Root == b.Root && a.Workers == b.Workers && a.TopN == b.TopN && a.CountLinks == b.CountLinks
}
