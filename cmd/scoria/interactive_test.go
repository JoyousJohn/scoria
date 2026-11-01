package main

import (
	"bufio"
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestPromptOptionsDefaults(t *testing.T) {
	var out bytes.Buffer
	defaults := wizardOptions{Root: ".", Workers: 0, TopN: 20, CountLinks: true, Open: true}
	got, err := promptOptions(bufio.NewReader(strings.NewReader("\n\n\n\n\n\n\n")), &out, nil, defaults)
	if err != nil {
		t.Fatalf("promptOptions: %v", err)
	}
	if got.Root != "." || got.Workers != 0 || got.TopN != 20 || !got.CountLinks {
		t.Fatalf("scan options = %#v", got)
	}
	if got.JSON || got.Dupes || got.AI || got.LowIntegrity {
		t.Fatalf("optional modes should be off: %#v", got)
	}
	if !filepath.IsAbs(got.HTML) || !strings.HasSuffix(got.HTML, ".html") {
		t.Fatalf("report path = %q", got.HTML)
	}
	if !got.Open {
		t.Fatal("report should open by default")
	}
}

func TestPromptOptionsOverrides(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	defaults := wizardOptions{Root: ".", Workers: 0, TopN: 20, CountLinks: true, Open: true}
	input := dir + "\n2\n1,2\n\n2\n\n"
	got, err := promptOptions(bufio.NewReader(strings.NewReader(input)), &out, nil, defaults)
	if err != nil {
		t.Fatalf("promptOptions: %v", err)
	}
	if got.Root != filepath.Clean(dir) {
		t.Fatalf("root = %q, want %q", got.Root, filepath.Clean(dir))
	}
	if got.CountLinks {
		t.Fatal("fast mode should disable hard-link counting")
	}
	if !got.Dupes {
		t.Fatal("duplicate verification should be on")
	}
	if got.AI {
		t.Fatal("AI review should be skipped without an API key")
	}
	if got.JSON || got.HTML != "" {
		t.Fatalf("console output selected, got JSON=%v HTML=%q", got.JSON, got.HTML)
	}
	if !strings.Contains(out.String(), "AI review needs SCORIA_API_KEY") {
		t.Fatalf("missing key message absent: %q", out.String())
	}
}

func TestPromptOptionsRetriesInvalidAnswers(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	defaults := wizardOptions{Root: ".", Workers: 0, TopN: 20, CountLinks: true, Open: true}
	input := "Z:\\definitely-not-here\n" + dir + "\n9\n1\nx\n\n7\n3\n\n"
	got, err := promptOptions(bufio.NewReader(strings.NewReader(input)), &out, nil, defaults)
	if err != nil {
		t.Fatalf("promptOptions: %v", err)
	}
	if got.Root != filepath.Clean(dir) {
		t.Fatalf("root = %q, want %q", got.Root, filepath.Clean(dir))
	}
	if !got.JSON {
		t.Fatal("JSON output should be selected")
	}
	text := out.String()
	for _, want := range []string{
		"Cannot use",
		"Please enter a number from 1 to 2.",
		"Please enter 1, 2, 1,2, or none.",
		"Please enter a number from 1 to 3.",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q: %q", want, text)
		}
	}
}

func TestPromptOptionsQuit(t *testing.T) {
	var out bytes.Buffer
	defaults := wizardOptions{Root: ".", Workers: 0, TopN: 20, CountLinks: true, Open: true}
	_, err := promptOptions(bufio.NewReader(strings.NewReader("\n\n\n\n\n\nq\n")), &out, nil, defaults)
	if !errors.Is(err, errWizardQuit) {
		t.Fatalf("err = %v, want errWizardQuit", err)
	}
}

func TestPromptOptionsAIRequiresModel(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	defaults := wizardOptions{Root: dir, Workers: 0, TopN: 20, CountLinks: true, Open: true, APIKey: "test-key"}
	input := "\n1\n2\n\nopenai/gpt-4o-mini\n2\n\n"
	got, err := promptOptions(bufio.NewReader(strings.NewReader(input)), &out, nil, defaults)
	if err != nil {
		t.Fatalf("promptOptions: %v", err)
	}
	if !got.AI || got.Model != "openai/gpt-4o-mini" {
		t.Fatalf("AI = %v, model = %q", got.AI, got.Model)
	}
	if !strings.Contains(out.String(), "redacted payload") {
		t.Fatalf("redaction notice absent: %q", out.String())
	}
}

func TestPromptOptionsAllowsKeylessLoopbackAI(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	defaults := wizardOptions{
		Root:       dir,
		Workers:    0,
		TopN:       20,
		CountLinks: true,
		Open:       true,
		BaseURL:    "http://127.0.0.1:11434/v1",
	}
	input := "\n1\n2\n\n\nlocal-model\n2\n\n"
	got, err := promptOptions(bufio.NewReader(strings.NewReader(input)), &out, nil, defaults)
	if err != nil {
		t.Fatalf("promptOptions: %v", err)
	}
	if !got.AI || got.Model != "local-model" {
		t.Fatalf("AI = %v, model = %q", got.AI, got.Model)
	}
}

func TestPromptOptionsBlankModelSkipsAI(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	defaults := wizardOptions{Root: dir, Workers: 0, TopN: 20, CountLinks: true, Open: true, APIKey: "test-key"}
	input := "\n1\n2\n\n\n2\n\n"
	got, err := promptOptions(bufio.NewReader(strings.NewReader(input)), &out, nil, defaults)
	if err != nil {
		t.Fatalf("promptOptions: %v", err)
	}
	if got.AI {
		t.Fatal("blank model should skip AI review")
	}
}

func TestPromptAdvancedUpdatesOptions(t *testing.T) {
	var out bytes.Buffer
	opts := wizardOptions{
		Root:       ".",
		Workers:    0,
		TopN:       20,
		CountLinks: true,
		Open:       true,
		HTML:       `C:\reports\scoria.html`,
	}
	input := "1\n50\n2\n8\n3\nC:\\temp\n5\n.log\n9\ny\nb\n"
	if err := promptAdvanced(bufio.NewReader(strings.NewReader(input)), &out, nil, &opts); err != nil {
		t.Fatalf("promptAdvanced: %v", err)
	}
	if opts.TopN != 50 || opts.Workers != 8 {
		t.Fatalf("top = %d, workers = %d", opts.TopN, opts.Workers)
	}
	if len(opts.Exclusions.dirs) != 1 || opts.Exclusions.dirs[0] != `C:\temp` {
		t.Fatalf("dirs = %#v", opts.Exclusions.dirs)
	}
	if len(opts.Exclusions.exts) != 1 || opts.Exclusions.exts[0] != ".log" {
		t.Fatalf("exts = %#v", opts.Exclusions.exts)
	}
	if !opts.LowIntegrity {
		t.Fatal("low integrity should be on")
	}
	if opts.HTML != "" || opts.Open {
		t.Fatalf("HTML = %q, open = %v; low integrity must fall back to console", opts.HTML, opts.Open)
	}
	if !strings.Contains(out.String(), "switching output to console") {
		t.Fatalf("fallback notice absent: %q", out.String())
	}
}

func TestPromptAdvancedTogglesDefaultConfig(t *testing.T) {
	var out bytes.Buffer
	opts := wizardOptions{TopN: 20}
	input := "8\nb\n"
	if err := promptAdvanced(bufio.NewReader(strings.NewReader(input)), &out, nil, &opts); err != nil {
		t.Fatalf("promptAdvanced: %v", err)
	}
	if !opts.Exclusions.noConfig {
		t.Fatal("default exclusion config should be off")
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

func TestPromptOptionsSelectsProviderPreset(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	defaults := wizardOptions{Root: dir, Workers: 0, TopN: 20, CountLinks: true, Open: true, APIKey: "test-key"}
	input := "\n1\n2\n2\ngpt-4o\n2\n\n"
	got, err := promptOptions(bufio.NewReader(strings.NewReader(input)), &out, nil, defaults)
	if err != nil {
		t.Fatalf("promptOptions: %v", err)
	}
	if got.BaseURL != "https://api.openai.com/v1" {
		t.Fatalf("base URL = %q", got.BaseURL)
	}
	if !got.AI || got.Model != "gpt-4o" {
		t.Fatalf("AI = %v, model = %q", got.AI, got.Model)
	}
}

func TestAskProviderCustomURLValidates(t *testing.T) {
	var out bytes.Buffer
	input := "9\nhttp://example.com\nhttp://127.0.0.1:8080/v1\n"
	got, err := askProvider(bufio.NewReader(strings.NewReader(input)), &out, nil, "")
	if err != nil {
		t.Fatalf("askProvider: %v", err)
	}
	if got != "http://127.0.0.1:8080/v1" {
		t.Fatalf("base = %q", got)
	}
	if !strings.Contains(out.String(), "refusing non-HTTPS") {
		t.Fatalf("validation message absent: %q", out.String())
	}
}

func TestAskReportPathRejectsMissingDirectoryAndAcceptsStdout(t *testing.T) {
	var out bytes.Buffer
	missing := filepath.Join(t.TempDir(), "missing", "report.html")
	got, err := askReportPath(
		bufio.NewReader(strings.NewReader(missing+"\n-\n")),
		&out,
		nil,
		filepath.Join(t.TempDir(), "default.html"),
	)
	if err != nil {
		t.Fatalf("askReportPath: %v", err)
	}
	if got != "-" {
		t.Fatalf("path = %q, want -", got)
	}
	if !strings.Contains(out.String(), "directory does not exist") {
		t.Fatalf("missing directory message absent: %q", out.String())
	}
}
