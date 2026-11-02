package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/JoyousJohn/scoria/internal/analyzer"
	"github.com/JoyousJohn/scoria/internal/analyzer/openrouter"
	"github.com/JoyousJohn/scoria/internal/digest"
	"github.com/JoyousJohn/scoria/internal/dupes"
	"github.com/JoyousJohn/scoria/internal/integrity"
	"github.com/JoyousJohn/scoria/internal/report"
	"github.com/JoyousJohn/scoria/internal/rules"
	"github.com/JoyousJohn/scoria/internal/scan"
)

func main() {
	root := flag.String("root", ".", "directory to scan")
	workers := flag.Int("workers", 0, "directory workers (0 = 2x logical CPUs)")
	top := flag.Int("top", 20, "number of entries to keep in each largest/oldest list (0 disables)")
	jsonOutput := flag.Bool("json", false, "write the versioned digest JSON to stdout")
	htmlPath := flag.String("html", "", "write a self-contained HTML report to this path (- for stdout)")
	openReport := flag.Bool("open", true, "open the HTML report in the default browser")
	aiPreview := flag.Bool("ai-preview", false, "print the redacted analyzer payload and exit (no network)")
	useAI := flag.Bool("ai", false, "run the optional analyzer on redacted candidates")
	discover := flag.Bool("ai-discover", false, "propose directory patterns through the analyzer")
	discoveryPreview := flag.Bool("ai-discover-preview", false, "print the redacted discovery payload and exit (no network)")
	model := flag.String("model", "", "model ID for the selected endpoint (required with -ai)")
	baseURL := flag.String("base-url", "", "OpenAI-compatible API base URL (default "+openrouter.DefaultBaseURL+")")
	provider := flag.String("provider", "", "provider preset ("+providerIDs()+"); -base-url overrides")
	pause := flag.Bool("pause", false, "wait for Enter before exiting")
	countLinks := flag.Bool("links", true, "open each file read-only for accurate hard-link/unique totals (slower)")
	verifyDupes := flag.Bool("dupes", false, "verify same-size duplicates >= 1 MiB by hashing candidates (reads candidate file contents)")
	interactive := flag.Bool("interactive", false, "prompt for the options in the terminal before scanning")
	lowIntegrity := flag.Bool("low-integrity", false, "lower the process to low integrity before scanning (disables file report output)")
	colorMode := flag.String("color", "auto", "color output: auto, always, or never")
	progressMode := flag.String("progress", "auto", "progress line: auto, always, or never")
	sortMode := flag.String("sort", "priority", "recommendation order: priority or size")
	excludeFile := flag.String("exclude-file", "", "read exclusions from a text file")
	noConfig := flag.Bool("no-config", false, "do not load the default exclusion config")
	var exclusionArgs exclusionFlags
	flag.Var(&exclusionArgs.dirs, "exclude", "exclude a directory subtree (repeatable)")
	flag.Var(&exclusionArgs.globs, "exclude-glob", "exclude a glob pattern (repeatable)")
	flag.Var(&exclusionArgs.exts, "exclude-ext", "exclude a file extension (repeatable)")
	flag.Var(&exclusionArgs.names, "exclude-name", "exclude a filename (repeatable)")
	flag.Parse()
	exclusionArgs.config = *excludeFile
	exclusionArgs.noConfig = *noConfig

	autoInteractive := shouldAutoInteractive(flag.NFlag(), flag.NArg(), isConsole(os.Stdin), isConsole(os.Stdout))
	if strings.EqualFold(strings.TrimSpace(*provider), "list") {
		for _, preset := range providerPresets {
			fmt.Fprintf(os.Stdout, "%-10s %s\n", preset.id, preset.baseURL)
		}
		return
	}
	if autoInteractive {
		*interactive = true
		*pause = true
	}

	if !validColorMode(*colorMode) {
		fmt.Fprintf(os.Stderr, "scoria: invalid -color %q (want auto, always, or never)\n", *colorMode)
		os.Exit(2)
	}
	if !validProgressMode(*progressMode) {
		fmt.Fprintf(os.Stderr, "scoria: invalid -progress %q (want auto, always, or never)\n", *progressMode)
		os.Exit(2)
	}
	stdoutColor := newColorizer(os.Stdout, *colorMode)
	stderrColor := newColorizer(os.Stderr, *colorMode)
	apiKey := os.Getenv("SCORIA_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("OPENROUTER_API_KEY")
	}
	apiBase, baseErr := resolveProviderBase(*provider, *baseURL)
	if baseErr != nil {
		fmt.Fprintf(os.Stderr, "scoria: %v\n", baseErr)
		os.Exit(2)
	}
	if apiBase == "" {
		apiBase = strings.TrimSpace(os.Getenv("SCORIA_BASE_URL"))
	}

	var input *bufio.Reader
	if *interactive {
		input = bufio.NewReader(os.Stdin)
		wizard, err := promptOptions(input, os.Stderr, stderrColor, wizardOptions{
			Root:         *root,
			Workers:      *workers,
			TopN:         *top,
			CountLinks:   *countLinks,
			JSON:         *jsonOutput,
			HTML:         *htmlPath,
			Open:         *openReport,
			Dupes:        *verifyDupes,
			AI:           *useAI,
			Model:        *model,
			LowIntegrity: *lowIntegrity,
			Exclusions:   exclusionArgs,
			APIKey:       apiKey,
			BaseURL:      apiBase,
		})
		if err != nil {
			if errors.Is(err, errWizardQuit) {
				return
			}
			fmt.Fprintf(os.Stderr, "%s %v\n", stderrColor.failure("scoria:"), err)
			os.Exit(2)
		}
		*root = wizard.Root
		*workers = wizard.Workers
		*top = wizard.TopN
		*countLinks = wizard.CountLinks
		*jsonOutput = wizard.JSON
		*htmlPath = wizard.HTML
		*openReport = wizard.Open
		*verifyDupes = wizard.Dupes
		*useAI = wizard.AI
		*model = wizard.Model
		*lowIntegrity = wizard.LowIntegrity
		exclusionArgs = wizard.Exclusions
	}

	if !validSortMode(*sortMode) {
		fmt.Fprintf(os.Stderr, "scoria: invalid -sort %q (want priority or size)\n", *sortMode)
		os.Exit(2)
	}
	if *htmlPath != "" && *jsonOutput {
		fmt.Fprintln(os.Stderr, "scoria: -html and -json cannot be combined")
		os.Exit(2)
	}
	if *aiPreview && (*jsonOutput || *htmlPath != "" || *useAI || *discover || *discoveryPreview) {
		fmt.Fprintln(os.Stderr, "scoria: -ai-preview cannot be combined with another output or AI mode")
		os.Exit(2)
	}
	if *discoveryPreview && (*jsonOutput || *htmlPath != "" || *useAI || *aiPreview || *discover) {
		fmt.Fprintln(os.Stderr, "scoria: -ai-discover-preview cannot be combined with another output or AI mode")
		os.Exit(2)
	}
	if *useAI && *discover {
		fmt.Fprintln(os.Stderr, "scoria: -ai and -ai-discover cannot be combined")
		os.Exit(2)
	}
	if *useAI || *discover {
		if strings.TrimSpace(*model) == "" {
			fmt.Fprintln(os.Stderr, "scoria: -model is required with -ai or -ai-discover")
			os.Exit(2)
		}
		if apiKey == "" && openrouter.KeyRequired(apiBase) {
			fmt.Fprintln(os.Stderr, "scoria: set SCORIA_API_KEY or OPENROUTER_API_KEY for -ai or -ai-discover")
			os.Exit(2)
		}
		if err := openrouter.ValidateBaseURL(apiBase); err != nil {
			fmt.Fprintln(os.Stderr, "scoria:", err)
			os.Exit(2)
		}
	}
	if *lowIntegrity && *htmlPath != "" && *htmlPath != "-" {
		fmt.Fprintln(os.Stderr, "scoria: -low-integrity cannot write an HTML report file; use -html - or omit -html")
		os.Exit(2)
	}
	*sortMode = strings.ToLower(*sortMode)

	exclusionRules, customRules, configSource, configRules, buildErr := buildExclusionRules(exclusionArgs)
	if buildErr != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", stderrColor.failure("scoria:"), buildErr)
		os.Exit(2)
	}
	if configSource != "" {
		fmt.Fprintf(os.Stderr, "exclusions: loaded %d rules from %s\n", configRules, configSource)
	}
	cfg := scan.Options{
		Root:       *root,
		Workers:    *workers,
		TopN:       *top,
		CountLinks: *countLinks,
		Exclusions: exclusionRules,
	}
	jsonOut := *jsonOutput

	if *lowIntegrity {
		if err := integrity.LowerToLow(); err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", stderrColor.failure("scoria:"), err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "%s\n", stderrColor.warning("low integrity: scanning with a low-integrity token"))
	}

	progress := &progressLine{out: os.Stderr, enabled: progressEnabled(*progressMode, os.Stderr)}
	if progress.enabled {
		cfg.Progress = progress.update
	}

	result, err := scan.Walk(cfg)
	progress.finish()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", stderrColor.failure("scoria:"), err)
		os.Exit(2)
	}
	warnExclusionRules(os.Stderr, stderrColor, customRules, result.Aggregate)

	var duplicateResult *dupes.Result
	if *verifyDupes {
		fmt.Fprintf(os.Stderr, "%s\n", stderrColor.warning(
			"duplicate check: reading contents of same-size candidates; the metadata-only guarantee does not apply to this phase",
		))
		collector := dupes.NewCollector(result.Aggregate.SizeCounts, dupes.Options{Root: result.Root})
		dupProgress := &progressLine{out: os.Stderr, enabled: progress.enabled, label: "re-walked"}
		dupCfg := scan.Options{
			Root:       cfg.Root,
			Workers:    cfg.Workers,
			TopN:       0,
			CountLinks: false,
			FileSink:   collector.Sink,
		}
		if dupProgress.enabled {
			dupCfg.Progress = dupProgress.update
		}
		_, err := scan.Walk(dupCfg)
		dupProgress.finish()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", stderrColor.failure("scoria:"), err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "%s\n", stderrColor.muted(fmt.Sprintf(
			"duplicate check: hashing %s candidate files", commas(collector.CandidateCount()),
		)))
		duplicateResult = collector.Result()
	}

	elapsed := result.Elapsed
	entriesPerSecond := 0.0
	if elapsed > 0 {
		entriesPerSecond = float64(result.Aggregate.Totals.Entries) / elapsed.Seconds()
	}

	meta := digest.Scan{
		Workers:          result.Workers,
		TopN:             cfg.TopN,
		CountLinks:       cfg.CountLinks,
		GoVersion:        runtime.Version(),
		ElapsedMS:        elapsed.Milliseconds(),
		EntriesPerSecond: entriesPerSecond,
		Sort:             *sortMode,
	}
	ruleOpts := rules.DefaultOptions()
	ruleOpts.DuplicateCheck = duplicateResult
	recs := rules.Analyze(result.Root, result.Aggregate, ruleOpts)
	sortRecommendations(recs, *sortMode)
	doc := digest.New(result.Root, time.Now(), result.Aggregate, meta)
	if duplicateResult != nil {
		doc.DuplicateCheck = &digest.DuplicateCheck{
			Candidates:       duplicateResult.Candidates,
			Hashed:           duplicateResult.Hashed,
			BytesRead:        duplicateResult.BytesRead,
			ReadErrors:       duplicateResult.ReadErrors,
			SkippedProtected: duplicateResult.SkippedProtected,
			SkippedHardlinks: duplicateResult.SkippedHardlinks,
		}
	}
	for _, r := range recs {
		doc.Recommendations = append(doc.Recommendations, digest.Recommendation{
			ID:         r.ID,
			Rule:       r.Rule,
			Title:      r.Title,
			Detail:     r.Detail,
			Confidence: string(r.Confidence),
			Priority:   r.Priority,
			Items:      r.Items,
			Bytes:      r.Bytes,
			Examples:   r.Examples,
		})
	}

	if *discover || *discoveryPreview {
		names, err := runDiscovery(cfg, result.Root, progress.enabled)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", stderrColor.failure("scoria:"), err)
			os.Exit(2)
		}
		discoveryPayload := analyzer.BuildDiscoveryPayload(doc, names)
		if *discoveryPreview {
			fmt.Fprintln(os.Stderr, "discovery payload preview: no network request")
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(discoveryPayload); err != nil {
				fmt.Fprintf(os.Stderr, "%s %v\n", stderrColor.failure("scoria:"), err)
				os.Exit(2)
			}
			pauseIfRequested(*pause)
			return
		}
		client, err := openrouter.New(openrouter.Config{
			APIKey:  apiKey,
			Model:   *model,
			BaseURL: apiBase,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", stderrColor.failure("scoria:"), err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "discovery: sending %s directory names to %s model %s\n",
			commas(uint64(len(discoveryPayload.DirectoryNames))), endpointLabel(apiBase), *model)
		discoveryResult, err := client.Discover(context.Background(), discoveryPayload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s discovery failed: %v\n", stderrColor.warning("warning:"), err)
		} else {
			doc.Discovery = digestDiscovery(discoveryResult)
		}
	}

	if *useAI {
		payload := analyzer.BuildPayload(doc)
		if len(payload.Candidates) == 0 {
			fmt.Fprintf(os.Stderr, "%s\n", stderrColor.warning("cloud analysis: no candidates; request skipped"))
		} else {
			client, err := openrouter.New(openrouter.Config{
				APIKey:  apiKey,
				Model:   *model,
				BaseURL: apiBase,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s %v\n", stderrColor.failure("scoria:"), err)
				os.Exit(2)
			}
			fmt.Fprintf(os.Stderr, "cloud analysis: sending %s candidates to %s model %s\n",
				commas(uint64(len(payload.Candidates))), endpointLabel(apiBase), *model)
			result, err := client.Analyze(context.Background(), payload)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s cloud analysis failed: %v\n", stderrColor.warning("warning:"), err)
			} else {
				doc.Analysis = digestAnalysis(result, doc.Recommendations)
			}
		}
	}

	if *aiPreview {
		fmt.Fprintln(os.Stderr, "analyzer payload preview: no network request")
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(analyzer.BuildPayload(doc)); err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", stderrColor.failure("scoria:"), err)
			os.Exit(2)
		}
		pauseIfRequested(*pause)
		return
	}

	if *htmlPath != "" {
		var buf bytes.Buffer
		if err := report.Render(&buf, doc); err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", stderrColor.failure("scoria:"), err)
			os.Exit(2)
		}
		if *htmlPath == "-" {
			if _, err := os.Stdout.Write(buf.Bytes()); err != nil {
				fmt.Fprintf(os.Stderr, "%s %v\n", stderrColor.failure("scoria:"), err)
				os.Exit(2)
			}
			pauseIfRequested(*pause)
			return
		}
		if err := os.WriteFile(*htmlPath, buf.Bytes(), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", stderrColor.failure("scoria:"), err)
			os.Exit(2)
		}
		abs := *htmlPath
		if p, err := filepath.Abs(*htmlPath); err == nil {
			abs = p
		}
		fmt.Fprintf(os.Stderr, "%s\n", stderrColor.success("report written: "+abs))
		if *openReport {
			if err := openInBrowser(abs); err != nil {
				fmt.Fprintf(os.Stderr, "%s could not open report: %v\n", stderrColor.warning("warning:"), err)
			}
		}
		pauseIfRequested(*pause)
		return
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", stderrColor.failure("scoria:"), err)
			os.Exit(2)
		}
		pauseIfRequested(*pause)
		return
	}

	printSummary(os.Stdout, stdoutColor, result, entriesPerSecond, cfg.TopN, cfg.CountLinks)
	printRecommendations(os.Stdout, stdoutColor, recs, duplicateResult != nil)
	printDiscovery(os.Stdout, stdoutColor, doc.Discovery)
	printAnalysis(os.Stdout, stdoutColor, doc.Analysis)
	printDuplicateStats(os.Stdout, stdoutColor, duplicateResult)
	if *interactive && !jsonOut {
		runSortMenu(input, os.Stdout, os.Stderr, stdoutColor, stderrColor, recs, duplicateResult != nil, *sortMode)
	}
	pauseIfRequested(*pause)
}

func printDiscovery(w io.Writer, c *colorizer, discovery *digest.Discovery) {
	if discovery == nil {
		return
	}
	header := "suggested directory patterns (" + discovery.Analyzer
	if discovery.Model != "" {
		header += ", " + discovery.Model
	}
	header += "; review before acting):"
	fmt.Fprintf(w, "\n%s\n", c.heading(header))
	for _, pattern := range discovery.Patterns {
		fmt.Fprintf(w, "  %s  %s files  %s  [%s]\n", c.bold(pattern.Name), commas(pattern.Files), humanBytes(pattern.Bytes), c.muted(pattern.Confidence))
		fmt.Fprintf(w, "      %s\n", pattern.Reason)
	}
}

func printAnalysis(w io.Writer, c *colorizer, analysis *digest.Analysis) {
	if analysis == nil {
		return
	}
	header := "cloud analysis (" + analysis.Analyzer
	if analysis.Model != "" {
		header += ", " + analysis.Model
	}
	header += "):"
	fmt.Fprintf(w, "\n%s\n", c.heading(header))
	for _, finding := range analysis.Findings {
		title := finding.Title
		if title == "" {
			title = finding.ID
		}
		fmt.Fprintf(w, "  %s [%d] %s\n", c.muted(finding.ID), finding.Rank, c.bold(title))
		fmt.Fprintf(w, "      %s\n", finding.Explanation)
	}
}

func printDuplicateStats(w io.Writer, c *colorizer, result *dupes.Result) {
	if result == nil {
		return
	}
	fmt.Fprintf(w, "\n%s\n", c.heading("duplicate check:"))
	fmt.Fprintf(w, "  candidates: %s files, hashed: %s, read: %s, read errors: %s\n",
		commas(result.Candidates), commas(result.Hashed), humanBytes(result.BytesRead), coloredCount(c, result.ReadErrors))
	fmt.Fprintf(w, "  skipped: %s protected paths, %s hard-link entries\n",
		commas(result.SkippedProtected), commas(result.SkippedHardlinks))
}

func runDiscovery(cfg scan.Options, root string, progressEnabled bool) ([]analyzer.DirectoryName, error) {
	collector := analyzer.NewDiscoveryCollector(root)
	discoveryCfg := cfg
	discoveryCfg.Root = root
	discoveryCfg.TopN = 0
	discoveryCfg.CountLinks = false
	discoveryCfg.Progress = nil
	discoveryCfg.FileSink = collector.Sink
	discoveryProgress := &progressLine{out: os.Stderr, enabled: progressEnabled, label: "discovery"}
	if discoveryProgress.enabled {
		discoveryCfg.Progress = discoveryProgress.update
	}
	fmt.Fprintln(os.Stderr, "discovery: walking for directory-name aggregates")
	_, err := scan.Walk(discoveryCfg)
	discoveryProgress.finish()
	if err != nil {
		return nil, err
	}
	return collector.Result(200), nil
}

func digestAnalysis(result analyzer.Result, recs []digest.Recommendation) *digest.Analysis {
	titles := make(map[string]string, len(recs))
	for _, recommendation := range recs {
		titles[recommendation.ID] = recommendation.Title
	}
	analysis := &digest.Analysis{
		Analyzer: result.Analyzer,
		Model:    result.Model,
		Findings: make([]digest.AnalysisFinding, 0, len(result.Findings)),
	}
	for _, finding := range result.Findings {
		analysis.Findings = append(analysis.Findings, digest.AnalysisFinding{
			ID:          finding.ID,
			Title:       titles[finding.ID],
			Rank:        finding.Rank,
			Explanation: finding.Explanation,
		})
	}
	return analysis
}

func digestDiscovery(result analyzer.DiscoveryResult) *digest.Discovery {
	discovery := &digest.Discovery{
		Analyzer: result.Analyzer,
		Model:    result.Model,
		Patterns: make([]digest.DiscoveryFinding, 0, len(result.Patterns)),
	}
	for _, pattern := range result.Patterns {
		discovery.Patterns = append(discovery.Patterns, digest.DiscoveryFinding{
			Kind:       pattern.Kind,
			Name:       pattern.Name,
			Files:      pattern.Files,
			Bytes:      pattern.Bytes,
			Confidence: pattern.Confidence,
			Reason:     pattern.Reason,
		})
	}
	return discovery
}

func printRecommendations(w io.Writer, c *colorizer, recs []rules.Recommendation, contentsRead bool) {
	header := "recommendations (rules only; metadata only - verify before acting):"
	if contentsRead {
		header = "recommendations (rules only; duplicate candidates were content-hashed - verify before acting):"
	}
	fmt.Fprintf(w, "\n%s\n", c.heading(header))
	if len(recs) == 0 {
		fmt.Fprintf(w, "  %s\n", c.muted("none"))
		return
	}
	for i, r := range recs {
		fmt.Fprintf(w, "  %2d. [%s] %s\n", i+1, c.muted(string(r.Confidence)), c.bold(r.Title))
		fmt.Fprintf(w, "      %s %s, %s. %s\n", commas(r.Items), itemWord(r.Items), humanBytes(r.Bytes), r.Detail)
		for _, example := range r.Examples {
			fmt.Fprintf(w, "      e.g. %s\n", c.muted(example))
		}
	}
}

func printSummary(w io.Writer, c *colorizer, result *scan.Result, entriesPerSecond float64, top int, countLinks bool) {
	agg := result.Aggregate
	fmt.Fprintf(w, "%s\n", c.heading("scoria scan (read-only)"))
	fmt.Fprintf(w, "root:       %s\n", result.Root)
	fmt.Fprintf(w, "workers:    %d\ntop:        %d\nelapsed:    %s\nthroughput: %s entries/sec\n\n",
		result.Workers, top, result.Elapsed.Round(time.Millisecond), commasFloat(entriesPerSecond))

	fmt.Fprintf(w, "entries:        %s\n", commas(agg.Totals.Entries))
	if countLinks {
		fmt.Fprintf(w, "unique files:   %s\n", commas(agg.Totals.UniqueFiles))
		fmt.Fprintf(w, "hardlink extra: %s\n", commas(agg.Totals.HardlinkExtra))
	} else {
		fmt.Fprintf(w, "unique files:   %s\n", c.warning("not computed (-links=false)"))
		fmt.Fprintf(w, "hardlink extra: %s\n", c.warning("not computed (-links=false)"))
	}
	fmt.Fprintf(w, "files:          %s\n", commas(agg.Totals.Files))
	fmt.Fprintf(w, "directories:    %s\n", commas(agg.Totals.Directories))
	fmt.Fprintf(w, "empty files:    %s\n", commas(agg.Totals.EmptyFiles))
	fmt.Fprintf(w, "logical bytes:  %s\n", humanBytes(agg.Totals.LogicalBytes))
	fmt.Fprintf(w, "unique bytes:   %s\n\n", humanBytes(agg.Totals.UniqueBytes))

	if len(agg.Largest) > 0 {
		fmt.Fprintf(w, "%s\n", c.heading("largest files:"))
		for i, f := range agg.Largest {
			fmt.Fprintf(w, "  %2d. %10s  %s\n", i+1, humanBytes(f.Size), c.muted(f.Path))
		}
		fmt.Fprintln(w)
	}

	if len(agg.Stalest) > 0 {
		fmt.Fprintf(w, "%s\n", c.heading("oldest files by last write:"))
		for i, f := range agg.Stalest {
			stamp := "unknown"
			if !f.ModTime.IsZero() {
				stamp = f.ModTime.Format("2006-01-02")
			}
			fmt.Fprintf(w, "  %2d. %10s  %s  %s\n", i+1, stamp, humanBytes(f.Size), c.muted(f.Path))
		}
		fmt.Fprintln(w)
	}

	if len(agg.Directories) > 0 {
		fmt.Fprintf(w, "%s\n", c.heading("largest directories (direct contents):"))
		for i, d := range agg.Directories {
			fmt.Fprintf(w, "  %2d. %10s  %s files  %s\n", i+1, humanBytes(d.Bytes), commas(d.Files), c.muted(d.Path))
		}
		fmt.Fprintln(w)
	}

	if len(agg.Extensions) > 0 {
		fmt.Fprintf(w, "%s\n", c.heading("extensions:"))
		limit := len(agg.Extensions)
		if limit > 12 {
			limit = 12
		}
		for _, e := range agg.Extensions[:limit] {
			ext := e.Ext
			if ext == "" {
				ext = "(none)"
			}
			fmt.Fprintf(w, "  %-14s %10s files  %s\n", ext, commas(e.Files), humanBytes(e.Bytes))
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%s\n", c.heading("excluded by rules (not enumerated or aggregated):"))
	if len(agg.Excluded) == 0 {
		fmt.Fprintf(w, "  %s\n", c.success("none matched"))
	} else {
		for _, e := range agg.Excluded {
			suffix := ""
			if e.Sensitive {
				suffix = c.muted("  [sensitive preset, aggregate only]")
			}
			if e.Dirs > 0 {
				fmt.Fprintf(w, "  %-32s %s dirs  %s%s\n", e.Rule, commas(e.Dirs), "(subtree not enumerated)", suffix)
			}
			if e.Files > 0 {
				fmt.Fprintf(w, "  %-32s %s files  %s%s\n", e.Rule, commas(e.Files), humanBytes(e.Bytes), suffix)
			}
		}
	}
	fmt.Fprintln(w)

	s := agg.Skipped
	fmt.Fprintf(w, "%s\n", c.heading("skipped by the tool:"))
	fmt.Fprintf(w, "  reparse points:      %s (%s dirs, %s files)\n",
		coloredCount(c, s.ReparsePoints), coloredCount(c, s.ReparsePointDirs), coloredCount(c, s.ReparsePointFiles))
	fmt.Fprintf(w, "  permission denied:   %s directories, %s files\n",
		coloredCount(c, s.PermissionDeniedDirs), coloredCount(c, s.FileAccessDenied))
	fmt.Fprintf(w, "  cloud placeholders:  %s (%s, not opened)\n",
		coloredCount(c, s.CloudPlaceholders), coloredBytes(c, s.CloudPlaceholderBytes))
	fmt.Fprintf(w, "  long path names:     %s\n", coloredCount(c, s.LongPathNames))
	fmt.Fprintf(w, "  other errors:        %s directories, %s file opens\n",
		coloredCount(c, s.OtherErrors), coloredCount(c, s.FileOpenErrors))
}

func coloredCount(c *colorizer, n uint64) string {
	if n == 0 {
		return c.muted("0")
	}
	return c.warning(commas(n))
}

func coloredBytes(c *colorizer, n int64) string {
	if n == 0 {
		return c.muted("0 B")
	}
	return c.warning(humanBytes(n))
}

func itemWord(n uint64) string {
	if n == 1 {
		return "item"
	}
	return "items"
}

func commas(n uint64) string {
	return addCommas(strconv.FormatUint(n, 10))
}

func addCommas(s string) string {
	if len(s) <= 3 {
		return s
	}
	var b []byte
	head := len(s) % 3
	if head > 0 {
		b = append(b, s[:head]...)
	}
	for i := head; i < len(s); i += 3 {
		if len(b) > 0 {
			b = append(b, ',')
		}
		b = append(b, s[i:i+3]...)
	}
	return string(b)
}

func commasFloat(v float64) string {
	if v < 1000 {
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return commas(uint64(v))
}

func humanBytes(n int64) string {
	if n < 0 {
		return "-" + humanBytes(-n)
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	value := strconv.FormatFloat(float64(n)/float64(div), 'f', 2, 64)
	if dot := strings.IndexByte(value, '.'); dot >= 0 {
		value = addCommas(value[:dot]) + value[dot:]
	}
	return value + " " + string("KMGTPE"[exp]) + "iB"
}

func openInBrowser(path string) error {
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", path).Start()
}

func shouldAutoInteractive(nflags, nargs int, stdinConsole, stdoutConsole bool) bool {
	return nflags == 0 && nargs == 0 && stdinConsole && stdoutConsole
}

func pauseIfRequested(enabled bool) {
	if !enabled {
		return
	}
	fmt.Fprint(os.Stderr, "\nPress Enter to exit...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
