package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/JoyousJohn/scoria/internal/analyzer/openrouter"
)

var errWizardQuit = errors.New("interactive setup cancelled")

type wizardOptions struct {
	Root         string
	Workers      int
	TopN         int
	CountLinks   bool
	JSON         bool
	HTML         string
	Open         bool
	Dupes        bool
	AI           bool
	Model        string
	LowIntegrity bool
	Exclusions   exclusionFlags
	APIKey       string
	BaseURL      string
}

func promptOptions(r *bufio.Reader, out io.Writer, c *colorizer, d wizardOptions) (wizardOptions, error) {
	opts := d

	fmt.Fprintln(out, c.heading("Scoria interactive setup"))
	fmt.Fprintln(out, c.muted("Press Enter to accept the value in brackets."))
	fmt.Fprintln(out)

	drives := listDrives()
	if len(drives) > 0 {
		fmt.Fprintln(out, c.heading("Available drives:"))
		for i, dr := range drives {
			line := fmt.Sprintf("  %d. %-4s", i+1, dr.root)
			if dr.label != "" {
				line += " " + dr.label
			}
			if free := freeSpace(dr.root); free != "" {
				line += " (" + free + " free)"
			}
			fmt.Fprintln(out, line)
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintln(out, c.muted("Enter a number, a directory path, or press Enter for the current directory."))
	root, err := askRoot(r, out, c, "Root directory", opts.Root, drives)
	if err != nil {
		return d, err
	}
	opts.Root = root

	fmt.Fprintln(out)
	fmt.Fprintln(out, c.heading("How thorough should the scan be?"))
	fmt.Fprintln(out, "  1. Standard - metadata only; count hard links for accurate totals (default)")
	fmt.Fprintln(out, "  2. Fast     - metadata only; skip hard-link accounting (unique totals not computed)")
	defDepth := 1
	if !opts.CountLinks {
		defDepth = 2
	}
	depth, err := askMenu(r, out, c, "Scan depth", 2, defDepth)
	if err != nil {
		return d, err
	}
	opts.CountLinks = depth == 1

	fmt.Fprintln(out)
	fmt.Fprintln(out, c.heading("Extra analysis (comma-separated; Enter for none):"))
	fmt.Fprintln(out, "  1. Verify duplicates - hash same-size files >= 1 MiB (reads candidate contents)")
	fmt.Fprintln(out, "  2. AI review         - send a redacted, path-free summary to your configured AI endpoint")
	dupes, ai, err := askAnalysis(r, out, c, opts.Dupes, opts.AI)
	if err != nil {
		return d, err
	}
	opts.Dupes = dupes
	opts.AI = ai
	if opts.AI {
		base, err := askProvider(r, out, c, opts.BaseURL)
		if err != nil {
			return d, err
		}
		opts.BaseURL = base
		if opts.APIKey == "" && openrouter.KeyRequired(opts.BaseURL) {
			fmt.Fprintln(out, c.warning("AI review needs SCORIA_API_KEY or OPENROUTER_API_KEY; AI review is off."))
			opts.AI = false
		} else {
			if strings.TrimSpace(opts.Model) == "" {
				model, err := readLine(r, out, c, "Model ID (blank skips AI review)", "")
				if err != nil {
					return d, err
				}
				if model == "" {
					opts.AI = false
				} else {
					opts.Model = model
				}
			}
			if opts.AI {
				fmt.Fprintln(out, c.muted("AI review sends only the redacted payload; no paths or examples."))
			}
		}
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, c.heading("Output:"))
	fmt.Fprintln(out, "  1. HTML report, opened in your browser (default)")
	fmt.Fprintln(out, "  2. Console summary in this window")
	fmt.Fprintln(out, "  3. JSON digest to stdout")
	defOutput := 1
	if opts.JSON {
		defOutput = 3
	}
	output, err := askMenu(r, out, c, "Output format", 3, defOutput)
	if err != nil {
		return d, err
	}
	switch output {
	case 2:
		opts.JSON = false
		opts.HTML = ""
	case 3:
		opts.JSON = true
		opts.HTML = ""
	default:
		opts.JSON = false
		if opts.LowIntegrity && opts.HTML != "-" {
			fmt.Fprintln(out, c.warning("Low integrity cannot write an HTML report file; using console output instead."))
			opts.HTML = ""
			opts.Open = false
			break
		}
		path, err := askReportPath(r, out, c, opts.HTML)
		if err != nil {
			return d, err
		}
		opts.HTML = path
		if path != "-" {
			opts.Open, err = askBool(
				r,
				out,
				c,
				"Open the report when it is ready",
				"",
				"Y opens the finished report in your default browser. n leaves it on disk and prints the path.",
				opts.Open,
			)
			if err != nil {
				return d, err
			}
		}
	}

	for {
		printPlan(out, c, opts)
		value, err := readLine(r, out, c, "Start scan (a = advanced options, q = quit)", "")
		if err != nil {
			return d, err
		}
		switch strings.ToLower(value) {
		case "", "y", "yes", "start":
			return opts, nil
		case "a", "advanced":
			if err := promptAdvanced(r, out, c, &opts); err != nil {
				return d, err
			}
		case "q", "quit":
			return d, errWizardQuit
		default:
			fmt.Fprintln(out, c.warning("Press Enter to start, a for advanced options, or q to quit."))
		}
	}
}

func promptAdvanced(r *bufio.Reader, out io.Writer, c *colorizer, o *wizardOptions) error {
	for {
		fmt.Fprintln(out)
		fmt.Fprintln(out, c.heading("Advanced options"))
		fmt.Fprintf(out, "  1. Top-N per largest/oldest list: %d\n", o.TopN)
		fmt.Fprintf(out, "  2. Directory workers: %s\n", workerText(o.Workers))
		fmt.Fprintf(out, "  3. Add excluded directory (%s)\n", customRuleText(customExclusionCount(o.Exclusions)))
		fmt.Fprintln(out, "  4. Add excluded glob")
		fmt.Fprintln(out, "  5. Add excluded extension")
		fmt.Fprintln(out, "  6. Add excluded filename")
		fmt.Fprintf(out, "  7. Exclusion file: %s\n", exclusionFileText(o.Exclusions))
		fmt.Fprintf(out, "  8. Default exclusion config: %s\n", onOff(!o.Exclusions.noConfig))
		fmt.Fprintf(out, "  9. Low integrity: %s\n", onOff(o.LowIntegrity))
		fmt.Fprintln(out, "  b. Back")
		value, err := readLine(r, out, c, "Advanced", "b")
		if err != nil {
			return err
		}
		switch strings.ToLower(value) {
		case "", "b", "back":
			return nil
		case "1":
			top, err := askInt(r, out, c, "Top-N entries to keep in each list (0 disables)", o.TopN)
			if err != nil {
				return err
			}
			o.TopN = top
		case "2":
			workers, err := askInt(r, out, c, "Directory workers (0 = 2x logical CPUs)", o.Workers)
			if err != nil {
				return err
			}
			o.Workers = workers
		case "3", "4", "5", "6":
			labels := map[string][2]string{
				"3": {"Directory to exclude", "dirs"},
				"4": {"Glob pattern to exclude", "globs"},
				"5": {"File extension to exclude (for example .log)", "exts"},
				"6": {"Filename to exclude (for example Thumbs.db)", "names"},
			}[value]
			entry, err := readLine(r, out, c, labels[0], "")
			if err != nil {
				return err
			}
			entry = trimQuotes(strings.TrimSpace(entry))
			if entry != "" {
				switch labels[1] {
				case "dirs":
					o.Exclusions.dirs = append(o.Exclusions.dirs, entry)
				case "globs":
					o.Exclusions.globs = append(o.Exclusions.globs, entry)
				case "exts":
					o.Exclusions.exts = append(o.Exclusions.exts, entry)
				case "names":
					o.Exclusions.names = append(o.Exclusions.names, entry)
				}
			}
		case "7":
			path, err := readLine(r, out, c, "Exclusion file (blank keeps current)", o.Exclusions.config)
			if err != nil {
				return err
			}
			path = trimQuotes(strings.TrimSpace(path))
			if path != "" {
				o.Exclusions.config = path
			}
		case "8":
			o.Exclusions.noConfig = !o.Exclusions.noConfig
		case "9":
			low, err := askBool(
				r,
				out,
				c,
				"Lower the process to low integrity",
				"",
				"Low integrity limits what the process can write. Scoria never writes during a scan;\nwith this on, an HTML report file is not available, so output falls back to the console.",
				o.LowIntegrity,
			)
			if err != nil {
				return err
			}
			if low && o.HTML != "" && o.HTML != "-" {
				fmt.Fprintf(out, c.warning("Low integrity cannot write an HTML report file; switching output to console (%s).\n"), o.HTML)
				o.HTML = ""
				o.Open = false
			}
			o.LowIntegrity = low
		default:
			fmt.Fprintln(out, c.warning("Please enter a number from 1 to 9, or b to go back."))
		}
	}
}

func askAnalysis(r *bufio.Reader, out io.Writer, c *colorizer, defDupes, defAI bool) (bool, bool, error) {
	hint := "none"
	switch {
	case defDupes && defAI:
		hint = "1,2"
	case defDupes:
		hint = "1"
	case defAI:
		hint = "2"
	}
	for {
		value, err := readLine(r, out, c, "Extra analysis", hint)
		if err != nil {
			return false, false, err
		}
		if value == "" {
			return defDupes, defAI, nil
		}
		value = strings.ToLower(value)
		if value == "none" || value == "0" || value == "-" {
			return false, false, nil
		}
		var dupes, ai, invalid bool
		for _, part := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ' ' || r == '+'
		}) {
			switch part {
			case "1":
				dupes = true
			case "2":
				ai = true
			default:
				invalid = true
			}
		}
		if invalid {
			fmt.Fprintln(out, c.warning("Please enter 1, 2, 1,2, or none."))
			continue
		}
		return dupes, ai, nil
	}
}

func askProvider(r *bufio.Reader, out io.Writer, c *colorizer, current string) (string, error) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, c.heading("AI endpoint:"))
	for i, preset := range providerPresets {
		fmt.Fprintf(out, "  %d. %s (%s)\n", i+1, preset.name, preset.baseURL)
	}
	customIndex := len(providerPresets) + 1
	fmt.Fprintf(out, "  %d. Custom base URL\n", customIndex)
	choice, err := askMenu(r, out, c, "Provider", customIndex, providerIndexForBase(current))
	if err != nil {
		return "", err
	}
	if choice <= len(providerPresets) {
		return providerPresets[choice-1].baseURL, nil
	}
	hint := ""
	if current != "" && providerIndexForBase(current) == customIndex {
		hint = current
	}
	for {
		value, err := readLine(r, out, c, "Base URL", hint)
		if err != nil {
			return "", err
		}
		if value == "" {
			value = hint
		}
		if value == "" {
			fmt.Fprintln(out, c.warning("A base URL is required."))
			continue
		}
		if err := openrouter.ValidateBaseURL(value); err != nil {
			fmt.Fprintf(out, "%s %v\n", c.failure("Cannot use"), err)
			continue
		}
		return strings.TrimSpace(value), nil
	}
}

func askMenu(r *bufio.Reader, out io.Writer, c *colorizer, label string, max, def int) (int, error) {
	for {
		value, err := readLine(r, out, c, label, strconv.Itoa(def))
		if err != nil {
			return 0, err
		}
		if value == "" {
			return def, nil
		}
		n, err := strconv.Atoi(value)
		if err == nil && n >= 1 && n <= max {
			return n, nil
		}
		fmt.Fprintf(out, c.warning("Please enter a number from 1 to %d.\n"), max)
	}
}

func askRoot(r *bufio.Reader, out io.Writer, c *colorizer, label, def string, drives []driveChoice) (string, error) {
	fmt.Fprintln(out)
	for {
		value, err := readLine(r, out, c, label, def)
		if err != nil {
			return "", err
		}
		if value == "" {
			value = def
		}
		value = trimQuotes(value)
		if n, err := strconv.Atoi(value); err == nil && n >= 1 && n <= len(drives) {
			value = drives[n-1].root
		}
		if len(value) == 2 && value[1] == ':' {
			value += `\`
		}
		clean := filepath.Clean(value)
		abs, err := filepath.Abs(clean)
		if err != nil {
			fmt.Fprintf(out, "%s %q: %v\n", c.failure("Cannot use"), value, err)
			continue
		}
		info, err := os.Stat(abs)
		if err != nil {
			fmt.Fprintf(out, "%s %q: %v\n", c.failure("Cannot use"), value, err)
			continue
		}
		if !info.IsDir() {
			fmt.Fprintf(out, "%s %q: not a directory\n", c.failure("Cannot use"), value)
			continue
		}
		return clean, nil
	}
}

func askReportPath(r *bufio.Reader, out io.Writer, c *colorizer, def string) (string, error) {
	if def == "-" {
		return "-", nil
	}
	if def == "" {
		def = defaultReportPath()
	}
	for {
		value, err := readLine(r, out, c, "Report path", def)
		if err != nil {
			return "", err
		}
		if value == "" {
			value = def
		}
		value = trimQuotes(value)
		if value == "-" {
			return "-", nil
		}
		abs, err := filepath.Abs(filepath.Clean(value))
		if err != nil {
			fmt.Fprintf(out, "%s %q: %v\n", c.failure("Cannot use"), value, err)
			continue
		}
		parent, err := os.Stat(filepath.Dir(abs))
		if err != nil || !parent.IsDir() {
			fmt.Fprintf(out, "%s %q: directory does not exist\n", c.failure("Cannot use"), value)
			continue
		}
		info, err := os.Stat(abs)
		if err == nil && info.IsDir() {
			fmt.Fprintf(out, "%s %q: is a directory\n", c.failure("Cannot use"), value)
			continue
		}
		if err == nil {
			overwrite, err := askBool(
				r,
				out,
				c,
				"Report file already exists; overwrite it",
				"",
				"Y replaces the existing file at this path. n keeps it and asks for another path.",
				false,
			)
			if err != nil {
				return "", err
			}
			if !overwrite {
				continue
			}
		}
		return abs, nil
	}
}

func defaultReportPath() string {
	base, err := os.UserHomeDir()
	if err != nil || base == "" {
		if wd, err := os.Getwd(); err == nil {
			base = wd
		}
	}
	if base == "" {
		return "scoria-report.html"
	}
	path := filepath.Join(base, "scoria-report.html")
	if _, err := os.Stat(path); err == nil {
		path = filepath.Join(base, "scoria-report-"+time.Now().Format("20060102-150405")+".html")
	}
	return path
}

func askBool(r *bufio.Reader, out io.Writer, c *colorizer, label, detail, help string, def bool) (bool, error) {
	fmt.Fprintln(out)
	if detail != "" {
		fmt.Fprintln(out, c.heading(label+"?"))
		fmt.Fprintln(out, detail)
		fmt.Fprintln(out)
	}
	hint := "Y/n/?"
	if !def {
		hint = "y/N/?"
	}
	for {
		value, err := readLine(r, out, c, label, hint)
		if err != nil {
			return false, err
		}
		if value == "?" || strings.EqualFold(value, "help") {
			fmt.Fprintln(out)
			fmt.Fprintln(out, help)
			fmt.Fprintln(out)
			continue
		}
		switch strings.ToLower(value) {
		case "":
			return def, nil
		case "y", "yes", "true", "1":
			return true, nil
		case "n", "no", "false", "0":
			return false, nil
		default:
			fmt.Fprintln(out, c.warning("Please answer y or n."))
		}
	}
}

func askInt(r *bufio.Reader, out io.Writer, c *colorizer, label string, def int) (int, error) {
	fmt.Fprintln(out)
	for {
		value, err := readLine(r, out, c, label, strconv.Itoa(def))
		if err != nil {
			return 0, err
		}
		if value == "" {
			return def, nil
		}
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			fmt.Fprintln(out, c.warning("Please enter a non-negative integer."))
			continue
		}
		return n, nil
	}
}

func readLine(r *bufio.Reader, out io.Writer, c *colorizer, label, hint string) (string, error) {
	if hint != "" {
		fmt.Fprintf(out, "%s [%s]: ", c.accent(label), hint)
	} else {
		fmt.Fprintf(out, "%s: ", c.accent(label))
	}
	line, err := r.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && strings.TrimSpace(line) != "" {
			return strings.TrimSpace(line), nil
		}
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func printPlan(out io.Writer, c *colorizer, o wizardOptions) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, c.heading("Ready to scan"))
	fmt.Fprintf(out, "  %-12s %s\n", "Scan:", describeRoot(o.Root))
	mode := "standard (hard links counted)"
	if !o.CountLinks {
		mode = "fast (hard links not counted)"
	}
	fmt.Fprintf(out, "  %-12s %s\n", "Mode:", mode)
	duplicates := "off"
	if o.Dupes {
		duplicates = "verify (reads candidate contents >= 1 MiB)"
	}
	fmt.Fprintf(out, "  %-12s %s\n", "Duplicates:", duplicates)
	ai := "off"
	if o.AI {
		ai = o.Model + " via " + endpointLabel(o.BaseURL) + " (redacted payload)"
	}
	fmt.Fprintf(out, "  %-12s %s\n", "AI review:", ai)
	fmt.Fprintf(out, "  %-12s %s\n", "Output:", describeOutput(o))
	fmt.Fprintf(out, "  %-12s %s\n", "Exclusions:", describeExclusions(o.Exclusions))
	fmt.Fprintf(out, "  %-12s top %d, workers %s\n", "Advanced:", o.TopN, workerText(o.Workers))
	if o.LowIntegrity {
		fmt.Fprintf(out, "  %-12s low (HTML report file disabled)\n", "Integrity:")
	}
	fmt.Fprintln(out)
}

func describeRoot(root string) string {
	shown := root
	if abs, err := filepath.Abs(root); err == nil {
		shown = abs
	}
	if free := freeSpace(root); free != "" {
		shown += " (" + free + " free)"
	}
	return shown
}

func describeOutput(o wizardOptions) string {
	switch {
	case o.HTML == "-":
		return "HTML report to stdout"
	case o.HTML != "":
		text := "HTML report -> " + o.HTML
		if o.Open {
			text += " (opens in browser)"
		}
		return text
	case o.JSON:
		return "JSON digest to stdout"
	default:
		return "console summary"
	}
}

func describeExclusions(e exclusionFlags) string {
	parts := []string{"sensitive preset"}
	if n := customExclusionCount(e); n > 0 {
		parts = append(parts, customRuleText(n))
	}
	if e.config != "" {
		parts = append(parts, "file "+e.config)
	}
	if e.noConfig {
		parts = append(parts, "default config off")
	} else if e.config == "" {
		parts = append(parts, "default config on")
	}
	return strings.Join(parts, "; ")
}

func customExclusionCount(e exclusionFlags) int {
	return len(e.dirs) + len(e.globs) + len(e.exts) + len(e.names)
}

func customRuleText(n int) string {
	if n == 1 {
		return "1 custom rule"
	}
	return fmt.Sprintf("%d custom rules", n)
}

func exclusionFileText(e exclusionFlags) string {
	if e.config == "" {
		return "(none; default config applies)"
	}
	return e.config
}

func workerText(workers int) string {
	if workers == 0 {
		return "auto (2x CPUs)"
	}
	return strconv.Itoa(workers)
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

func freeSpace(path string) string {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	var available, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(name, &available, &total, &free); err != nil {
		return ""
	}
	if total == 0 {
		return ""
	}
	return humanBytes(int64(free))
}

type driveChoice struct {
	root  string
	label string
}

func listDrives() []driveChoice {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var drives []driveChoice
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		drives = append(drives, driveChoice{root: root, label: volumeLabel(root)})
	}
	return drives
}

func volumeLabel(root string) string {
	name, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return ""
	}
	var label [261]uint16
	var serial, maxComponent, flags uint32
	if err := windows.GetVolumeInformation(name, &label[0], uint32(len(label)), &serial, &maxComponent, &flags, nil, 0); err != nil {
		return ""
	}
	return windows.UTF16ToString(label[:])
}

func trimQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
