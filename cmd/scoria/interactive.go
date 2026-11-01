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

	"golang.org/x/sys/windows"

	"github.com/JoyousJohn/scoria/internal/scan"
)

func promptOptions(r *bufio.Reader, out io.Writer, c *colorizer, defaults scan.Options, jsonDefault bool) (scan.Options, bool, error) {
	fmt.Fprintln(out, c.bold("Scoria interactive setup (press Enter to accept the value in brackets)"))
	fmt.Fprintln(out)

	drives := listDrives()
	if len(drives) > 0 {
		fmt.Fprintln(out, c.bold("Available drives:"))
		for i, d := range drives {
			if d.label != "" {
				fmt.Fprintf(out, "  %d. %-4s %s\n", i+1, d.root, c.dim(d.label))
			} else {
				fmt.Fprintf(out, "  %d. %s\n", i+1, d.root)
			}
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintln(out, c.dim("Enter a number, a directory path, or press Enter for the current directory."))
	root, err := askRoot(r, out, c, "Root directory", defaults.Root, drives)
	if err != nil {
		return defaults, jsonDefault, err
	}
	links, err := askBool(
		r,
		out,
		c,
		"Count hard links and unique files",
		"  On by default. Dedupes hard links by file ID for accurate totals. Opens each\n  file read-only (metadata only, no contents) and is noticeably slower.",
		`A hard link is a second name for the same file data. Counting directory entries
alone counts the same bytes more than once. With this on, Scoria opens each file
read-only and asks Windows for its file ID and link count, so "unique files" and
"unique bytes" are accurate.

It does not read file contents. It does not open cloud placeholders (those are
counted separately). It makes the scan noticeably slower - often 2-4x on a warm
tree - because it opens every file.

Y = accurate entries + unique totals (slower)
n = entries only; unique files/bytes are reported as not computed (faster)`,
		defaults.CountLinks,
	)
	if err != nil {
		return defaults, jsonDefault, err
	}
	top, err := askInt(
		r,
		out,
		c,
		"Top-N entries to keep in each largest/oldest list (0 disables; does not limit the scan)",
		defaults.TopN,
	)
	if err != nil {
		return defaults, jsonDefault, err
	}
	workers, err := askInt(
		r,
		out,
		c,
		"Directory workers (0 = 2x logical CPUs; one directory per worker)",
		defaults.Workers,
	)
	if err != nil {
		return defaults, jsonDefault, err
	}
	jsonOut, err := askFormat(r, out, c, jsonDefault)
	if err != nil {
		return defaults, jsonDefault, err
	}

	opts := defaults
	opts.Root = root
	opts.CountLinks = links
	opts.TopN = top
	opts.Workers = workers
	return opts, jsonOut, nil
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
			fmt.Fprintf(out, "%s %q: %v\n", c.red("Cannot use"), value, err)
			continue
		}
		info, err := os.Stat(abs)
		if err != nil {
			fmt.Fprintf(out, "%s %q: %v\n", c.red("Cannot use"), value, err)
			continue
		}
		if !info.IsDir() {
			fmt.Fprintf(out, "%s %q: not a directory\n", c.red("Cannot use"), value)
			continue
		}
		return clean, nil
	}
}

func askBool(r *bufio.Reader, out io.Writer, c *colorizer, label, detail, help string, def bool) (bool, error) {
	fmt.Fprintln(out)
	if detail != "" {
		fmt.Fprintln(out, c.bold(label+"?"))
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
			fmt.Fprintln(out, c.yellow("Please answer y or n."))
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
			fmt.Fprintln(out, c.yellow("Please enter a non-negative integer."))
			continue
		}
		return n, nil
	}
}

func askFormat(r *bufio.Reader, out io.Writer, c *colorizer, jsonDefault bool) (bool, error) {
	fmt.Fprintln(out)
	hint := "1"
	if jsonDefault {
		hint = "2"
	}
	for {
		value, err := readLine(r, out, c, "Output: (1) console (2) JSON", hint)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(value) {
		case "":
			return jsonDefault, nil
		case "1", "console":
			return false, nil
		case "2", "json":
			return true, nil
		default:
			fmt.Fprintln(out, c.yellow("Please enter 1 for console or 2 for JSON."))
		}
	}
}

func readLine(r *bufio.Reader, out io.Writer, c *colorizer, label, hint string) (string, error) {
	if hint != "" {
		fmt.Fprintf(out, "%s [%s]: ", c.cyan(label), hint)
	} else {
		fmt.Fprintf(out, "%s: ", c.cyan(label))
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
