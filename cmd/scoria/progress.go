package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/JoyousJohn/scoria/internal/scan"
)

type progressLine struct {
	out     io.Writer
	enabled bool
	width   int
	label   string
}

func validProgressMode(mode string) bool {
	switch strings.ToLower(mode) {
	case "auto", "always", "never":
		return true
	default:
		return false
	}
}

func progressEnabled(mode string, f *os.File) bool {
	switch strings.ToLower(mode) {
	case "never":
		return false
	case "always":
		return true
	default:
		return isConsole(f)
	}
}

func isConsole(f *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}

func (p *progressLine) update(pr scan.Progress) {
	if p == nil || !p.enabled {
		return
	}
	label := p.label
	if label == "" {
		label = "scanned"
	}
	line := fmt.Sprintf(
		"%s %s entries in %s (%s/s)",
		label,
		commas(pr.Entries),
		formatElapsed(pr.Elapsed),
		commasFloat(pr.EntriesPerSecond),
	)
	if len(line) < p.width {
		line += strings.Repeat(" ", p.width-len(line))
	}
	p.width = len(line)
	fmt.Fprintf(p.out, "\r%s", line)
}

func (p *progressLine) finish() {
	if p == nil || !p.enabled || p.width == 0 {
		return
	}
	fmt.Fprintf(p.out, "\r%s\r", strings.Repeat(" ", p.width))
	p.width = 0
}

func formatElapsed(d time.Duration) string {
	return d.Round(100 * time.Millisecond).String()
}
