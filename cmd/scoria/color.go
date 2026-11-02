package main

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

type colorizer struct {
	enabled bool
}

func validColorMode(mode string) bool {
	switch strings.ToLower(mode) {
	case "auto", "always", "never":
		return true
	default:
		return false
	}
}

func newColorizer(f *os.File, mode string) *colorizer {
	switch strings.ToLower(mode) {
	case "never":
		return &colorizer{}
	case "always":
		enableConsoleVT(f)
		return &colorizer{enabled: true}
	default:
		return &colorizer{enabled: autoColor(f)}
	}
}

func autoColor(f *os.File) bool {
	if colorDisabledByEnv() {
		return false
	}
	return enableConsoleVT(f)
}

func colorDisabledByEnv() bool {
	if os.Getenv("NO_COLOR") != "" {
		return true
	}
	return strings.EqualFold(os.Getenv("TERM"), "dumb")
}

func enableConsoleVT(f *os.File) bool {
	handle := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	if err := windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT); err != nil {
		return false
	}
	return true
}

func (c *colorizer) paint(code, s string) string {
	if c == nil || !c.enabled {
		return s
	}
	return code + s + "\x1b[0m"
}

func (c *colorizer) bold(s string) string {
	return c.paint("\x1b[1m", s)
}

func (c *colorizer) dim(s string) string {
	return c.paint("\x1b[2m", s)
}

func (c *colorizer) cyan(s string) string {
	return c.paint("\x1b[36m", s)
}

func (c *colorizer) yellow(s string) string {
	return c.paint("\x1b[33m", s)
}

func (c *colorizer) red(s string) string {
	return c.paint("\x1b[31m", s)
}

func (c *colorizer) success(s string) string {
	return c.paint("\x1b[32m", s)
}

func (c *colorizer) heading(s string) string {
	return c.bold(s)
}

func (c *colorizer) muted(s string) string {
	return c.dim(s)
}

func (c *colorizer) accent(s string) string {
	return c.cyan(s)
}

func (c *colorizer) warning(s string) string {
	return c.yellow(s)
}

func (c *colorizer) failure(s string) string {
	return c.red(s)
}
