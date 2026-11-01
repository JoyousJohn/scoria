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
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	return enableConsoleVT(f)
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
