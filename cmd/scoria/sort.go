package main

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/JoyousJohn/scoria/internal/rules"
)

func validSortMode(mode string) bool {
	switch strings.ToLower(mode) {
	case "priority", "size":
		return true
	default:
		return false
	}
}

func sortRecommendations(recs []rules.Recommendation, mode string) {
	sizeFirst := strings.EqualFold(mode, "size")
	sort.SliceStable(recs, func(i, j int) bool {
		a, b := recs[i], recs[j]
		if sizeFirst {
			if a.Bytes != b.Bytes {
				return a.Bytes > b.Bytes
			}
			if a.Priority != b.Priority {
				return a.Priority > b.Priority
			}
		} else {
			if a.Priority != b.Priority {
				return a.Priority > b.Priority
			}
			if a.Bytes != b.Bytes {
				return a.Bytes > b.Bytes
			}
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Title < b.Title
	})
}

func runSortMenu(
	r *bufio.Reader,
	out io.Writer,
	promptOut io.Writer,
	outColor *colorizer,
	promptColor *colorizer,
	recs []rules.Recommendation,
	contentsRead bool,
	initialMode string,
) {
	if len(recs) == 0 {
		return
	}
	mode := initialMode
	for {
		value, err := readLine(
			r,
			promptOut,
			promptColor,
			fmt.Sprintf("Sort recommendations (current: %s; p/s/q)", mode),
			"",
		)
		if err != nil {
			return
		}
		switch strings.ToLower(value) {
		case "", "q", "quit":
			return
		case "p", "priority":
			mode = "priority"
		case "s", "size":
			mode = "size"
		default:
			fmt.Fprintln(promptOut, promptColor.yellow("Please enter p, s, or q."))
			continue
		}
		sortRecommendations(recs, mode)
		fmt.Fprintf(out, "\nsorted by %s\n", mode)
		printRecommendations(out, outColor, recs, contentsRead)
	}
}
