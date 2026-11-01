package rules

import (
	"fmt"
	"sort"
	"time"

	"github.com/JoyousJohn/scoria/internal/aggregate"
	"github.com/JoyousJohn/scoria/internal/dupes"
	"github.com/JoyousJohn/scoria/internal/junk"
	"github.com/JoyousJohn/scoria/internal/protected"
)

type Confidence string

const (
	Low    Confidence = "low"
	Medium Confidence = "medium"
	High   Confidence = "high"
)

type Recommendation struct {
	ID         string
	Rule       string
	Title      string
	Detail     string
	Confidence Confidence
	Priority   int
	Items      uint64
	Bytes      int64
	Examples   []string
}

const (
	PriorityVerifiedDuplicates  = 100
	PriorityJunkDir             = 80
	PriorityJunkExtension       = 60
	PriorityDuplicateCandidates = 40
	PriorityOldFile             = 20
	PriorityLargeFile           = 10
)

func priorityForRule(rule string) int {
	switch rule {
	case "verified-duplicates":
		return PriorityVerifiedDuplicates
	case "junk-dir":
		return PriorityJunkDir
	case "junk-extension":
		return PriorityJunkExtension
	case "duplicate-candidates":
		return PriorityDuplicateCandidates
	case "old-file":
		return PriorityOldFile
	default:
		return PriorityLargeFile
	}
}

type Options struct {
	Now               time.Time
	LargeFileBytes    int64
	MinOldFileBytes   int64
	MinGroupBytes     int64
	StaleAfter        time.Duration
	MaxFileCandidates int
	DuplicateCheck    *dupes.Result
}

func DefaultOptions() Options {
	return Options{
		Now:               time.Now(),
		LargeFileBytes:    100 << 20,
		MinOldFileBytes:   1 << 20,
		MinGroupBytes:     1 << 20,
		StaleAfter:        2 * 365 * 24 * time.Hour,
		MaxFileCandidates: 5,
	}
}

func Analyze(root string, agg *aggregate.Aggregate, opts Options) []Recommendation {
	opts = withDefaults(opts)
	recs := make([]Recommendation, 0)
	pathless := !protected.IsPath(root) && !protected.IsDriveRoot(root)

	for _, j := range agg.Junk {
		if j.Files == 0 || j.Bytes < opts.MinGroupBytes {
			continue
		}
		if j.Example != "" && protected.IsPath(absolute(root, j.Example)) {
			continue
		}
		rec := Recommendation{
			Rule:       "junk-dir",
			Title:      "Generated directory: " + j.Kind,
			Detail:     "Looks like dependency, cache, or build output. Verify you have no local changes you need before removing anything.",
			Confidence: junkConfidence(j.Kind),
			Items:      j.Files,
			Bytes:      j.Bytes,
		}
		if j.Example != "" {
			rec.Examples = []string{j.Example}
		}
		recs = append(recs, rec)
	}

	largest := 0
	for _, f := range agg.Largest {
		if largest >= opts.MaxFileCandidates {
			break
		}
		if f.Size < opts.LargeFileBytes {
			continue
		}
		if protected.IsPath(absolute(root, f.Path)) {
			continue
		}
		recs = append(recs, Recommendation{
			Rule:       "large-file",
			Title:      "Large file",
			Detail:     "Size alone is not a reason to remove a file. Confirm it is still needed.",
			Confidence: Low,
			Items:      1,
			Bytes:      f.Size,
			Examples:   []string{f.Path},
		})
		largest++
	}

	old := 0
	for _, f := range agg.Stalest {
		if old >= opts.MaxFileCandidates {
			break
		}
		if f.ModTime.IsZero() || f.Size < opts.MinOldFileBytes {
			continue
		}
		age := opts.Now.Sub(f.ModTime)
		if age < opts.StaleAfter {
			continue
		}
		if protected.IsPath(absolute(root, f.Path)) {
			continue
		}
		recs = append(recs, Recommendation{
			Rule:  "old-file",
			Title: "Old file",
			Detail: fmt.Sprintf(
				"Last written about %.1f years ago. Verify it is still needed; age alone is not proof.",
				age.Hours()/24/365.25,
			),
			Confidence: Low,
			Items:      1,
			Bytes:      f.Size,
			Examples:   []string{f.Path},
		})
		old++
	}

	if pathless {
		tempExtensions := map[string]Confidence{
			".tmp":        Medium,
			".temp":       Medium,
			".part":       Medium,
			".crdownload": Medium,
			".dmp":        Low,
		}
		for _, e := range agg.Extensions {
			confidence, ok := tempExtensions[e.Ext]
			if !ok || e.Bytes < opts.MinGroupBytes {
				continue
			}
			recs = append(recs, Recommendation{
				Rule:       "junk-extension",
				Title:      "Temporary-file extension: " + e.Ext,
				Detail:     "Temporary, partial-download, or crash-dump extension. Extension alone is not proof of ownership; inspect before removing.",
				Confidence: confidence,
				Items:      e.Files,
				Bytes:      e.Bytes,
			})
		}

	}

	if opts.DuplicateCheck != nil {
		for _, g := range opts.DuplicateCheck.Groups {
			if g.Wasted < opts.MinGroupBytes {
				continue
			}
			recs = append(recs, Recommendation{
				Rule:       "verified-duplicates",
				Title:      "Verified duplicate group",
				Detail:     fmt.Sprintf("%d files have identical contents. Decide which copy to keep.", g.Count),
				Confidence: High,
				Items:      uint64(g.Count),
				Bytes:      g.Wasted,
				Examples:   g.Paths,
			})
		}
	} else if pathless {
		var groups, duplicates uint64
		var excess int64
		for _, sc := range agg.SizeCounts {
			if sc.Size <= 0 || sc.Count < 2 {
				continue
			}
			groups++
			duplicates += sc.Count - 1
			excess += int64(sc.Count-1) * sc.Size
		}
		if groups > 0 && excess >= opts.MinGroupBytes {
			detail := fmt.Sprintf("%d size groups share a size. Contents were not compared; treat this as a lead only.", groups)
			if groups == 1 {
				detail = "1 size group shares a size. Contents were not compared; treat this as a lead only."
			}
			recs = append(recs, Recommendation{
				Rule:       "duplicate-candidates",
				Title:      "Possible duplicate candidates",
				Detail:     detail,
				Confidence: Low,
				Items:      duplicates,
				Bytes:      excess,
			})
		}
	}

	for i := range recs {
		recs[i].Priority = priorityForRule(recs[i].Rule)
	}
	sort.Slice(recs, func(i, j int) bool {
		if recs[i].Priority != recs[j].Priority {
			return recs[i].Priority > recs[j].Priority
		}
		if recs[i].Bytes != recs[j].Bytes {
			return recs[i].Bytes > recs[j].Bytes
		}
		if recs[i].Rule != recs[j].Rule {
			return recs[i].Rule < recs[j].Rule
		}
		return recs[i].Title < recs[j].Title
	})
	for i := range recs {
		recs[i].ID = fmt.Sprintf("c%d", i+1)
	}
	return recs
}

func withDefaults(opts Options) Options {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if opts.LargeFileBytes <= 0 {
		opts.LargeFileBytes = 100 << 20
	}
	if opts.MinOldFileBytes <= 0 {
		opts.MinOldFileBytes = 1 << 20
	}
	if opts.MinGroupBytes <= 0 {
		opts.MinGroupBytes = 1 << 20
	}
	if opts.StaleAfter <= 0 {
		opts.StaleAfter = 2 * 365 * 24 * time.Hour
	}
	if opts.MaxFileCandidates <= 0 {
		opts.MaxFileCandidates = 5
	}
	return opts
}

func junkConfidence(kind string) Confidence {
	if junk.IsGenerated(kind) {
		return Low
	}
	switch kind {
	case junk.Cache:
		return Low
	default:
		return Medium
	}
}
