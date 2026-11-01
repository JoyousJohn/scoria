package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/JoyousJohn/scoria/internal/digest"
)

const PayloadVersion = 1

type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, payload Payload) (Result, error)
}

type Payload struct {
	Version    int         `json:"version"`
	Scan       ScanSummary `json:"scan"`
	Extensions []Extension `json:"extensions,omitempty"`
	Candidates []Candidate `json:"candidates"`
}

type ScanSummary struct {
	Entries        uint64 `json:"entries"`
	UniqueFiles    uint64 `json:"unique_files"`
	Files          uint64 `json:"files"`
	Directories    uint64 `json:"directories"`
	LogicalBytes   int64  `json:"logical_bytes"`
	UniqueBytes    int64  `json:"unique_bytes"`
	EmptyFiles     uint64 `json:"empty_files"`
	HardlinkExtra  uint64 `json:"hardlink_extra_entries"`
	ContentsHashed bool   `json:"contents_hashed"`
}

type Extension struct {
	Ext   string `json:"ext"`
	Files uint64 `json:"files"`
	Bytes int64  `json:"bytes"`
}

type Candidate struct {
	ID         string `json:"id"`
	Rule       string `json:"rule"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	Confidence string `json:"confidence"`
	Priority   int    `json:"priority"`
	Items      uint64 `json:"items"`
	Bytes      int64  `json:"bytes"`
	SizeBucket string `json:"size_bucket"`
}

type Finding struct {
	ID          string `json:"id"`
	Rank        int    `json:"rank"`
	Explanation string `json:"explanation"`
}

type Result struct {
	Analyzer string    `json:"analyzer"`
	Model    string    `json:"model,omitempty"`
	Findings []Finding `json:"findings"`
}

type RulesOnly struct{}

func (RulesOnly) Name() string {
	return "rules-only"
}

func (RulesOnly) Analyze(_ context.Context, payload Payload) (Result, error) {
	findings := make([]Finding, 0, len(payload.Candidates))
	for i, candidate := range payload.Candidates {
		findings = append(findings, Finding{
			ID:          candidate.ID,
			Rank:        i + 1,
			Explanation: candidate.Title,
		})
	}
	return Result{Analyzer: "rules-only", Findings: findings}, nil
}

func Validate(payload Payload, result Result) (Result, error) {
	allowed := make(map[string]struct{}, len(payload.Candidates))
	for _, candidate := range payload.Candidates {
		allowed[candidate.ID] = struct{}{}
	}
	seenIDs := make(map[string]struct{}, len(result.Findings))
	seenRanks := make(map[int]struct{}, len(result.Findings))
	findings := make([]Finding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		id := strings.TrimSpace(finding.ID)
		if _, ok := allowed[id]; !ok {
			return Result{}, fmt.Errorf("analyzer returned unknown candidate ID %q", id)
		}
		if _, ok := seenIDs[id]; ok {
			return Result{}, fmt.Errorf("analyzer returned duplicate candidate ID %q", id)
		}
		if finding.Rank < 1 || finding.Rank > len(payload.Candidates) {
			return Result{}, fmt.Errorf("analyzer returned invalid rank %d", finding.Rank)
		}
		if _, ok := seenRanks[finding.Rank]; ok {
			return Result{}, fmt.Errorf("analyzer returned duplicate rank %d", finding.Rank)
		}
		explanation := strings.TrimSpace(finding.Explanation)
		if explanation == "" {
			return Result{}, fmt.Errorf("analyzer returned an empty explanation for %q", id)
		}
		if len(explanation) > 2000 {
			return Result{}, fmt.Errorf("analyzer explanation for %q is too long", id)
		}
		seenIDs[id] = struct{}{}
		seenRanks[finding.Rank] = struct{}{}
		findings = append(findings, Finding{ID: id, Rank: finding.Rank, Explanation: explanation})
	}
	if len(seenIDs) != len(allowed) {
		return Result{}, fmt.Errorf("analyzer returned %d of %d candidates", len(seenIDs), len(allowed))
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Rank < findings[j].Rank })
	result.Findings = findings
	return result, nil
}

func BuildPayload(doc *digest.Digest) Payload {
	payload := Payload{
		Version: PayloadVersion,
		Scan: ScanSummary{
			Entries:        doc.Totals.Entries,
			UniqueFiles:    doc.Totals.UniqueFiles,
			Files:          doc.Totals.Files,
			Directories:    doc.Totals.Directories,
			LogicalBytes:   doc.Totals.LogicalBytes,
			UniqueBytes:    doc.Totals.UniqueBytes,
			EmptyFiles:     doc.Totals.EmptyFiles,
			HardlinkExtra:  doc.Totals.HardlinkExtra,
			ContentsHashed: doc.DuplicateCheck != nil,
		},
		Extensions: make([]Extension, 0, min(len(doc.Extensions), 20)),
		Candidates: make([]Candidate, 0, len(doc.Recommendations)),
	}
	for _, extension := range doc.Extensions {
		if len(payload.Extensions) >= 20 {
			break
		}
		payload.Extensions = append(payload.Extensions, Extension{
			Ext:   extension.Ext,
			Files: extension.Files,
			Bytes: extension.Bytes,
		})
	}
	for _, recommendation := range doc.Recommendations {
		payload.Candidates = append(payload.Candidates, Candidate{
			ID:         recommendation.ID,
			Rule:       recommendation.Rule,
			Title:      recommendation.Title,
			Detail:     recommendation.Detail,
			Confidence: recommendation.Confidence,
			Priority:   recommendation.Priority,
			Items:      recommendation.Items,
			Bytes:      recommendation.Bytes,
			SizeBucket: sizeBucket(recommendation.Bytes),
		})
	}
	return payload
}

func sizeBucket(bytes int64) string {
	switch {
	case bytes <= 0:
		return "0"
	case bytes < 1<<20:
		return "<1 MiB"
	case bytes < 10<<20:
		return "1-10 MiB"
	case bytes < 100<<20:
		return "10-100 MiB"
	case bytes < 1<<30:
		return "100 MiB-1 GiB"
	case bytes < 10<<30:
		return "1-10 GiB"
	default:
		return ">=10 GiB"
	}
}
