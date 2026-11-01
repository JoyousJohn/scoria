package analyzer

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/JoyousJohn/scoria/internal/digest"
	"github.com/JoyousJohn/scoria/internal/junk"
	"github.com/JoyousJohn/scoria/internal/protected"
)

const DiscoveryVersion = 1

const maxDiscoveryNames = 200000

var discoveryBlocked = map[string]struct{}{
	".git": {},
	".svn": {},
	".hg":  {},
	".bzr": {},
}

func blockedDiscoveryName(name string) bool {
	_, ok := discoveryBlocked[strings.ToLower(name)]
	return ok
}

type DirectoryName struct {
	Name  string `json:"name"`
	Files uint64 `json:"files"`
	Bytes int64  `json:"bytes"`
}

type DiscoveryPayload struct {
	Version        int             `json:"version"`
	Scan           ScanSummary     `json:"scan"`
	ExistingRules  []string        `json:"existing_rules"`
	DirectoryNames []DirectoryName `json:"directory_names"`
	Extensions     []Extension     `json:"extensions,omitempty"`
}

type DiscoveryFinding struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Files      uint64 `json:"files"`
	Bytes      int64  `json:"bytes"`
	Confidence string `json:"confidence"`
	Reason     string `json:"reason"`
}

type DiscoveryResult struct {
	Analyzer string             `json:"analyzer"`
	Model    string             `json:"model,omitempty"`
	Patterns []DiscoveryFinding `json:"patterns"`
}

type DiscoveryCollector struct {
	root  string
	mu    sync.Mutex
	names map[string]*DirectoryName
}

func NewDiscoveryCollector(root string) *DiscoveryCollector {
	return &DiscoveryCollector{
		root:  filepath.Clean(root),
		names: make(map[string]*DirectoryName),
	}
}

func (c *DiscoveryCollector) Sink(path string, size int64, _ time.Time) {
	if protected.IsPath(path) {
		return
	}
	relative, err := filepath.Rel(c.root, path)
	if err != nil {
		return
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) < 2 {
		return
	}
	for _, part := range parts[:len(parts)-1] {
		if blockedDiscoveryName(part) {
			return
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 0; i < len(parts)-1; i++ {
		name := parts[i]
		if name == "" || name == "." || name == ".." {
			continue
		}
		entry := c.names[name]
		if entry == nil {
			if len(c.names) >= maxDiscoveryNames {
				continue
			}
			entry = &DirectoryName{Name: name}
			c.names[name] = entry
		}
		entry.Files++
		entry.Bytes += size
	}
}

func (c *DiscoveryCollector) Result(topN int) []DirectoryName {
	c.mu.Lock()
	names := make([]DirectoryName, 0, len(c.names))
	for _, entry := range c.names {
		names = append(names, *entry)
	}
	c.mu.Unlock()

	sort.Slice(names, func(i, j int) bool {
		if names[i].Bytes != names[j].Bytes {
			return names[i].Bytes > names[j].Bytes
		}
		if names[i].Files != names[j].Files {
			return names[i].Files > names[j].Files
		}
		return names[i].Name < names[j].Name
	})
	if topN > 0 && len(names) > topN {
		names = names[:topN]
	}
	return names
}

func BuildDiscoveryPayload(doc *digest.Digest, names []DirectoryName) DiscoveryPayload {
	payload := DiscoveryPayload{
		Version:        DiscoveryVersion,
		Scan:           scanSummary(doc),
		ExistingRules:  junk.Names(),
		DirectoryNames: make([]DirectoryName, 0, min(len(names), 100)),
		Extensions:     make([]Extension, 0, min(len(doc.Extensions), 20)),
	}
	for _, name := range names {
		if len(payload.DirectoryNames) >= 100 {
			break
		}
		if _, covered := junk.ClassifyDir(name.Name); covered {
			continue
		}
		payload.DirectoryNames = append(payload.DirectoryNames, name)
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
	return payload
}

func ValidateDiscovery(payload DiscoveryPayload, result DiscoveryResult) (DiscoveryResult, error) {
	allowed := make(map[string]DirectoryName, len(payload.DirectoryNames))
	for _, name := range payload.DirectoryNames {
		allowed[strings.ToLower(name.Name)] = name
	}
	seen := make(map[string]struct{}, len(result.Patterns))
	findings := make([]DiscoveryFinding, 0, len(result.Patterns))
	for _, pattern := range result.Patterns {
		if pattern.Kind != "dir-basename" {
			return DiscoveryResult{}, fmt.Errorf("discovery: unsupported pattern kind %q", pattern.Kind)
		}
		name := strings.TrimSpace(pattern.Name)
		if name == "" || strings.ContainsAny(name, `\/`) {
			return DiscoveryResult{}, fmt.Errorf("discovery: invalid directory name %q", pattern.Name)
		}
		if blockedDiscoveryName(name) {
			return DiscoveryResult{}, fmt.Errorf("discovery: %q is not a discovery candidate", name)
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			return DiscoveryResult{}, fmt.Errorf("discovery: duplicate directory name %q", name)
		}
		if _, ok := junk.ClassifyDir(name); ok {
			return DiscoveryResult{}, fmt.Errorf("discovery: %q is already covered by a built-in rule", name)
		}
		stat, ok := allowed[key]
		if !ok {
			return DiscoveryResult{}, fmt.Errorf("discovery: unknown directory name %q", name)
		}
		confidence := strings.ToLower(strings.TrimSpace(pattern.Confidence))
		if confidence != "low" && confidence != "medium" && confidence != "high" {
			return DiscoveryResult{}, fmt.Errorf("discovery: invalid confidence %q", pattern.Confidence)
		}
		reason := strings.TrimSpace(pattern.Reason)
		if reason == "" {
			return DiscoveryResult{}, fmt.Errorf("discovery: empty reason for %q", name)
		}
		if len(reason) > 500 {
			return DiscoveryResult{}, fmt.Errorf("discovery: reason for %q is too long", name)
		}
		seen[key] = struct{}{}
		findings = append(findings, DiscoveryFinding{
			Kind:       "dir-basename",
			Name:       stat.Name,
			Files:      stat.Files,
			Bytes:      stat.Bytes,
			Confidence: confidence,
			Reason:     reason,
		})
	}
	if len(findings) > 20 {
		return DiscoveryResult{}, fmt.Errorf("discovery: too many patterns")
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Bytes != findings[j].Bytes {
			return findings[i].Bytes > findings[j].Bytes
		}
		if findings[i].Files != findings[j].Files {
			return findings[i].Files > findings[j].Files
		}
		return findings[i].Name < findings[j].Name
	})
	result.Patterns = findings
	return result, nil
}
