package exclude

import (
	"fmt"
	"os"
	"path"
	"strings"
)

type Kind string

const (
	Subtree   Kind = "directory-subtree"
	Glob      Kind = "glob"
	Extension Kind = "extension"
)

type Rule struct {
	Kind      Kind
	Pattern   string
	Label     string
	Sensitive bool
}

func (r Rule) Key() string {
	label := r.Label
	if label == "" {
		label = r.Pattern
	}
	return string(r.Kind) + ":" + label
}

type compiled struct {
	rule    Rule
	value   string
	literal bool
}

type Matcher struct {
	subtrees   []compiled
	globs      []compiled
	extensions []compiled
	pathGlobs  bool
}

func Compile(rules []Rule) (*Matcher, error) {
	m := &Matcher{}
	for _, rule := range rules {
		if rule.Label == "" {
			rule.Label = rule.Pattern
		}
		switch rule.Kind {
		case Subtree:
			expanded, ok := expandEnv(rule.Pattern)
			if !ok {
				continue
			}
			value := normalizePath(expanded)
			if value == "" {
				continue
			}
			if !isAbsPath(expanded) {
				return nil, fmt.Errorf("exclude: subtree rule %q is not absolute", rule.Pattern)
			}
			m.subtrees = append(m.subtrees, compiled{rule: rule, value: value})
		case Extension:
			value := strings.ToLower(strings.TrimSpace(rule.Pattern))
			if value == "" {
				return nil, fmt.Errorf("exclude: empty extension rule")
			}
			if !strings.HasPrefix(value, ".") {
				value = "." + value
			}
			if value == "." {
				return nil, fmt.Errorf("exclude: invalid extension rule %q", rule.Pattern)
			}
			m.extensions = append(m.extensions, compiled{rule: rule, value: value})
		case Glob:
			value := strings.ToLower(strings.ReplaceAll(rule.Pattern, `\`, "/"))
			if value == "" {
				return nil, fmt.Errorf("exclude: empty glob rule")
			}
			if _, err := path.Match(value, ""); err != nil {
				return nil, fmt.Errorf("exclude: bad glob %q: %w", rule.Pattern, err)
			}
			literal := !strings.ContainsAny(value, "*?[")
			if strings.Contains(value, "/") {
				m.pathGlobs = true
			}
			m.globs = append(m.globs, compiled{rule: rule, value: value, literal: literal})
		default:
			return nil, fmt.Errorf("exclude: unknown rule kind %q", rule.Kind)
		}
	}
	return m, nil
}

func (m *Matcher) NeedsRelPath() bool {
	return m.pathGlobs
}

func (m *Matcher) MatchDir(absPath, relPath string) (Rule, bool) {
	normalized := normalizePath(absPath)
	for _, c := range m.subtrees {
		if within(normalized, c.value) {
			return c.rule, true
		}
	}
	if len(m.globs) == 0 {
		return Rule{}, false
	}
	base := absPath
	if i := strings.LastIndexAny(base, `\/`); i >= 0 {
		base = base[i+1:]
	}
	rel := normalizeSlashes(relPath)
	for _, c := range m.globs {
		if matchGlob(c, base, rel) {
			return c.rule, true
		}
	}
	return Rule{}, false
}

func (m *Matcher) MatchFile(name, ext, relPath string) (Rule, bool) {
	for _, c := range m.extensions {
		if ext == c.value {
			return c.rule, true
		}
	}
	if len(m.globs) == 0 {
		return Rule{}, false
	}
	rel := normalizeSlashes(relPath)
	for _, c := range m.globs {
		if matchGlob(c, name, rel) {
			return c.rule, true
		}
	}
	return Rule{}, false
}

func matchGlob(c compiled, base, rel string) bool {
	if c.literal {
		if strings.EqualFold(base, c.value) {
			return true
		}
		return rel != "" && strings.EqualFold(rel, c.value)
	}
	lowerBase := strings.ToLower(base)
	if ok, _ := path.Match(c.value, lowerBase); ok {
		return true
	}
	if rel == "" {
		return false
	}
	ok, _ := path.Match(c.value, strings.ToLower(rel))
	return ok
}

func within(candidate, root string) bool {
	if candidate == root {
		return true
	}
	return strings.HasPrefix(candidate, root+`\`)
}

func normalizePath(p string) string {
	switch {
	case strings.HasPrefix(p, `\\?\UNC\`):
		p = `\\` + p[len(`\\?\UNC\`):]
	case strings.HasPrefix(p, `\\?\`):
		p = p[len(`\\?\`):]
	}
	p = strings.ReplaceAll(p, "/", `\`)
	p = strings.TrimRight(p, `\`)
	return strings.ToLower(p)
}

func normalizeSlashes(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	return strings.TrimPrefix(p, "./")
}

func isAbsPath(p string) bool {
	if strings.HasPrefix(p, `\\`) {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

func expandEnv(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '%' {
			if j := strings.IndexByte(s[i+1:], '%'); j >= 0 {
				name := s[i+1 : i+1+j]
				value, ok := os.LookupEnv(name)
				if !ok || value == "" {
					return "", false
				}
				b.WriteString(value)
				i += j + 2
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), true
}
