package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/JoyousJohn/scoria/internal/aggregate"
	"github.com/JoyousJohn/scoria/internal/exclude"
)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}
	*s = append(*s, value)
	return nil
}

type exclusionFlags struct {
	dirs     stringList
	globs    stringList
	exts     stringList
	names    stringList
	config   string
	noConfig bool
}

func buildExclusionRules(flags exclusionFlags) ([]exclude.Rule, []exclude.Rule, string, int, error) {
	all := exclude.DefaultRules()
	custom := make([]exclude.Rule, 0)

	for _, value := range flags.dirs {
		if !strings.Contains(value, "%") {
			absolute, err := filepath.Abs(value)
			if err != nil {
				return nil, nil, "", 0, fmt.Errorf("exclude: resolve %q: %w", value, err)
			}
			value = absolute
		}
		custom = append(custom, exclude.Rule{Kind: exclude.Subtree, Pattern: value})
	}
	for _, value := range flags.globs {
		custom = append(custom, exclude.Rule{Kind: exclude.Glob, Pattern: value})
	}
	for _, value := range flags.exts {
		custom = append(custom, exclude.Rule{Kind: exclude.Extension, Pattern: value})
	}
	for _, value := range flags.names {
		custom = append(custom, exclude.Rule{Kind: exclude.Name, Pattern: value})
	}

	configPath := flags.config
	if configPath == "" && !flags.noConfig {
		candidate, err := defaultExclusionFile()
		if err == nil {
			info, statErr := os.Stat(candidate)
			switch {
			case statErr == nil && info.Mode().IsRegular():
				configPath = candidate
			case statErr == nil:
				return nil, nil, "", 0, fmt.Errorf("exclude-config: %s is not a regular file", candidate)
			case !os.IsNotExist(statErr):
				return nil, nil, "", 0, fmt.Errorf("exclude-config: %w", statErr)
			}
		}
	}

	configRules := 0
	if configPath != "" {
		fromFile, err := loadExclusionFile(configPath)
		if err != nil {
			return nil, nil, "", 0, err
		}
		configRules = len(fromFile)
		custom = append(custom, fromFile...)
	}

	all = append(all, custom...)
	if _, err := exclude.Compile(all); err != nil {
		return nil, nil, "", 0, err
	}
	return all, custom, configPath, configRules, nil
}

func defaultExclusionFile() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "Scoria", "exclusions.txt"), nil
}

func loadExclusionFile(path string) ([]exclude.Rule, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("exclude-file: %w", err)
	}
	defer file.Close()

	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("exclude-file: %w", err)
	}
	return parseExclusionFile(file, filepath.Dir(absolute))
}

func parseExclusionFile(reader io.Reader, baseDir string) ([]exclude.Rule, error) {
	scanner := bufio.NewScanner(reader)
	rules := make([]exclude.Rule, 0)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		index := strings.IndexAny(line, " \t")
		verb := line
		value := ""
		if index >= 0 {
			verb = line[:index]
			value = strings.TrimSpace(line[index+1:])
		}
		value = trimQuotes(value)
		if value == "" {
			return nil, fmt.Errorf("exclude-file line %d: empty %s value", lineNumber, verb)
		}
		switch strings.ToLower(verb) {
		case "dir":
			if !strings.Contains(value, "%") {
				if !filepath.IsAbs(value) {
					value = filepath.Join(baseDir, value)
				}
				value = filepath.Clean(value)
			}
			rules = append(rules, exclude.Rule{Kind: exclude.Subtree, Pattern: value})
		case "glob":
			rules = append(rules, exclude.Rule{Kind: exclude.Glob, Pattern: value})
		case "ext":
			rules = append(rules, exclude.Rule{Kind: exclude.Extension, Pattern: value})
		case "name":
			rules = append(rules, exclude.Rule{Kind: exclude.Name, Pattern: value})
		default:
			return nil, fmt.Errorf("exclude-file line %d: unknown directive %q", lineNumber, verb)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("exclude-file: %w", err)
	}
	return rules, nil
}

func warnExclusionRules(out io.Writer, c *colorizer, custom []exclude.Rule, agg *aggregate.Aggregate) {
	matched := make(map[string]struct{}, len(agg.Excluded))
	for _, entry := range agg.Excluded {
		matched[entry.Kind+":"+entry.Rule] = struct{}{}
	}
	for _, rule := range custom {
		if _, ok := matched[rule.Key()]; !ok {
			fmt.Fprintf(out, "%s exclusion rule %q matched nothing\n", c.yellow("warning:"), rule.Pattern)
		}
	}
	if agg.Totals.Entries == 0 && len(agg.Excluded) > 0 {
		fmt.Fprintf(out, "%s exclusion rules excluded every entry; check the rules\n", c.yellow("warning:"))
	}
}
