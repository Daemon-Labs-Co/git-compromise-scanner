// Package scan takes inert bytes and a set of patterns and returns matches.
// It knows nothing about git, the network, or where the bytes came from.
//
// Safety: content is only ever matched against regular expressions. It is
// never executed, parsed as code, or deserialized.
package scan

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Pattern is a single indicator of compromise.
type Pattern struct {
	Name        string
	Regex       *regexp.Regexp
	Raw         string
	Severity    string
	Description string
}

// Match records one pattern hit within a piece of content.
type Match struct {
	PatternName string
	Severity    string
	Description string
	LineHint    int
}

// Scanner holds a compiled pattern set.
type Scanner struct {
	patterns []Pattern
}

// LoadPatterns reads a tab-delimited patterns file:
//
//	SEVERITY<tab>NAME<tab>REGEX<tab>DESCRIPTION
//
// Lines beginning with # and blank lines are ignored. REGEX uses Go
// regexp syntax (no shell escaping).
func LoadPatterns(path string) (*Scanner, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var patterns []Pattern
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) < 3 {
			return nil, fmt.Errorf("line %d: expected SEVERITY<tab>NAME<tab>REGEX[<tab>DESC], got %d fields", lineNum, len(parts))
		}
		raw := strings.TrimSpace(parts[2])
		re, err := regexp.Compile(raw)
		if err != nil {
			return nil, fmt.Errorf("line %d: bad regex %q: %v", lineNum, raw, err)
		}
		desc := ""
		if len(parts) >= 4 {
			desc = strings.TrimSpace(parts[3])
		}
		patterns = append(patterns, Pattern{
			Name:        strings.TrimSpace(parts[1]),
			Regex:       re,
			Raw:         raw,
			Severity:    strings.TrimSpace(parts[0]),
			Description: desc,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(patterns) == 0 {
		return nil, fmt.Errorf("no patterns loaded from %s", path)
	}
	return &Scanner{patterns: patterns}, nil
}

// Count returns the number of loaded patterns.
func (s *Scanner) Count() int { return len(s.patterns) }

// Scan matches all patterns against content and returns every hit.
func (s *Scanner) Scan(content []byte) []Match {
	var matches []Match
	for _, p := range s.patterns {
		if loc := p.Regex.FindIndex(content); loc != nil {
			matches = append(matches, Match{
				PatternName: p.Name,
				Severity:    p.Severity,
				Description: p.Description,
				LineHint:    lineNumber(content, loc[0]),
			})
		}
	}
	return matches
}

func lineNumber(content []byte, offset int) int {
	if offset < 0 || offset > len(content) {
		return 0
	}
	return bytes.Count(content[:offset], []byte("\n")) + 1
}
