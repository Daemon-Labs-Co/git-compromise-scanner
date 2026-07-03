package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAllowlistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.txt")

	al := NewAllowlist()
	al.Add("bbbb000000000000000000000000000000000000")
	al.Add("aaaa000000000000000000000000000000000000")
	if err := al.Save(path); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, sha := range []string{
		"aaaa000000000000000000000000000000000000",
		"bbbb000000000000000000000000000000000000",
	} {
		if !loaded.Has(sha) {
			t.Errorf("round-trip lost SHA %s", sha)
		}
	}
	if loaded.Has("cccc000000000000000000000000000000000000") {
		t.Error("Has() returned true for a SHA that was never added")
	}

	// Saved file must be sorted and carry a comment header.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	if !strings.HasPrefix(content, "#") {
		t.Error("saved allowlist should start with a comment header")
	}
	if strings.Index(content, "aaaa") > strings.Index(content, "bbbb") {
		t.Error("saved SHAs are not sorted")
	}
}

func TestLoadAllowlistParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.txt")
	content := strings.Join([]string{
		"# header comment",
		"",
		"aaaa000000000000000000000000000000000000",
		"bbbb000000000000000000000000000000000000  reviewed 2026-07-02, vendored jquery",
		"cccc000000000000000000000000000000000000\tnote after a tab",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	al, err := LoadAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, sha := range []string{
		"aaaa000000000000000000000000000000000000",
		"bbbb000000000000000000000000000000000000",
		"cccc000000000000000000000000000000000000",
	} {
		if !al.Has(sha) {
			t.Errorf("missing SHA %s (trailing notes should be stripped)", sha)
		}
	}
}

func TestLoadAllowlistMissingFile(t *testing.T) {
	al, err := LoadAllowlist(filepath.Join(t.TempDir(), "does-not-exist.txt"))
	if err != nil {
		t.Fatalf("missing file must not be an error, got %v", err)
	}
	if al.Has("anything") {
		t.Error("empty allowlist should contain nothing")
	}
}

func TestWriteJSONNormalizesNilSlices(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, &Report{RepoPath: "/some/repo"}); err != nil {
		t.Fatal(err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, key := range []string{"blob_findings", "meta_anomalies", "remote_findings"} {
		v, ok := decoded[key]
		if !ok {
			t.Errorf("missing key %q", key)
			continue
		}
		if _, isArray := v.([]interface{}); !isArray {
			t.Errorf("%q should be a JSON array, got %T (nil slice not normalized)", key, v)
		}
	}
}

func TestWriteTextCleanReport(t *testing.T) {
	var buf bytes.Buffer
	WriteText(&buf, &Report{RepoPath: "/some/repo", TotalCommits: 3})
	out := buf.String()

	if !strings.Contains(out, "/some/repo") {
		t.Error("summary should include the repo path")
	}
	if !strings.Contains(out, "[OK]") || !strings.Contains(out, "does NOT guarantee") {
		t.Error("clean report should print the [OK] line with the no-guarantee caveat")
	}
}

func TestWriteTextWithFindings(t *testing.T) {
	r := &Report{
		RepoPath: "/some/repo",
		BlobFindings: []BlobFinding{{
			BlobSHA:     "abcdef0123456789abcdef0123456789abcdef01",
			Paths:       []string{"index.js"},
			Commits:     []string{"c1", "c2", "c3", "c4", "c5", "c6", "c7"},
			PatternName: "curl-pipe-shell",
			Severity:    "CRITICAL",
			Description: "remote script piped to shell",
		}},
		MetaAnomalies: []MetaAnomaly{{
			Commit: "1111111111111111111111111111111111111111",
			AuthorName: "Eve", AuthorEmail: "eve@attacker.example",
			TZMismatch: true,
		}},
		RemoteFindings: []RemoteFinding{{
			Name: "evil", Version: "6.6.6", Host: "c2.malicious.example",
			Reason: "blocklisted", Severity: "CRITICAL", Checked: false,
		}},
	}

	var buf bytes.Buffer
	WriteText(&buf, r)
	out := buf.String()

	for _, want := range []string{
		"IOC MATCHES", "curl-pipe-shell", "index.js", "(+2 more)", // 7 commits, 5 shown
		"COMMIT METADATA ANOMALIES", "TZ-MISMATCH", "eve@attacker.example",
		"EXTERNAL REFERENCE FINDINGS", "c2.malicious.example",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "[OK]") {
		t.Error("report with findings must not print the [OK] line")
	}
}

func TestShort(t *testing.T) {
	if got := short("abcdef0123456789abcdef01"); got != "abcdef012345" {
		t.Errorf("short() = %q", got)
	}
	if got := short("abc"); got != "abc" {
		t.Errorf("short() should pass short strings through, got %q", got)
	}
}
