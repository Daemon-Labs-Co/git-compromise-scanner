// Package report aggregates findings from every other module into a
// single result, and manages the known-good blob allowlist.
//
// The allowlist is a persisted set of blob SHAs that have been scanned
// and judged clean. Because a git blob SHA is a content checksum, an
// allowlisted SHA means "this exact file content was reviewed and is
// safe." On future scans, matching content is skipped (faster) and any
// content drift from an expected SHA can be flagged (integrity).
package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// BlobFinding is an IOC match against a unique blob, with attribution.
type BlobFinding struct {
	BlobSHA     string   `json:"blob_sha"`
	Paths       []string `json:"paths"`
	Commits     []string `json:"commits,omitempty"`
	PatternName string   `json:"pattern_name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	LineHint    int      `json:"line_hint,omitempty"`
}

// MetaAnomaly is a commit with forged-metadata indicators.
type MetaAnomaly struct {
	Commit      string `json:"commit"`
	AuthorName  string `json:"author_name"`
	AuthorEmail string `json:"author_email"`
	AuthorDate  string `json:"author_date"`
	CommitDate  string `json:"commit_date"`
	AuthorTZ    string `json:"author_tz"`
	CommitTZ    string `json:"commit_tz"`
	Subject     string `json:"subject"`
	TZMismatch  bool   `json:"tz_mismatch"`
	DateAnomaly bool   `json:"date_anomaly"`
}

// RemoteFinding mirrors a remote.Finding for the report (kept local to
// avoid a hard dependency cycle; the cmd layer adapts between them).
type RemoteFinding struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	URL      string `json:"url"`
	Host     string `json:"host"`
	Reason   string `json:"reason"`
	Severity string `json:"severity"`
	Checked  bool   `json:"checked"`
}

// Report is the full aggregated result for one repository.
type Report struct {
	RepoPath       string          `json:"repo_path"`
	ScanTime       string          `json:"scan_time"`
	TotalCommits   int             `json:"total_commits"`
	UniqueBlobs    int             `json:"unique_blobs"`
	BlobsScanned   int             `json:"blobs_scanned"`
	BlobsSkipped   int             `json:"blobs_skipped_allowlisted"`
	BlobFindings   []BlobFinding   `json:"blob_findings"`
	MetaAnomalies  []MetaAnomaly   `json:"meta_anomalies"`
	RemoteFindings []RemoteFinding `json:"remote_findings"`
	Duration       string          `json:"duration"`
}

// ---------- allowlist (known-good SHA store) ----------

// Allowlist is a set of blob SHAs known to be clean.
type Allowlist struct {
	shas map[string]bool
}

// NewAllowlist returns an empty allowlist.
func NewAllowlist() *Allowlist {
	return &Allowlist{shas: map[string]bool{}}
}

// LoadAllowlist reads a known-good SHA file (one SHA per line, # comments
// allowed). A missing file is not an error; it yields an empty allowlist.
func LoadAllowlist(path string) (*Allowlist, error) {
	al := NewAllowlist()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return al, nil
		}
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// allow "sha  optional note"
		if i := strings.IndexAny(line, " \t"); i >= 0 {
			line = line[:i]
		}
		al.shas[line] = true
	}
	return al, sc.Err()
}

// Has reports whether a SHA is allowlisted.
func (a *Allowlist) Has(sha string) bool { return a.shas[sha] }

// Add records a SHA as known-good.
func (a *Allowlist) Add(sha string) { a.shas[sha] = true }

// Save writes the allowlist back to disk, sorted, with a header.
func (a *Allowlist) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	shas := make([]string, 0, len(a.shas))
	for s := range a.shas {
		shas = append(shas, s)
	}
	sort.Strings(shas)

	w := bufio.NewWriter(f)
	fmt.Fprintf(w, "# git-compromise-scanner known-good blob allowlist\n")
	fmt.Fprintf(w, "# generated %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "# one blob SHA per line; these contents were scanned and judged clean\n")
	for _, s := range shas {
		fmt.Fprintln(w, s)
	}
	return w.Flush()
}

// ---------- output ----------

// WriteJSON emits the report as indented JSON.
func WriteJSON(w io.Writer, r *Report) error {
	if r.BlobFindings == nil {
		r.BlobFindings = []BlobFinding{}
	}
	if r.MetaAnomalies == nil {
		r.MetaAnomalies = []MetaAnomaly{}
	}
	if r.RemoteFindings == nil {
		r.RemoteFindings = []RemoteFinding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText emits a human-readable summary to w.
func WriteText(w io.Writer, r *Report) {
	p := func(format string, a ...interface{}) { fmt.Fprintf(w, format+"\n", a...) }

	p("=====================================")
	p("  SCAN COMPLETE")
	p("=====================================")
	p("  Repository:        %s", r.RepoPath)
	p("  Commits:           %d", r.TotalCommits)
	p("  Unique blobs:      %d", r.UniqueBlobs)
	p("  Blobs scanned:     %d", r.BlobsScanned)
	p("  Blobs skipped:     %d (allowlisted)", r.BlobsSkipped)
	p("  Blob findings:     %d", len(r.BlobFindings))
	p("  Meta anomalies:    %d", len(r.MetaAnomalies))
	p("  Remote findings:   %d", len(r.RemoteFindings))
	p("  Duration:          %s", r.Duration)
	p("=====================================")

	if len(r.MetaAnomalies) > 0 {
		p("")
		p("COMMIT METADATA ANOMALIES:")
		for _, m := range r.MetaAnomalies {
			flags := []string{}
			if m.TZMismatch {
				flags = append(flags, "TZ-MISMATCH")
			}
			if m.DateAnomaly {
				flags = append(flags, "DATE-ANOMALY")
			}
			p("  %s  %s <%s>  [%s]", short(m.Commit), m.AuthorName, m.AuthorEmail, strings.Join(flags, ","))
			p("    author: %s (%s)  commit: %s (%s)", m.AuthorDate, m.AuthorTZ, m.CommitDate, m.CommitTZ)
			p("    subject: %s", m.Subject)
		}
	}

	if len(r.BlobFindings) > 0 {
		p("")
		p("IOC MATCHES (by unique blob):")
		for _, b := range r.BlobFindings {
			p("")
			p("  Blob:    %s [%s] %s", short(b.BlobSHA), b.Severity, b.PatternName)
			p("  Desc:    %s", b.Description)
			p("  Paths:   %s", strings.Join(b.Paths, ", "))
			if len(b.Commits) > 0 {
				shown := b.Commits
				if len(shown) > 5 {
					shown = shown[:5]
				}
				short5 := make([]string, len(shown))
				for i, c := range shown {
					short5[i] = short(c)
				}
				suffix := ""
				if len(b.Commits) > 5 {
					suffix = fmt.Sprintf(" (+%d more)", len(b.Commits)-5)
				}
				p("  Commits: %s%s", strings.Join(short5, ", "), suffix)
			}
		}
	}

	if len(r.RemoteFindings) > 0 {
		p("")
		p("EXTERNAL REFERENCE FINDINGS:")
		for _, rf := range r.RemoteFindings {
			checked := ""
			if rf.Checked {
				checked = " (live-checked)"
			}
			p("  [%s] %s@%s  host=%s%s", rf.Severity, rf.Name, rf.Version, rf.Host, checked)
			p("    %s", rf.Reason)
		}
	}

	total := len(r.BlobFindings) + len(r.MetaAnomalies) + len(r.RemoteFindings)
	if total == 0 {
		p("")
		p("[OK] No IOC matches, metadata anomalies, or remote findings.")
		p("     This does NOT guarantee the repository is clean.")
	}
}

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
