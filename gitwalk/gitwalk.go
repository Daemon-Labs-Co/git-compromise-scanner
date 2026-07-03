// Package gitwalk knows how git works and nothing else.
//
// Its job is to enumerate the contents of a repository safely:
//   - every commit
//   - every ref (branch/tag/remote tip)
//   - every UNIQUE blob that has ever existed in history
//   - the mapping from a blob back to the commits and paths that reference it
//
// Safety: this package never checks out a commit and never executes
// repository content. All access is read-only via plumbing commands
// (rev-list, cat-file, for-each-ref, log). Blob content is returned as
// inert bytes for another package to scan.
package gitwalk

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Repo represents a git repository on disk.
type Repo struct {
	Path string
}

// New returns a Repo after verifying the path is a git repository.
func New(path string) (*Repo, error) {
	r := &Repo{Path: path}
	if err := r.run("rev-parse", "--git-dir"); err != nil {
		return nil, fmt.Errorf("not a git repository: %s", path)
	}
	return r, nil
}

// Ref is a named pointer to a commit (branch, tag, or remote tip).
type Ref struct {
	Hash string
	Name string
}

// Commit holds parsed metadata for a single commit.
type Commit struct {
	Hash        string
	AuthorName  string
	AuthorEmail string
	AuthorDate  string
	AuthorTZ    string
	CommitDate  string
	CommitTZ    string
	Subject     string
}

// BlobRef ties a unique blob to one location where it is referenced.
type BlobRef struct {
	Commit string // commit SHA that references this blob
	Path   string // path of the blob within that commit's tree
}

// Blob is a unique file version, identified by its content hash.
// The same Blob may be referenced from many commits and paths.
type Blob struct {
	SHA  string    // git object SHA = content checksum
	Size int64     // blob size in bytes
	Refs []BlobRef // every commit+path that references this content
}

// Short returns a 12-char prefix of a hash.
func Short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

// Commits returns every commit reachable from all refs.
func (r *Repo) Commits() ([]string, error) {
	out, err := r.output("rev-list", "--all")
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(out)
	if raw == "" {
		return nil, nil
	}
	return strings.Split(raw, "\n"), nil
}

// Refs returns every branch, tag, and remote tip, deduplicated by hash.
func (r *Repo) Refs() ([]Ref, error) {
	out, err := r.output("for-each-ref",
		"--format=%(objectname) %(refname:short)",
		"refs/heads/", "refs/remotes/", "refs/tags/")
	if err != nil {
		return nil, err
	}

	var refs []Ref
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		if seen[parts[0]] {
			continue
		}
		seen[parts[0]] = true
		refs = append(refs, Ref{Hash: parts[0], Name: parts[1]})
	}
	return refs, nil
}

// Meta returns parsed metadata for a single commit.
func (r *Repo) Meta(hash string) (Commit, error) {
	out, err := r.output("log", "-1",
		"--format=%an\t%ae\t%ad\t%cd\t%s", "--date=iso", hash)
	if err != nil {
		return Commit{}, err
	}
	parts := strings.SplitN(strings.TrimSpace(out), "\t", 5)
	if len(parts) < 5 {
		return Commit{}, fmt.Errorf("unexpected log format for %s", hash)
	}
	return Commit{
		Hash:        hash,
		AuthorName:  parts[0],
		AuthorEmail: parts[1],
		AuthorDate:  parts[2],
		AuthorTZ:    extractTZ(parts[2]),
		CommitDate:  parts[3],
		CommitTZ:    extractTZ(parts[3]),
		Subject:     parts[4],
	}, nil
}

// UniqueBlobs enumerates every blob that has ever existed in history,
// deduplicated by content SHA. This is the core of the "scan every
// version of every file" requirement done efficiently: identical content
// is scanned once, no matter how many commits reference it.
//
// Implementation: `git log --all --root --raw` walks every commit's diff
// against its parent (the root commit is diffed against the empty tree),
// which yields every (path, blob SHA) pair ever introduced. This is
// deliberately not `git rev-list --all --objects`: that command dedups
// blob objects during tree traversal and reports only the first path it
// encounters for a given content SHA, silently dropping other paths that
// happen to reference identical content (e.g. two files with the same
// contents). Walking diffs instead captures every path a blob was ever
// added or modified under, which is what attribution needs. We then
// resolve each blob's size via a single batched cat-file call.
func (r *Repo) UniqueBlobs() (map[string]*Blob, error) {
	// Step 1: list every (sha, path) pair ever introduced by a commit.
	out, err := r.output("log", "--all", "--root", "--raw", "--no-renames",
		"--full-index", "--abbrev=40", "--format=", "--diff-filter=ACMR")
	if err != nil {
		return nil, err
	}

	type objLine struct {
		sha  string
		path string
	}
	var objs []objLine
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, ":") {
			continue
		}
		// Format: ":<oldmode> <newmode> <oldsha> <newsha> <status>\t<path>"
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		fields := strings.Fields(line[:tab])
		if len(fields) < 4 {
			continue
		}
		objs = append(objs, objLine{sha: fields[3], path: line[tab+1:]})
	}

	// Step 2: batch-check object types and sizes so we keep only blobs.
	shaList := make([]string, 0, len(objs))
	seenSHA := map[string]bool{}
	for _, o := range objs {
		if !seenSHA[o.sha] {
			seenSHA[o.sha] = true
			shaList = append(shaList, o.sha)
		}
	}
	typeSize, err := r.batchCheck(shaList)
	if err != nil {
		return nil, err
	}

	// Step 3: aggregate references per unique blob SHA, deduping
	// (sha, path) pairs seen across multiple commits.
	blobs := map[string]*Blob{}
	seenRef := map[string]bool{}
	for _, o := range objs {
		ts, ok := typeSize[o.sha]
		if !ok || ts.typ != "blob" {
			continue
		}
		b, exists := blobs[o.sha]
		if !exists {
			b = &Blob{SHA: o.sha, Size: ts.size}
			blobs[o.sha] = b
		}
		key := o.sha + "\x00" + o.path
		if !seenRef[key] {
			seenRef[key] = true
			b.Refs = append(b.Refs, BlobRef{Path: o.path})
		}
	}

	// Step 4: commit attribution is resolved lazily in the caller when a
	// hit is found, via CommitsForPath. Refs[].Commit is left empty here.
	return blobs, nil
}

// Content returns the raw bytes of a blob by its SHA, without checkout.
func (r *Repo) Content(sha string) ([]byte, error) {
	cmd := exec.Command("git", "-C", r.Path, "cat-file", "blob", sha)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CommitsForPath returns commits that touched a given path, newest first.
// Used to attribute a flagged blob back to human-readable history.
func (r *Repo) CommitsForPath(path string) ([]string, error) {
	out, err := r.output("log", "--all", "--format=%H", "--", path)
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(out)
	if raw == "" {
		return nil, nil
	}
	return strings.Split(raw, "\n"), nil
}

// ChangedFiles returns the files changed in a single commit (for the
// per-commit forensic pass). Uses --root so the first commit is included.
func (r *Repo) ChangedFiles(hash string) ([]string, error) {
	out, err := r.output("diff-tree", "--root", "--no-commit-id",
		"--name-only", "-r", hash)
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(out)
	if raw == "" {
		return nil, nil
	}
	return strings.Split(raw, "\n"), nil
}

// FileAt returns the content of a path at a specific commit, no checkout.
func (r *Repo) FileAt(hash, path string) ([]byte, error) {
	cmd := exec.Command("git", "-C", r.Path, "show", hash+":"+path)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---------- internal helpers ----------

type objInfo struct {
	typ  string
	size int64
}

// batchCheck resolves type and size for many objects in one cat-file call.
func (r *Repo) batchCheck(shas []string) (map[string]objInfo, error) {
	cmd := exec.Command("git", "-C", r.Path, "cat-file", "--batch-check")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	go func() {
		w := bufio.NewWriter(stdin)
		for _, s := range shas {
			fmt.Fprintln(w, s)
		}
		w.Flush()
		stdin.Close()
	}()

	result := map[string]objInfo{}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		// Format: "<sha> <type> <size>"  or  "<sha> missing"
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "missing" {
			continue
		}
		if len(fields) < 3 {
			continue
		}
		var size int64
		fmt.Sscanf(fields[2], "%d", &size)
		result[fields[0]] = objInfo{typ: fields[1], size: size}
	}

	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	return result, scanner.Err()
}

func (r *Repo) run(args ...string) error {
	cmd := exec.Command("git", append([]string{"-C", r.Path}, args...)...)
	return cmd.Run()
}

func (r *Repo) output(args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", r.Path}, args...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}

func extractTZ(isoDate string) string {
	fields := strings.Fields(strings.TrimSpace(isoDate))
	if len(fields) >= 3 {
		return fields[len(fields)-1]
	}
	return ""
}
