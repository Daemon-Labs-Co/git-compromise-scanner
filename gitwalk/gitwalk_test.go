package gitwalk

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// testRepo builds a real throwaway git repository:
//
//	commit 1: a.txt = "hello\n"            (author TZ +0200, committer TZ -0500)
//	commit 2: a.txt = "changed\n", b.txt = "hello\n" (same content as a.txt v1)
//	tag v1 on commit 2
//
// Returns the repo and the two commit hashes, oldest first.
func testRepo(t *testing.T) (*Repo, []string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()

	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=Alice", "GIT_AUTHOR_EMAIL=alice@example.com",
		"GIT_AUTHOR_DATE=2026-01-02T10:00:00+02:00",
		"GIT_COMMITTER_NAME=Bob", "GIT_COMMITTER_EMAIL=bob@example.com",
		"GIT_COMMITTER_DATE=2026-01-02T03:00:00-05:00",
	)
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	git("init", "-q", "-b", "main")
	// Keep the fixture hermetic regardless of the developer's global git
	// config (GPG signing would hang tests waiting for a passphrase).
	git("config", "commit.gpgsign", "false")
	git("config", "tag.gpgsign", "false")
	write("a.txt", "hello\n")
	git("add", "a.txt")
	git("commit", "-q", "-m", "first commit")

	write("a.txt", "changed\n")
	write("b.txt", "hello\n") // identical content to a.txt at commit 1
	git("add", "a.txt", "b.txt")
	git("commit", "-q", "-m", "second commit")
	git("tag", "v1")

	r, err := New(dir)
	if err != nil {
		t.Fatalf("New(%s): %v", dir, err)
	}

	hashes, err := r.Commits()
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 2 {
		t.Fatalf("test repo has %d commits, want 2", len(hashes))
	}
	// rev-list is newest first; return oldest first.
	return r, []string{hashes[1], hashes[0]}
}

func TestNewRejectsNonRepo(t *testing.T) {
	if _, err := New(t.TempDir()); err == nil {
		t.Error("New() accepted a directory that is not a git repository")
	}
}

func TestRefs(t *testing.T) {
	r, commits := testRepo(t)
	refs, err := r.Refs()
	if err != nil {
		t.Fatal(err)
	}
	// main and v1 both point at commit 2; Refs dedups by hash.
	if len(refs) != 1 {
		t.Fatalf("got %d refs, want 1 (deduplicated by hash): %+v", len(refs), refs)
	}
	if refs[0].Hash != commits[1] {
		t.Errorf("ref points at %s, want head commit %s", refs[0].Hash, commits[1])
	}
}

func TestMeta(t *testing.T) {
	r, commits := testRepo(t)
	m, err := r.Meta(commits[0])
	if err != nil {
		t.Fatal(err)
	}
	if m.AuthorName != "Alice" || m.AuthorEmail != "alice@example.com" {
		t.Errorf("author = %s <%s>", m.AuthorName, m.AuthorEmail)
	}
	if m.Subject != "first commit" {
		t.Errorf("subject = %q", m.Subject)
	}
	// The forged-metadata signal: author and committer timezones differ.
	if m.AuthorTZ != "+0200" || m.CommitTZ != "-0500" {
		t.Errorf("TZs = author %q / committer %q, want +0200 / -0500", m.AuthorTZ, m.CommitTZ)
	}
	if m.AuthorTZ == m.CommitTZ {
		t.Error("expected differing timezones in test fixture")
	}
}

func TestUniqueBlobsDeduplicatesContent(t *testing.T) {
	r, _ := testRepo(t)
	blobs, err := r.UniqueBlobs()
	if err != nil {
		t.Fatal(err)
	}
	// Unique contents ever: "hello\n" (a.txt v1 AND b.txt) and "changed\n".
	if len(blobs) != 2 {
		t.Fatalf("got %d unique blobs, want 2: %+v", len(blobs), blobs)
	}

	var hello *Blob
	for _, b := range blobs {
		content, err := r.Content(b.SHA)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) == "hello\n" {
			hello = b
		}
	}
	if hello == nil {
		t.Fatal("no blob with content 'hello\\n'")
	}
	if hello.Size != int64(len("hello\n")) {
		t.Errorf("Size = %d, want %d", hello.Size, len("hello\n"))
	}
	// Same content is referenced from two paths but stored/scanned once.
	paths := map[string]bool{}
	for _, ref := range hello.Refs {
		paths[ref.Path] = true
	}
	if !paths["a.txt"] || !paths["b.txt"] {
		t.Errorf("hello blob refs = %+v, want both a.txt and b.txt", hello.Refs)
	}
}

func TestCommitsForPath(t *testing.T) {
	r, commits := testRepo(t)

	got, err := r.CommitsForPath("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != commits[1] || got[1] != commits[0] {
		t.Errorf("CommitsForPath(a.txt) = %v, want [%s %s] (newest first)", got, commits[1], commits[0])
	}

	got, err = r.CommitsForPath("b.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != commits[1] {
		t.Errorf("CommitsForPath(b.txt) = %v", got)
	}
}

func TestChangedFiles(t *testing.T) {
	r, commits := testRepo(t)

	// --root means the initial commit reports its files too.
	got, err := r.ChangedFiles(commits[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "a.txt" {
		t.Errorf("ChangedFiles(first) = %v, want [a.txt]", got)
	}

	got, err = r.ChangedFiles(commits[1])
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("ChangedFiles(second) = %v, want a.txt and b.txt", got)
	}
}

func TestFileAt(t *testing.T) {
	r, commits := testRepo(t)

	content, err := r.FileAt(commits[0], "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "hello\n" {
		t.Errorf("FileAt(first, a.txt) = %q, want the historical version", content)
	}

	content, err = r.FileAt(commits[1], "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "changed\n" {
		t.Errorf("FileAt(second, a.txt) = %q", content)
	}

	if _, err := r.FileAt(commits[0], "b.txt"); err == nil {
		t.Error("FileAt should fail for a path that does not exist at that commit")
	}
}

func TestShort(t *testing.T) {
	if got := Short("abcdef0123456789abcdef0123456789abcdef01"); got != "abcdef012345" {
		t.Errorf("Short() = %q", got)
	}
	if got := Short("abc"); got != "abc" {
		t.Errorf("Short() should pass short hashes through, got %q", got)
	}
}

func TestExtractTZ(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026-01-02 10:00:00 +0200", "+0200"},
		{"2026-01-02 03:00:00 -0500", "-0500"},
		{"garbage", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := extractTZ(c.in); got != c.want {
			t.Errorf("extractTZ(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
