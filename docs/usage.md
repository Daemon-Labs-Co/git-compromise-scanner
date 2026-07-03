# Usage: finding and excising a compromise

This walks through the two halves of an investigation: using the packages in
this repo to **find** evidence of compromise across a repository's full
history, then **excising** confirmed-bad content from that history. The
second half is deliberately not something this tool does for you — see
[Why excision isn't automated](#why-excision-isnt-automated) below.

There is no `cmd/` binary yet (see the [README](../README.md#status)), so
"running the scanner" means wiring the five packages together in a small Go
program. That's less friction than it sounds — the whole driver is about 40
lines, shown below.

## 1. Prepare your IOC patterns

Copy `patterns.example.tsv` and replace its illustrative entries with the
concrete indicators from your incident: exact malicious domains, file hashes,
attacker email fragments, malware string constants, etc. Format and details
are in [patterns.md](patterns.md).

```sh
cp patterns.example.tsv patterns.tsv
$EDITOR patterns.tsv
```

Also populate `remote.c2Blocklist` (in `remote/remote.go`) with any C2 hosts
from your incident report or threat-intel feed — those hosts are refused
even if you later enable live remote checks.

## 2. Run a scan

Write a small driver that wires the packages together — this mirrors
["How a scan fits together"](architecture.md#how-a-scan-fits-together) in the
architecture doc:

```go
// cmd/scan/main.go (not yet in the repo — create it, or paste into a scratch main package)
package main

import (
	"log"
	"os"
	"time"

	"github.com/daemon-labs-co/git-compromise-scanner/deps"
	"github.com/daemon-labs-co/git-compromise-scanner/gitwalk"
	"github.com/daemon-labs-co/git-compromise-scanner/report"
	"github.com/daemon-labs-co/git-compromise-scanner/scan"
)

func main() {
	repoPath := os.Args[1]     // path to the suspect repository
	patternsPath := os.Args[2] // e.g. patterns.tsv
	allowlistPath := "allowlist.txt"

	start := time.Now()

	r, err := gitwalk.New(repoPath)
	if err != nil {
		log.Fatal(err)
	}
	scanner, err := scan.LoadPatterns(patternsPath)
	if err != nil {
		log.Fatal(err)
	}
	allow, err := report.LoadAllowlist(allowlistPath)
	if err != nil {
		log.Fatal(err)
	}

	commits, err := r.Commits()
	if err != nil {
		log.Fatal(err)
	}

	rep := &report.Report{RepoPath: repoPath, TotalCommits: len(commits)}

	// Metadata anomalies: forged author/committer timestamps, TZ mismatches.
	for _, hash := range commits {
		meta, err := r.Meta(hash)
		if err != nil {
			continue
		}
		if meta.AuthorTZ != meta.CommitTZ {
			rep.MetaAnomalies = append(rep.MetaAnomalies, report.MetaAnomaly{
				Commit: hash, AuthorTZ: meta.AuthorTZ, CommitTZ: meta.CommitTZ,
				TZMismatch: true,
			})
		}
	}

	// Content: every unique blob that has ever existed, scanned once.
	blobs, err := r.UniqueBlobs()
	if err != nil {
		log.Fatal(err)
	}
	rep.UniqueBlobs = len(blobs)
	for sha, b := range blobs {
		if allow.Has(sha) {
			rep.BlobsSkipped++
			continue
		}
		rep.BlobsScanned++
		content, err := r.Content(sha)
		if err != nil {
			continue
		}
		for _, m := range scanner.Scan(content) {
			var paths []string
			for _, ref := range b.Refs {
				paths = append(paths, ref.Path)
			}
			rep.BlobFindings = append(rep.BlobFindings, report.BlobFinding{
				BlobSHA: sha, Paths: paths, PatternName: m.PatternName,
				Severity: m.Severity, Description: m.Description, LineHint: m.LineHint,
			})
		}

		// Dependency manifests get an extra pass: parse references, then
		// triage resolved URLs against the trusted-registry/blocklist rules.
		for _, ref := range b.Refs {
			if ref.Path != "package.json" && ref.Path != "package-lock.json" {
				continue
			}
			// deps.ParsePackageJSON / deps.ParseLockfile + remote.Inspect
			// wire in here — see architecture.md for the exact call shapes.
			_ = deps.Reference{}
		}
	}

	rep.Duration = time.Since(start).String()
	report.WriteText(os.Stdout, rep)
}
```

Run it against the suspect repository (never your own working copy — clone
the suspect repo to a scratch directory first):

```sh
git clone --no-checkout /path/to/suspect-repo /tmp/investigate
go run ./cmd/scan /tmp/investigate patterns.tsv
```

`--no-checkout` matters: it avoids ever materializing potentially malicious
files on disk. The scanner itself never checks anything out either — only
`git clone` needs the checkout step, and skipping it removes even that.

## 3. Read the report

`report.WriteText` groups output into three sections:

- **Commit metadata anomalies** — commits where author and committer
  timezones (or dates) disagree. Not proof of tampering by itself (rebases
  and cherry-picks cause this legitimately), but worth checking against your
  incident timeline.
- **IOC matches, grouped by unique blob** — each hit shows the blob SHA, the
  pattern that matched, severity, and up to five commits/paths that
  reference it. Because blobs are deduplicated by content, one match here can
  mean the payload was copied into many files across history — check every
  listed path and commit.
- **External reference findings** — dependency URLs that are blocklisted
  (CRITICAL), resolve to an untrusted registry (HIGH), or are missing an
  integrity hash (MEDIUM).

Treat CRITICAL and HIGH findings as requiring a follow-up manual review of
the actual commit and blob content (`git show <commit>`, `git cat-file blob
<sha>` in a **disposable, network-isolated** environment — never execute
anything the scanner surfaces).

A clean run does not mean a clean repository — the scanner only knows the
patterns you gave it. Also check `docs/patterns.md` if you're not confident
your pattern set covers your incident's actual IOCs.

## 4. Allowlist reviewed-clean content (optional, speeds up re-scans)

Once you've manually confirmed a blob is safe, add its SHA so future scans
skip it:

```go
allow.Add(sha)
allow.Save("allowlist.txt")
```

Because the allowlist keys on content SHA, this is safe across re-clones and
branches: the same file content anywhere in history is skipped, and any
*different* content at a previously-reviewed path is not (drift is still
flagged).

## 5. Excising confirmed-bad history

Once you've identified the exact blob SHAs, paths, or commits that need to
go, this tool's job is done — everything past this point is standard git
history surgery, done with tools built for it. **Do this on a fresh clone,
never on the only copy of the repository.**

### Recommended: `git filter-repo`

[`git filter-repo`](https://github.com/newren/git-filter-repo) is the
current recommended tool for rewriting history (faster and safer than the
older `git filter-branch`, and explicitly recommended over it upstream).

```sh
# Fresh clone to work on — never rewrite your only copy.
git clone /path/to/suspect-repo /tmp/excise
cd /tmp/excise

# Remove specific blobs by content SHA (the exact hashes from your report).
git filter-repo --strip-blobs-with-ids <(printf '%s\n' <sha1> <sha2>)

# Or remove a path entirely, everywhere in history.
git filter-repo --path path/to/malicious-file --invert-paths

# Or drop specific commits by hash (rewrites everything after them too).
git filter-repo --commit-callback '
if commit.original_id in (b"<commit-sha-1>", b"<commit-sha-2>"):
    commit.skip()
'
```

### Alternative: BFG Repo-Cleaner

For simple "delete this blob/text everywhere" cases,
[BFG](https://rtyley.github.io/bfg-repo-cleaner/) is a faster, simpler
alternative to `filter-repo` for that narrow use case:

```sh
bfg --delete-files malicious-file.js /tmp/excise
bfg --strip-blobs-with-ids blob-ids.txt /tmp/excise
```

### After rewriting

```sh
cd /tmp/excise
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

Then **re-run the scanner against the rewritten repo** and confirm the
flagged SHAs are no longer reachable (`UniqueBlobs` in the new report should
not include them, and `BlobFindings` should be empty for the patterns that
matched before).

### Before you push the rewritten history anywhere

- **History rewriting changes every downstream commit hash.** Every
  collaborator must discard their existing clone and re-clone; anyone who
  doesn't will silently resurrect the old history on their next push.
  Coordinate this before force-pushing, don't just do it.
- **Force-pushing a shared branch is destructive to anyone else's in-flight
  work.** Confirm no one has unpushed commits based on the old history first.
- **Rewriting history does not undo the exposure.** Any secret, credential,
  or token that was ever committed was already exposed the moment it was
  pushed anywhere reachable (forks, CI logs, local clones, GitHub's caches).
  Rotate and revoke those credentials regardless of whether you rewrite
  history — filter-repo/BFG only prevent the bad content from being handed
  to *future* clones, they don't retroactively un-leak it.
- **Preserve evidence before you rewrite.** Keep the original clone
  (untouched) and your scan report somewhere safe for incident
  documentation, in case you need to reference the exact compromised commits
  later.

## Why excision isn't automated

This project's [safety model](../README.md#safety-model) is built around
never writing to or executing content from the repository under
investigation — every `gitwalk` call is read-only plumbing, and nothing here
runs `git filter-repo`, `push`, or any other mutating command. Keeping
detection and remediation as separate, deliberate steps means a scan can
never accidentally destroy evidence, and a destructive history rewrite always
happens as an explicit, reviewed action by a human — not a side effect of
running a scanner.
