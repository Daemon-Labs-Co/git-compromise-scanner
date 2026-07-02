# git-compromise-scanner

A forensic scanner that hunts for indicators of compromise (IOCs) across the
**entire history** of a git repository — every commit, every ref, and every
unique version of every file that has ever existed — without ever checking out
or executing repository content.

It was built for supply-chain-compromise investigations: given a repo that may
have been touched by an attacker (malicious commits, planted payloads,
tampered lockfiles, forged commit metadata), it answers *"is there anything in
this repository's history that matches known-bad indicators?"*

## Safety model

The design separates concerns so that each risky capability lives in exactly
one place:

- **No checkouts, no execution.** All git access is read-only plumbing
  (`rev-list`, `cat-file`, `for-each-ref`, `log`, `diff-tree`, `show`). File
  content is handled as inert bytes and only ever matched against regexes.
- **No network by default.** Only the `remote` package may touch the network,
  and only when explicitly enabled — and even then it never contacts hosts on
  the C2 blocklist and never downloads payloads.
- **Manifests are parsed as data.** `package.json` / `package-lock.json` are
  JSON-decoded; npm is never run and lifecycle scripts are never executed
  (they are *surfaced* as findings instead).

## Package layout

| Package   | File                 | Responsibility |
|-----------|----------------------|----------------|
| `gitwalk` | `gitwalk/gitwalk.go` | Enumerate git history safely (commits, refs, unique blobs, content) |
| `scan`    | `scan/scan.go`       | Match inert bytes against an IOC pattern set |
| `deps`    | `deps/deps.go`       | Parse JS dependency manifests into normalized references |
| `remote`  | `remote/remote.go`   | Classify external URLs; the only module allowed near the network |
| `report`  | `report/report.go`   | Aggregate findings; manage the known-good blob allowlist; render output |

Each package is documented in detail below.

---

## `gitwalk` — safe git enumeration

Knows how git works and nothing else. Never checks out a commit; all access is
via read-only plumbing commands run against the repo directory.

### Types

- **`Repo`** — a git repository on disk. Field: `Path` (filesystem path).
- **`Ref`** — a named pointer to a commit. Fields: `Hash`, `Name` (branch,
  tag, or remote tip).
- **`Commit`** — parsed metadata for one commit: `Hash`, `AuthorName`,
  `AuthorEmail`, `AuthorDate`, `AuthorTZ`, `CommitDate`, `CommitTZ`,
  `Subject`. The separate author/committer timestamps and timezones exist so
  callers can detect forged metadata (e.g. backdated commits).
- **`Blob`** — one unique file version, identified by content SHA. Fields:
  `SHA`, `Size`, `Refs` (every commit+path that references this content).
- **`BlobRef`** — one location a blob is referenced from: `Commit`, `Path`.

### Functions and methods

- **`New(path) (*Repo, error)`** — verifies the path is a git repository
  (via `rev-parse --git-dir`) and returns a `Repo`.
- **`Short(hash) string`** — returns a 12-character prefix of a hash, for
  display.
- **`(*Repo) Commits() ([]string, error)`** — every commit SHA reachable
  from any ref (`rev-list --all`).
- **`(*Repo) Refs() ([]Ref, error)`** — every branch, tag, and remote tip,
  deduplicated by hash (`for-each-ref`).
- **`(*Repo) Meta(hash) (Commit, error)`** — parsed metadata for a single
  commit (`log -1` with a tab-delimited format).
- **`(*Repo) UniqueBlobs() (map[string]*Blob, error)`** — the core
  enumeration: every blob that has *ever* existed in history, deduplicated by
  content SHA. Identical content is therefore scanned once no matter how many
  commits contain it. Internally: `rev-list --all --objects` lists every
  reachable object with its path; one batched `cat-file --batch-check` call
  resolves types and sizes; only blobs are kept and their path references
  aggregated per SHA. Commit attribution is intentionally deferred — callers
  resolve it on demand via `CommitsForPath` only for blobs that actually match
  a pattern.
- **`(*Repo) Content(sha) ([]byte, error)`** — raw bytes of a blob
  (`cat-file blob`), without checkout.
- **`(*Repo) CommitsForPath(path) ([]string, error)`** — commits that touched
  a path, newest first. Used to attribute a flagged blob to human-readable
  history.
- **`(*Repo) ChangedFiles(hash) ([]string, error)`** — files changed in one
  commit (`diff-tree --root`, so the initial commit is included). Supports a
  per-commit forensic pass.
- **`(*Repo) FileAt(hash, path) ([]byte, error)`** — content of a path at a
  specific commit (`git show`), without checkout.

Internal helpers: `batchCheck` (streams SHAs through a single
`cat-file --batch-check` process and returns a type/size map), `run` /
`output` (thin `git -C <path>` wrappers), and `extractTZ` (pulls the timezone
field out of an ISO date string).

---

## `scan` — IOC pattern matching

Takes inert bytes and a pattern set and returns matches. Knows nothing about
git or the network; content is only ever matched against regexes — never
executed, parsed as code, or deserialized.

### Types

- **`Pattern`** — one indicator of compromise: `Name`, `Regex` (compiled),
  `Raw` (source text), `Severity`, `Description`.
- **`Match`** — one pattern hit: `PatternName`, `Severity`, `Description`,
  `LineHint` (1-based line number of the first match).
- **`Scanner`** — a compiled pattern set.

### Functions and methods

- **`LoadPatterns(path) (*Scanner, error)`** — reads a tab-delimited pattern
  file (format below). Fails fast on malformed lines or invalid regexes, and
  on an empty pattern set.
- **`(*Scanner) Count() int`** — number of loaded patterns.
- **`(*Scanner) Scan(content) []Match`** — matches every pattern against the
  content; returns one `Match` per pattern that hits (first occurrence, with
  a line hint).

### Pattern file format

```
SEVERITY<TAB>NAME<TAB>REGEX<TAB>DESCRIPTION
```

Lines starting with `#` and blank lines are ignored; regexes use Go `regexp`
syntax. See **`patterns.example.tsv`** in the repo root for a generic starter
set covering the usual suspects: curl-piped-to-shell droppers, obfuscated
`eval(atob(...))` payloads, exfiltration webhooks, committed private keys and
cloud tokens, malicious npm lifecycle scripts, and crypto-clipper indicators.
For a real investigation, replace or extend these with the concrete IOCs from
your incident.

---

## `deps` — dependency manifest parsing

Parses JavaScript dependency manifests into a normalized list of external
references. Parsing only: npm is never run, nothing is installed, lifecycle
scripts are never executed.

### Types

- **`Reference`** — one external dependency as declared or resolved: `Name`,
  `Version`, `Range` (declared semver range), `Resolved` (tarball URL from the
  lockfile), `Integrity` (lockfile integrity hash), `Dev`, `Source`
  (`"package.json"` or `"package-lock.json"`).
- **`Manifest`** — the normalized result for one repo: `References`.
- **`LifecycleScripts`** — install-time scripts found in `package.json`
  (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`,
  `prepublishOnly`). Returned separately because install scripts are a known
  malware execution vector worth surfacing on their own.

### Functions

- **`ParsePackageJSON(content) ([]Reference, *LifecycleScripts, error)`** —
  parses `package.json`: collects `dependencies`, `devDependencies`,
  `optionalDependencies`, and `peerDependencies` as references, and extracts
  any interesting lifecycle scripts.
- **`ParseLockfile(content) ([]Reference, error)`** — parses
  `package-lock.json` v1, v2, or v3. For v2/v3 it walks the `packages` map
  (deriving the package name from the last `node_modules/` segment); for v1 it
  falls back to the `dependencies` map. Results are sorted by name then
  version.

Internal helper: `lastNodeModules` finds the index just after the final
`node_modules/` segment so nested paths resolve to the right package name.

---

## `remote` — external reference triage

The **only** module permitted to touch the network, and it does so only when
explicitly enabled. By default it operates in report-only mode: it inspects
resolved dependency URLs and flags anything suspicious without making a single
outbound request.

### Package-level data

- **`c2Blocklist`** — hosts that are *never* contacted, even in live mode.
  Ships with illustrative placeholder entries; populate it from the IOC feed
  relevant to your investigation (incident reports, threat-intel advisories,
  your SOC's blocklist).
- **`trustedRegistryHosts`** — hosts considered normal for npm-resolved
  tarballs (`registry.npmjs.org`, `registry.yarnpkg.com`,
  `npm.pkg.github.com`). Anything else in a `resolved` URL is flagged for a
  human look.

### Types

- **`Config`** — remote behavior. `Enabled: false` (default) means inspect
  URLs only, no network; `true` opts in to live reachability checks.
- **`Finding`** — something notable about an external reference: `Name`,
  `Version`, `URL`, `Host`, `Reason`, `Severity`, and `Checked` (true only if
  a live request was actually made).

### Functions

- **`Inspect(refs, cfg) []Finding`** — classifies each resolved dependency
  URL, in order of precedence:
  1. **Unparseable URL** → MEDIUM.
  2. **Blocklisted host** → CRITICAL, and the host is never contacted.
  3. **Untrusted registry host** → HIGH. With `cfg.Enabled`, a live
     reachability check would run here — the seam exists but the actual HTTP
     HEAD is deliberately left as a stub pending further review.
  4. **Trusted host but missing integrity hash** → MEDIUM, because the
     lockfile then cannot prove the tarball wasn't swapped.

Internal helpers: `isBlocklisted` / `isTrustedHost` match a lowercased host
against the respective list, including subdomains (`x.example.com` matches a
list entry `example.com`).

---

## `report` — aggregation, allowlist, and output

Aggregates findings from every other module into a single result and manages
the known-good blob allowlist.

### Report types

- **`BlobFinding`** — an IOC match against a unique blob, with attribution:
  `BlobSHA`, `Paths`, `Commits`, `PatternName`, `Severity`, `Description`,
  `LineHint`.
- **`MetaAnomaly`** — a commit with forged-metadata indicators: the full
  author/committer name, email, dates, and timezones, plus `TZMismatch`
  (author and committer timezones disagree) and `DateAnomaly` flags.
- **`RemoteFinding`** — mirrors `remote.Finding`. Kept as a local type so
  `report` has no dependency on `remote`; the command layer adapts between
  them.
- **`Report`** — the full aggregated result for one repository: `RepoPath`,
  `ScanTime`, `TotalCommits`, `UniqueBlobs`, `BlobsScanned`, `BlobsSkipped`
  (allowlisted), the three findings slices, and `Duration`.

### Allowlist

A persisted set of blob SHAs that have been scanned and judged clean. Because
a git blob SHA is a content checksum, an allowlisted SHA means "this exact
file content was reviewed and is safe" — on future scans matching content is
skipped (speed), and drift from an expected SHA can be flagged (integrity).

- **`NewAllowlist() *Allowlist`** — an empty allowlist.
- **`LoadAllowlist(path) (*Allowlist, error)`** — reads a SHA file (one SHA
  per line, `#` comments and trailing notes allowed). A missing file is not an
  error; it yields an empty allowlist.
- **`(*Allowlist) Has(sha) bool`** — membership test.
- **`(*Allowlist) Add(sha)`** — record a SHA as known-good.
- **`(*Allowlist) Save(path) error`** — writes the list back to disk, sorted,
  with a generated header.

### Output

- **`WriteJSON(w, r) error`** — the report as indented JSON (nil finding
  slices are normalized to empty arrays first, so consumers always see
  `[]`).
- **`WriteText(w, r)`** — a human-readable summary: scan totals, then commit
  metadata anomalies, IOC matches grouped by unique blob (showing up to five
  referencing commits each), and external reference findings. When nothing was
  found it says so explicitly — along with the reminder that a clean scan does
  **not** guarantee a clean repository.

Internal helper: `short` (12-character hash prefix for display).

---

## How a scan fits together

A driver (command layer, not included here) wires the packages up roughly as:

1. `gitwalk.New` → `Commits()` / `Refs()` to establish scope.
2. `Meta()` per commit to detect metadata anomalies (timezone mismatches,
   date anomalies) → `report.MetaAnomaly`.
3. `UniqueBlobs()` → for each blob not in the allowlist, `Content()` →
   `scan.Scan()`. Hits become `report.BlobFinding`s, attributed via
   `CommitsForPath()`. Clean blobs can be `Allowlist.Add`ed.
4. Blobs whose path is `package.json` / `package-lock.json` additionally go
   through `deps.ParsePackageJSON` / `deps.ParseLockfile`, and the resulting
   references through `remote.Inspect` → `report.RemoteFinding`.
5. Everything lands in a `report.Report`, emitted via `WriteText` and/or
   `WriteJSON`.

## Repository status

The module is declared as
`github.com/daemon-labs-co/git-compromise-scanner`. There is no `cmd/` entry
point yet; the five packages are the reusable core.

## License

Released under the [MIT License](LICENSE).
