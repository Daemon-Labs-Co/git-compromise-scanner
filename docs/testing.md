# Testing

Run the full suite with:

```sh
go test ./...
```

Every package has a test file alongside it:

| Test file                 | What it verifies |
|---------------------------|------------------|
| `scan/scan_test.go`       | Pattern-file parsing (comments, blank lines, optional description, malformed lines, bad regexes, empty sets all rejected), matching against content, correct `LineHint` line numbers, and `lineNumber` edge cases (offsets out of range, offset at end of content). |
| `deps/deps_test.go`       | `package.json` parsing across all four dependency maps, dev flagging, extraction of install-time lifecycle scripts (and that non-install scripts like `test` are *not* surfaced), lockfile v3 parsing (root entry skipped, nested `node_modules/a/node_modules/b` resolving to `b`, sorted output), the v1 `dependencies` fallback, and rejection of invalid JSON. |
| `remote/remote_test.go`   | The full `Inspect` classification ladder — unresolved refs ignored, blocklisted hosts and their subdomains CRITICAL, untrusted registries HIGH, trusted-but-no-integrity MEDIUM, unparseable URLs MEDIUM, clean refs producing no finding. Also: blocklisted hosts are never live-checked even with `Enabled: true`, the live check remains an explicit stub, and host matching is case-insensitive without being spoofable by lookalike prefixes. |
| `report/report_test.go`   | Allowlist round-trip (save sorted with header, reload), parsing of comments and trailing notes after a SHA, missing-file-yields-empty-list behavior, `WriteJSON` normalizing nil slices to `[]`, and `WriteText` output for both clean reports (the `[OK]` line with its no-guarantee caveat) and reports with findings (all three sections, commit list truncation at five with a `(+N more)` suffix). |
| `gitwalk/gitwalk_test.go` | Integration tests against real git history: ref deduplication, commit metadata parsing (including differing author/committer timezones — the forged-metadata signal), unique-blob deduplication when identical content appears at two paths, per-path commit attribution, changed files including the root commit, and retrieving historical file versions without checkout. |

## How the `gitwalk` tests work

Because `gitwalk`'s job is enumerating git history, its tests must run against
a real repository. The fixture (`testRepo`) creates one **inside a throwaway
temp directory** (`t.TempDir()`, auto-deleted when the test ends): it runs
`git init` there, writes two small generated files, and makes two commits plus
a tag. Every git command is pinned to that directory with `git -C <tempdir>`;
the tests never run git against this repository or any other existing repo.

The fixture is hermetic with respect to developer configuration: it sets
`commit.gpgsign=false` and `tag.gpgsign=false` *locally in the temp repo*
(your global config is untouched) so that a signing-enabled environment
doesn't trigger GPG passphrase prompts mid-test, and it pins author/committer
identities, dates, and timezones via environment variables so assertions are
deterministic. If `git` is not installed, these tests skip rather than fail.

The other four packages' tests are pure unit tests: in-memory inputs, temp
files at most, no subprocesses and no network.
