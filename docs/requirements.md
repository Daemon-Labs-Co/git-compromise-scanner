# Requirements

## Build requirements

- **Go 1.21 or newer.** The module has no third-party dependencies — only the
  Go standard library.

## Runtime requirements

- **`git` on `PATH`.** The `gitwalk` package shells out to git plumbing
  commands (`rev-list`, `cat-file`, `for-each-ref`, `log`, `diff-tree`,
  `show`). Any reasonably modern git works; no unusual features are used.
- **Read access to the target repository directory.** The scanner never
  writes to the repository being scanned and never checks anything out.
- **No network access is required.** By default the tool makes zero outbound
  requests; the optional live-check mode in the `remote` package is off unless
  explicitly enabled (and is currently a stub — see
  [architecture](architecture.md#remote--external-reference-triage)).

## Test requirements

- Everything above, plus `git` for the `gitwalk` integration tests (they
  skip automatically if git is not installed). See [testing](testing.md).
