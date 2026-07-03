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

- **No checkouts, no execution.** All git access is read-only plumbing
  (`rev-list`, `cat-file`, `for-each-ref`, `log`, `diff-tree`, `show`). File
  content is handled as inert bytes and only ever matched against regexes.
- **No network by default.** Only the `remote` package may touch the network,
  and only when explicitly enabled — and even then it never contacts hosts on
  the C2 blocklist and never downloads payloads.
- **Manifests are parsed as data.** `package.json` / `package-lock.json` are
  JSON-decoded; npm is never run and lifecycle scripts are never executed
  (they are *surfaced* as findings instead).

## Quick start

```sh
go build ./...   # requires Go 1.21+; git must be on PATH at runtime
go test ./...
```

## Documentation

| Document | Contents |
|----------|----------|
| [docs/requirements.md](docs/requirements.md) | Build, runtime, and test requirements |
| [docs/building.md](docs/building.md)         | Build commands and package layout |
| [docs/architecture.md](docs/architecture.md) | Full reference for every package, struct, and function, plus how a scan fits together |
| [docs/patterns.md](docs/patterns.md)         | IOC pattern file format and the bundled example set |
| [docs/testing.md](docs/testing.md)           | What each test file covers and how the git-fixture tests work |

## Naming note

The `gitwalk/` package keeps its own name rather than the project's: it is the
component that *walks* git history (commits, refs, blobs) and is deliberately
reusable outside this scanner. The project as a whole is
`git-compromise-scanner`, module path
`github.com/daemon-labs-co/git-compromise-scanner`.

## Status

The five packages (`gitwalk`, `scan`, `deps`, `remote`, `report`) are the
reusable core; a `cmd/` driver binary is still to be written.

## License

Released under the [MIT License](LICENSE).
