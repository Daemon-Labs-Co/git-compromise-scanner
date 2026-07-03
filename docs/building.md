# Building

The module is `github.com/daemon-labs-co/git-compromise-scanner`, pure
standard library, so building is plain Go tooling:

```sh
go build ./...   # compile all packages
go vet ./...     # static checks
```

There is currently **no `cmd/` entry point** — the five packages are a
reusable core, and a driver binary is still to be written. See
[architecture — how a scan fits together](architecture.md#how-a-scan-fits-together)
for the wiring such a driver would implement. Once a
`cmd/git-compromise-scanner/main.go` exists, the binary builds with:

```sh
go build -o git-compromise-scanner ./cmd/git-compromise-scanner
```

(The binary name is already covered by `.gitignore`.)

## Layout

| Package   | Path                 | Responsibility |
|-----------|----------------------|----------------|
| `gitwalk` | `gitwalk/gitwalk.go` | Enumerate git history safely (commits, refs, unique blobs, content) |
| `scan`    | `scan/scan.go`       | Match inert bytes against an IOC pattern set |
| `deps`    | `deps/deps.go`       | Parse JS dependency manifests into normalized references |
| `remote`  | `remote/remote.go`   | Classify external URLs; the only module allowed near the network |
| `report`  | `report/report.go`   | Aggregate findings; manage the known-good blob allowlist; render output |

Full API documentation for every struct and function is in
[architecture.md](architecture.md).
