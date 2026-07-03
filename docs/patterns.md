# IOC pattern files

The `scan` package loads its indicators from a tab-delimited file:

```
SEVERITY<TAB>NAME<TAB>REGEX<TAB>DESCRIPTION
```

- Lines starting with `#` and blank lines are ignored.
- `DESCRIPTION` is optional; the first three fields are required.
- `REGEX` uses Go [`regexp`](https://pkg.go.dev/regexp/syntax) syntax — no
  shell escaping.
- Loading fails fast on malformed lines, invalid regexes, or an empty set.

## The example set

**`patterns.example.tsv`** in the repo root is a generic starter set showing
the kinds of indicators worth hunting for in git history:

- **Droppers / RCE** — `curl`/`wget` piped straight into a shell, encoded
  PowerShell commands.
- **Obfuscated payloads** — `eval(atob(...))` and `Function`-constructor
  decoding, unusually large base64 blobs, long hex-escape walls.
- **Exfiltration channels** — Discord webhooks, Telegram bot API URLs with
  tokens, raw pastebin fetches.
- **Leaked or planted credentials** — private key blocks, AWS access key IDs,
  GitHub tokens, hardcoded secret-looking assignments.
- **Malicious install vectors** — npm lifecycle scripts that download or eval
  at install time, unprompted `npx --yes` execution.
- **Crypto-theft tooling** — source containing wallet-address regexes
  (clipper behavior) and code hooking the injected web3 provider.

For a real investigation, replace or extend these with the concrete IOCs from
your incident: exact domains, file hashes, malware strings, attacker email
addresses, and so on. The `remote` package's `c2Blocklist` should be populated
from the same incident data (see
[architecture](architecture.md#remote--external-reference-triage)).
