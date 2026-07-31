# Scanner: SAST

Static analysis over Go source, using the standard library's `go/ast` — no external parser dependency, no cgo.

Off by default — enable with `--scanners sast`.

## Language scope: Go only

Rules are hand-written Go predicates over `go/ast` nodes (`ast.Inspect`). This was a deliberate scope decision, not an oversight: a real multi-language engine needs a proper parser per language (e.g. tree-sitter), and the common Go binding for that is **cgo-based** — it needs a C toolchain at build time, which breaks `GOOS=x GOARCH=y go build` cross-compilation working out of the box. Go source gets the stdlib parser for free; every other language would cost the whole project its pure-Go build story. So: Go now, other languages later, behind an explicit decision about that build tradeoff.

## Built-in rules (9)

| Rule | Severity | Detects |
|---|---|---|
| `go-hardcoded-secret` | MEDIUM | A literal string assigned to a variable named `password`/`secret`/`apikey`/`token` |
| `go-command-injection` | HIGH | `os/exec.Command`/`CommandContext` with an argument built via `fmt.Sprintf`/string concatenation instead of a literal |
| `go-sql-injection` | HIGH | `database/sql` `Query`/`Exec`/`QueryRow` (and `...Context` variants) with a query string built via `fmt.Sprintf`/concatenation instead of a literal/placeholders |
| `go-weak-hash` | LOW | `crypto/md5` or `crypto/sha1` usage |
| `go-weak-cipher-des` | MEDIUM | `crypto/des` usage |
| `go-insecure-random-for-secrets` | INFO | `math/rand` used inside a function whose name suggests it generates a token/session/key/secret |
| `go-discarded-auth-error` | HIGH | An auth-relevant call (`.Verify(`, `.Authenticate(`, `bcrypt.CompareHashAndPassword`) used as a bare statement, discarding its error return |
| `go-tls-insecure-skip-verify` | HIGH | `tls.Config{InsecureSkipVerify: true}` |
| `go-permissive-file-mode` | MEDIUM | `os.OpenFile`/`os.MkdirAll`/`os.Chmod` called with mode `0777`/`0666` |

## Honest ceiling

This is a curated AST-aware linter, not a Semgrep replacement — yet. Specifically it has:

- **No taint tracking.** Rules flag syntactic *candidates* (e.g. "this SQL query is built with `fmt.Sprintf`"); they can't trace whether the interpolated value actually originates from untrusted input. Expect a real false-positive rate that needs human triage.
- **No interprocedural analysis.** Each function body is analyzed alone; there's no call graph.
- **No metavariables / pattern language.** You can't write a generic `$DB.Query($QUERY, ...)`-style pattern — every check is bespoke Go code. This is the biggest gap versus what "SAST" usually implies at Semgrep's level of expressiveness.

Rules that overlap with the [secret scanner](secret.md) (`go-hardcoded-secret`) are intentional, not redundant: the secret scanner does line-level regex over raw text; this rule works on the actual AST assignment node, catching multi-line/formatted literals the regex misses and correctly ignoring matches inside comments or non-assignment string literals.
