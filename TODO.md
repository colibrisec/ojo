# ojo: planned work

Engineering backlog for expanding scanner functionality, in suggested build order. Excludes `--exit-code`/severity thresholds (handled at the CI/Actions layer, not in ojo) and rpm image support (owned separately).

Each item lists the approach, files touched, new dependencies (if any), and open decisions that need a call before starting. This is a plan, not a commitment to a timeline.

---

## Medium effort

### 1. Rust/Cargo ecosystem (`Cargo.lock`)

**Why first:** `Cargo.lock` is a fully-resolved lockfile — no property placeholders or parent-inheritance to deal with (unlike Maven, below), so it's the cleanest new-ecosystem win.

- New file: `internal/manifest/cargo.go` implementing the existing `manifest.Parser` interface (`Match("Cargo.lock")`, `Parse(path)`).
- Format is TOML (`[[package]]` blocks with `name`, `version`, `source`, `dependencies`). No TOML support exists in the module today — add a dependency (`github.com/pelletier/go-toml/v2` or `github.com/BurntSushi/toml`; the former is actively maintained and has a cleaner v2 API).
- OSV ecosystem string for Rust is `"crates.io"` — add `model.EcosystemCratesIO` alongside the existing `Go`/`npm`/`PyPI`/`Maven` constants.
- Register in `manifest.parsers` (`internal/manifest/manifest.go`) next to `goModParser{}`, `npmLockParser{}`, `pipRequirementsParser{}`.
- Test: mirror `manifest_test.go`'s pattern — write a small `Cargo.lock` fixture, assert parsed packages.

### 2. Java/Maven ecosystem (`pom.xml`)

- New file: `internal/manifest/maven.go`, `Match("pom.xml")`, XML via stdlib `encoding/xml` (no new dependency — XML is fully covered by stdlib, unlike TOML).
- **Real ceiling to design around up front:** `pom.xml` isn't a lockfile. Versions are frequently property placeholders (`${spring.version}`) resolved via a `<properties>` block, parent POM inheritance, or a `<dependencyManagement>` section in a *different* file entirely. A correct, complete implementation means fetching parent POMs and doing full Maven dependency resolution — out of scope.
  - **v1 scope:** parse literal `<dependency>` blocks with a literal `<version>` (direct string, not `${...}`) from the single file. Resolve simple same-file `${property}` substitution against that file's own `<properties>` block (cheap, catches a large fraction of real-world cases). Silently skip anything still unresolved (same pattern as `pip.go` skipping unpinned `requirements.txt` lines) — document this ceiling in a code comment and in `docs/guide/target/filesystem.md`.
- `model.EcosystemMaven` already exists — no model change needed there.
- Decide explicitly: Gradle (`build.gradle`/`build.gradle.kts`) is a Groovy/Kotlin DSL, not data — meaningfully harder to parse than XML. **Not in scope for this item**; call it out as a separate, larger future item if it comes up.

### 3. SARIF output (`-f sarif`)

- Unlocks GitHub code scanning UI integration (`github/codeql-action/upload-sarif` in a workflow) — the most commonly requested CI integration format after JSON.
- SARIF 2.1.0 is a well-defined JSON schema — hand-write the typed structs and marshal with stdlib `encoding/json`, same approach already used for CycloneDX-adjacent code. No new dependency needed; a SARIF library would be overkill for a schema this mechanical.
- New file: `internal/report/sarif.go`. Map both `model.Finding` (vuln) and `model.Issue` (secret/misconfig/sast) into `runs[].results[]`, with `ruleId`, severity → SARIF `level` (`error`/`warning`/`note`), and `locations[].physicalLocation` (file path relative to scan root + line, for `Issue`; package name for `Finding`, which has no line — decide how to represent that gracefully, e.g. `artifactLocation.uri` = the manifest file `Package.Source`).
- Wire into `cli/fs.go` and `cli/image.go`'s existing `format` switch, next to `json`/`sbom`.
- Add `docs/reference/cli.md` and `docs/guide/configuration.md` entries once shipped.

---

## Bigger commitments

### 4. SAST beyond Go

Revisit the cgo tradeoff explicitly before starting — this was already decided once (Go-only, stdlib `go/ast`, no cgo) specifically to avoid breaking cross-compilation. Don't silently reverse that; re-confirm it's worth the cost now.

- **Decision needed:** which language next? Python and JS/TS are the highest-value candidates since the vulnerability scanner already covers their ecosystems (PyPI, npm) — adding SAST for the same languages users are already getting dependency scanning for is a coherent story.
- **Decision needed:** tree-sitter binding choice. `smacker/go-tree-sitter` (cgo, mature, what was evaluated before) vs. checking whether a pure-Go tree-sitter port has matured enough to avoid cgo entirely — worth a fresh look rather than assuming the prior answer still holds.
- Design work: extend `internal/sast/scanner.go`'s `rule` struct (currently `check func(f *ast.File, fset *token.FileSet, path string) []model.Issue`, Go-AST-specific) to support a second, language-tagged predicate shape for tree-sitter nodes — same split already documented in `docs/guide/scanner/sast.md`.
- Build an initial ruleset per new language mirroring the existing Go ruleset's threat coverage (hardcoded secrets, injection, weak crypto, insecure deserialization, etc. — see `docs/guide/scanner/sast.md` for the Go list to mirror).
- Update `docs/guide/scanner/sast.md` and `docs/reference/coverage.md` once a language ships.

### 5. Local/offline vulnerability database

Currently every scan is a live query to OSV.dev (`internal/osv/client.go`) — no offline/air-gapped mode, and no resilience if OSV.dev is unreachable or rate-limits.

- OSV publishes bulk data dumps per ecosystem (GCS bucket, `.zip` per ecosystem) — sync mechanism needs to download and store these.
- Design decisions needed: storage format (embedded DB like bbolt/SQLite vs. flat files), storage location (`~/.cache/ojo/db` following XDG conventions), update cadence/staleness policy, and a `ojo db update`/`--download-db-only`-style subcommand mirroring the pattern most scanners use.
- `internal/osv/client.go`'s `Scan()` needs a second code path that queries the local DB instead of `POST /v1/querybatch` + `GET /v1/vulns/{id}` — same output shape (`[]model.Finding`), different data source, selected via a new `--offline` flag.
- This is real infrastructure (sync, versioning, storage growth over time, corruption/partial-update handling) — size it accordingly before committing to a timeline. Only worth building if air-gapped scanning is an actual requirement, not a nice-to-have.

### 6. Config file support (`.ojo.yaml`)

- Currently flags-only (`--scanners`, `-f/--format`) — no config file, no way to set defaults per-repo.
- `gopkg.in/yaml.v3` is already a dependency (secrets/misconfig scanners) — hand-roll a small config loader rather than pulling in `viper` (heavyweight for what's needed: a handful of fields, no hierarchical env-var binding requirement).
- Design: a `Config` struct mirroring current flag names (`scanners`, `format`, and whatever severity-threshold field the CI-side `--exit-code` work lands on, if ojo ends up needing to know about it — coordinate with that work before finalizing the schema). Precedence: flag > `.ojo.yaml` in cwd (or `--config path`) > built-in default.
- Load the config file early in `cli/root.go` (`PersistentPreRunE`) and use its values as flag defaults before cobra parsing, so explicit flags still win.
- Document in `docs/guide/configuration.md`.

---

## Suggested sequencing

1. Cargo (small, clean win)
2. SARIF (independent of the others, unlocks CI integration)
3. Maven (medium, has a real scoping decision to make up front)
4. Config file (unblocks nothing else, but is cheap and improves ergonomics for everything above)
5. SAST beyond Go / local DB — both are genuinely large; pick whichever has an actual driving need rather than doing both speculatively
