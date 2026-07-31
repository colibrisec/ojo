# ojo: planned work

Engineering backlog for expanding scanner functionality, in suggested build order. Excludes `--exit-code`/severity thresholds (handled at the CI/Actions layer, not in ojo) and rpm image support (owned separately).

Each item lists the approach, files touched, new dependencies (if any), and open decisions that need a call before starting. This is a plan, not a commitment to a timeline.

---

## Medium effort

### New ecosystem parsers, as many as reasonably possible — ✅ shipped

Same pattern every time: implement `manifest.Parser` (`Match`, `Parse`), register in `manifest.parsers` (`internal/manifest/manifest.go`), add a `model.Ecosystem` constant, write a fixture + test mirroring `manifest_test.go`. The real cost differences are (a) whether the format needs a new dependency and (b) whether it's a fully-resolved lockfile (cheap, accurate) or a source manifest with placeholders/inheritance (has a real ceiling, same shape as the `requirements.txt`-pinned-only precedent).

All six tiers below shipped. Every OSV ecosystem string was verified end-to-end against the live API with a real known-vulnerable package+version before being committed (not just unit-tested) — see the commit history for the actual CVEs each one turned up. Cross-manifest dedup also landed (`manifest.Discover` now dedupes by name+version+ecosystem across files, since PyPI alone has three sources now).

OSV ecosystem strings below are **verified against the live API** with a known-vulnerable package+version each, not assumed — getting one wrong means silent zero-results, the worst failure mode for a security tool.

**Tier 1 — free (stdlib `encoding/json`, no new dependency):**

| Ecosystem | File | OSV ecosystem string | Notes |
|---|---|---|---|
| PHP / Composer | `composer.lock` | `Packagist` | Fully-resolved lockfile, flat `packages`/`packages-dev` arrays. |
| Python / Pipenv | `Pipfile.lock` | `PyPI` | JSON, `default`/`develop` sections. Same ecosystem as existing `requirements.txt` support — packages from both should just merge. |
| .NET / NuGet | `packages.lock.json` | `NuGet` | JSON, nested by target framework (`"net6.0": {...}`) — flatten across frameworks, dedupe by name. **Caveat:** opt-in file (`RestorePackagesWithLockFile=true`); most .NET projects won't have it yet. |

**Tier 2 — free (`gopkg.in/yaml.v3`, already a dependency):**

| Ecosystem | File | OSV ecosystem string | Notes |
|---|---|---|---|
| Dart / Pub | `pubspec.lock` | `Pub` | YAML, fully-resolved lockfile. |

**Tier 3 — one new dependency (TOML), amortized across two ecosystems:**

- Add `github.com/pelletier/go-toml/v2` (actively maintained, clean v2 API) once; both parsers below share it.

| Ecosystem | File | OSV ecosystem string | Notes |
|---|---|---|---|
| Rust / Cargo | `Cargo.lock` | `crates.io` | Fully-resolved lockfile, `[[package]]` blocks. Cleanest win in this tier — no placeholders. |
| Python / Poetry | `poetry.lock` | `PyPI` | Same TOML shape as Cargo.lock. Same ecosystem as `requirements.txt`/`Pipfile.lock` — again, merge rather than duplicate-report. |

**Tier 4 — hand-rolled parser, no new dependency (custom text formats):**

| Ecosystem | File | OSV ecosystem string | Notes |
|---|---|---|---|
| Ruby / Bundler | `Gemfile.lock` | `RubyGems` | Custom indented text format (`GEM` block, `specs:` section, `  name (version)` lines) — small line-based parser, same idiom as `internal/misconfig/dockerfile.go`'s hand-rolled parser. |
| Java / Gradle | `gradle.lockfile` | `Maven` | Plain text, one `group:artifact:version=configurations` line per resolved dependency. **Opt-in** (Gradle dependency locking must be enabled) — sidesteps parsing the Groovy/Kotlin DSL entirely by only supporting this resolved-lockfile format, not `build.gradle` itself. |

**Tier 5 — has a real ceiling, do last:**

| Ecosystem | File | OSV ecosystem string | Notes |
|---|---|---|---|
| Java / Maven | `pom.xml` | `Maven` | Not a lockfile — property placeholders (`${spring.version}`), parent POM inheritance, and `<dependencyManagement>` in other files all affect the real resolved version. **v1 scope:** literal `<version>` values plus same-file `${property}` substitution only; silently skip anything still unresolved (same pattern as `pip.go`). Full Maven resolution (fetching parent POMs) is out of scope. |

**Tier 6 — free (stdlib `encoding/json`), shipped separately after the above:**

| Ecosystem | File | OSV ecosystem string | Notes |
|---|---|---|---|
| Swift / SwiftURL | `Package.resolved` | `SwiftURL` | Handles both the v1 (pre-Xcode 13, `{"object":{"pins":[...]}}`) and v2/v3 (`{"pins":[...]}`) shapes. Packages are matched by **repository URL**, not name (`https://github.com/apple/swift-nio.git` → `github.com/apple/swift-nio`) — verified against a live known-vulnerable version before shipping. Branch/revision-pinned deps with no tagged version are skipped (nothing to match against a SemVer-tag ecosystem). |

**Explicitly out of scope, not just deferred:**
- `build.gradle`/`build.gradle.kts` (Groovy/Kotlin DSL, not data — meaningfully harder than any of the above; `gradle.lockfile` above covers the same ecosystem without this cost).
- **CocoaPods (`Podfile.lock`)** — checked OSV's schema directly: there is no CocoaPods ecosystem defined at all. Not a parsing-effort problem; there's nowhere to send the query regardless of how well `Podfile.lock` gets parsed. Only revisit if OSV adds one.
- **Scala/sbt (`build.sbt`)** — no dedicated Scala ecosystem either, but not needed: Scala libraries publish under Maven coordinates (e.g. `com.typesafe.akka:akka-http_2.13`), so the existing `Maven` ecosystem support already covers them correctly (verified live). The actual blocker is identical to Gradle's: `build.sbt` is a Scala program, not data. The opt-in [`sbt-dependency-lock`](https://github.com/stringbean/sbt-dependency-lock) plugin generates a JSON lockfile that would sidestep this the same way `gradle.lockfile` does — worth adding as its own small item *if* that plugin's adoption is common enough to matter; it's meaningfully less standard than Gradle's built-in locking, so verify real-world usage before investing.

### SARIF output (`-f sarif`)

- Unlocks GitHub code scanning UI integration (`github/codeql-action/upload-sarif` in a workflow) — the most commonly requested CI integration format after JSON.
- SARIF 2.1.0 is a well-defined JSON schema — hand-write the typed structs and marshal with stdlib `encoding/json`, same approach already used for CycloneDX-adjacent code. No new dependency needed; a SARIF library would be overkill for a schema this mechanical.
- New file: `internal/report/sarif.go`. Map both `model.Finding` (vuln) and `model.Issue` (secret/misconfig/sast) into `runs[].results[]`, with `ruleId`, severity → SARIF `level` (`error`/`warning`/`note`), and `locations[].physicalLocation` (file path relative to scan root + line, for `Issue`; package name for `Finding`, which has no line — decide how to represent that gracefully, e.g. `artifactLocation.uri` = the manifest file `Package.Source`).
- Wire into `cli/fs.go` and `cli/image.go`'s existing `format` switch, next to `json`/`sbom`.
- Add `docs/reference/cli.md` and `docs/guide/configuration.md` entries once shipped.

---

## Bigger commitments

### SAST beyond Go

Revisit the cgo tradeoff explicitly before starting — this was already decided once (Go-only, stdlib `go/ast`, no cgo) specifically to avoid breaking cross-compilation. Don't silently reverse that; re-confirm it's worth the cost now.

- **Decision needed:** which language next? Python and JS/TS are the highest-value candidates since the vulnerability scanner already covers their ecosystems (PyPI, npm) — adding SAST for the same languages users are already getting dependency scanning for is a coherent story.
- **Decision needed:** tree-sitter binding choice. `smacker/go-tree-sitter` (cgo, mature, what was evaluated before) vs. checking whether a pure-Go tree-sitter port has matured enough to avoid cgo entirely — worth a fresh look rather than assuming the prior answer still holds.
- Design work: extend `internal/sast/scanner.go`'s `rule` struct (currently `check func(f *ast.File, fset *token.FileSet, path string) []model.Issue`, Go-AST-specific) to support a second, language-tagged predicate shape for tree-sitter nodes — same split already documented in `docs/guide/scanner/sast.md`.
- Build an initial ruleset per new language mirroring the existing Go ruleset's threat coverage (hardcoded secrets, injection, weak crypto, insecure deserialization, etc. — see `docs/guide/scanner/sast.md` for the Go list to mirror).
- Update `docs/guide/scanner/sast.md` and `docs/reference/coverage.md` once a language ships.

### Local/offline vulnerability database

Currently every scan is a live query to OSV.dev (`internal/osv/client.go`) — no offline/air-gapped mode, and no resilience if OSV.dev is unreachable or rate-limits.

- OSV publishes bulk data dumps per ecosystem (GCS bucket, `.zip` per ecosystem) — sync mechanism needs to download and store these.
- Design decisions needed: storage format (embedded DB like bbolt/SQLite vs. flat files), storage location (`~/.cache/ojo/db` following XDG conventions), update cadence/staleness policy, and a `ojo db update`/`--download-db-only`-style subcommand mirroring the pattern most scanners use.
- `internal/osv/client.go`'s `Scan()` needs a second code path that queries the local DB instead of `POST /v1/querybatch` + `GET /v1/vulns/{id}` — same output shape (`[]model.Finding`), different data source, selected via a new `--offline` flag.
- This is real infrastructure (sync, versioning, storage growth over time, corruption/partial-update handling) — size it accordingly before committing to a timeline. Only worth building if air-gapped scanning is an actual requirement, not a nice-to-have.

### Mobile app binary scanning (APK / IPA)

**This is not an ecosystem parser — it's a new target type**, comparable in size to building the container image scanner from scratch (`internal/image/`), not an incremental add. An APK/IPA is a compiled, zipped app bundle, not a dependency manifest with a package-manager database to read the way Debian/Alpine images have `dpkg`/`apk`.

Note what this *isn't*: an Android app's third-party library dependencies are already covered today if the project ships a `gradle.lockfile` (see the Maven/Gradle row above) — that's ordinary dependency scanning, already shipped. This item is specifically about inspecting the **compiled binary** itself.

**Android (APK):**
- An APK is a ZIP: `AndroidManifest.xml`, DEX bytecode, native `.so` libraries, resources.
- Realistic v1 scope, roughly in order of tractability:
  1. **Manifest/permission analysis** — parse `AndroidManifest.xml` (binary XML format, not plain text — needs a decoder, e.g. porting the logic from `androidbinary`/`apk-parser`-style tools) for over-broad permissions, exported components without permission guards, `debuggable="true"`, cleartext traffic allowed, etc. This is genuinely a **misconfiguration scanner extension** (`internal/misconfig/`), not a new scanner class — closest in spirit to the existing Dockerfile/K8s/Terraform checks.
  2. **Embedded native library fingerprinting** — identify bundled `.so` libraries (e.g. OpenSSL, FFmpeg, other C/C++ deps commonly vendored into Android apps) by hash/version signature and check them the same way `internal/image` checks OS packages. Real prior art to lean on rather than reinvent: OWASP's `MobSF` project has done exactly this fingerprinting work.
  3. **DEX bytecode analysis** (secrets in strings, obviously-vulnerable patterns) — much harder; probably out of scope even for a v1 of this v1.
- OSV's `Android` ecosystem exists but covers **AOSP/platform/kernel-level** CVEs (Android Security Bulletin), not app-level findings — not directly usable for "scan my app," more relevant to firmware/OS image scanning, a different and even more niche use case.

**iOS (IPA):**
- Meaningfully harder than APK. IPAs downloaded from the App Store are FairPlay-encrypted — static analysis of the actual executable is blocked without a jailbroken decryption step, which is a legal/ethical gray area to build tooling around. Ad-hoc/enterprise-distributed builds (no App Store encryption) are more tractable, but that's a narrower audience.
- `Info.plist`/entitlements analysis (ATS settings, exported capabilities) is the iOS analogue of `AndroidManifest.xml` misconfig checks and is realistic without touching the encrypted binary — likely the only iOS-side win worth pursuing without the encryption problem.

**Recommendation:** if this gets prioritized, start with Android manifest/permission analysis only (item 1 above) — it's a real, scoped, misconfig-scanner-shaped addition. Native library fingerprinting and anything iOS-binary-related are substantially bigger and should be separate decisions, not bundled into "add mobile support."

### Config file support (`.ojo.yaml`)

- Currently flags-only (`--scanners`, `-f/--format`) — no config file, no way to set defaults per-repo.
- `gopkg.in/yaml.v3` is already a dependency (secrets/misconfig scanners) — hand-roll a small config loader rather than pulling in `viper` (heavyweight for what's needed: a handful of fields, no hierarchical env-var binding requirement).
- Design: a `Config` struct mirroring current flag names (`scanners`, `format`, and whatever severity-threshold field the CI-side `--exit-code` work lands on, if ojo ends up needing to know about it — coordinate with that work before finalizing the schema). Precedence: flag > `.ojo.yaml` in cwd (or `--config path`) > built-in default.
- Load the config file early in `cli/root.go` (`PersistentPreRunE`) and use its values as flag defaults before cobra parsing, so explicit flags still win.
- Document in `docs/guide/configuration.md`.

---

## Suggested sequencing

1. ~~Ecosystem parsers (including Swift/SwiftURL)~~ — shipped.
2. SARIF (independent of the others, unlocks CI integration) — up next.
3. Config file (unblocks nothing else, but is cheap and improves ergonomics for everything above)
4. SAST beyond Go / local DB / mobile binary scanning — all three are genuinely large and independent; pick whichever has an actual driving need rather than doing them speculatively. If mobile comes up, start with Android manifest/permission analysis only (smallest real slice, see that section).
