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

### SARIF output (`-f sarif`) — ✅ shipped

- `internal/report/sarif.go`: hand-written SARIF 2.1.0 structs + stdlib `encoding/json`, no new dependency.
- **Validated against the official schema, not just eyeballed**: fetched `oasis-tcs/sarif-spec`'s actual schema file (note: it lives at `sarif-2.1/schema/sarif-schema-2.1.0.json` on the `main` branch — several commonly-cited URLs for this file, including the one initially used here, point at a stale `master`/`Schemata/` path that 404s) and ran a real scan's output through `jsonschema.Draft7Validator` — confirmed valid.
- Rules are deduped by ID across results (two findings citing the same CVE produce one `rules[]` entry, two `results[]` entries). Severity maps CRITICAL/HIGH→`error`, MEDIUM/MODERATE→`warning`, LOW/INFO→`note`, UNKNOWN→`warning` (not silently dropped/hidden). `Finding` locations (package-level, no line number) correctly omit `region`; `Issue` locations include it when `Line > 0`.
- Wired into `cli/fs.go` and `cli/image.go`'s `format` switch alongside `json`/`sbom`. Documented in `docs/reference/cli.md` and `docs/guide/configuration.md` (with a copy-pasteable `github/codeql-action/upload-sarif` snippet).

---

## Bigger commitments

### SAST beyond Go — Python ✅ shipped, JS/TS ✅ shipped, PHP ✅ shipped, Ruby ✅ shipped, Java ✅ shipped

Python shipped via `gotreesitter` (`github.com/odvcencio/gotreesitter`), a pure-Go tree-sitter runtime — no cgo, cross-compilation unaffected (verified: `CGO_ENABLED=0` builds for `linux/arm64` and `darwin/arm64` both succeed). This was not the first choice tried:

- `go-python/gpython` (mature, pure-Go, BSD-3) was evaluated first and **rejected after verification**: its parser cannot parse f-strings, the walrus operator, or `match` statements — confirmed with a real test program, not assumed. Since unparseable files are silently skipped (same policy as Go), shipping on gpython would have meant silent near-total under-coverage on real modern Python, the exact "silent zero-results" failure mode this file already warns about for OSV ecosystem strings.
- `gotreesitter` was verified the same way before adopting it: a test program confirmed it correctly parses f-strings (including interpolation as a distinct node — the structural signal the SQL/command-injection rules rely on), walrus, `match`, and type hints. It works by loading grammar tables extracted from upstream `tree-sitter-python`'s actual C source, reimplementing only the runtime/query engine in Go — not a from-scratch grammar reimplementation. Real caveat: the project is young (first commit ~2026-02, 543 stars at adoption time), a genuine risk tradeoff versus a decade-hardened cgo binding, accepted deliberately in exchange for keeping the no-cgo build story.
- Rules live in `internal/sast/python.go` as compiled tree-sitter queries (11 rules — see `docs/guide/scanner/sast.md`), curated against [semgrep-rules](https://github.com/semgrep/semgrep-rules)' Python ruleset as a reference for which patterns matter, not by executing semgrep's rule engine (that was explicitly considered and declined — see decision history in this session).
- `internal/sast/scanner.go`'s `rule` struct was **not** generalized into a shared multi-language shape — Python got its own parallel `pyRule` type and rule list instead. Two languages didn't justify the abstraction; revisit if a third language lands.

JS/TS/TSX shipped the same way, reusing `gotreesitter`'s javascript/typescript/tsx grammars — the parser choice wasn't re-litigated, but the "verify, don't assume" step was repeated: a test program confirmed all three grammars parse optional chaining, nullish coalescing, template literals, async/await, destructuring, private class fields, BigInt, dynamic import, decorators, generics, `as`-casts, and JSX (in both plain-JS and TSX files) with zero parse errors, before any rule was written.

- `.tsx` gets its own grammar (`TsxLanguage()`), not shared with plain `.ts` — confirmed directly that compiling a JSX-referencing query against the `typescript` grammar fails (`unknown node type "jsx_attribute"`), i.e. plain TypeScript's symbol table genuinely has no JSX support, this isn't a naming convention to just reuse.
- Confirmed the three grammars share identical field names/node shapes for the core JS subset (`variable_declarator`, `call_expression`, `member_expression`, `binary_expression`, etc.) — the same query source compiles against all three, so most rules are one query compiled three times (`mustTriQuery`) rather than three hand-written variants.
- Rules live in `internal/sast/javascript.go` (11 rules — see `docs/guide/scanner/sast.md`), curated against semgrep-rules' javascript/typescript rulesets the same way Python's were.
- **Bug caught during this work, worth remembering:** `Node.Text(source []byte)` slices into `source` by byte offset; passing `nil` for `source` silently returns `""` for any non-root node instead of panicking or erroring. Three call sites (JS's `+`-concatenation check, JS's `req`-root-identifier check, Python's `.format()` check) initially passed `nil` and silently never matched — caught by a targeted regression test that isolated each dynamic-string branch, not by the broader fixture tests (which happened to only exercise the template-literal/f-string branches). Always pass real source bytes to `.Text()`; a "no matches" result from a query-based rule is not proof the pattern is absent.

PHP shipped the same way: a test program confirmed `gotreesitter`'s php grammar parses enums, readonly properties, named arguments, the nullsafe operator (`?->`), match expressions, attributes (`#[...]`), union types, first-class callable syntax (`strlen(...)`), arrow functions, spread in calls, and constructor property promotion cleanly, before any rule was written.

- Single-quoted PHP strings are node type `string`; double-quoted (interpolated or not) and heredocs are `encapsed_string`/`heredoc` — this wasn't obvious from the language and was confirmed by dumping the parse tree before writing the dynamic-string check (`phpIsDynamicString` in `internal/sast/php.go`), same "verify the shape, don't assume" habit as the field-name checks for JS/Python.
- Rules live in `internal/sast/php.go` (10 rules — see `docs/guide/scanner/sast.md`), curated against semgrep-rules' php ruleset the same way. Notably includes `php-preg-replace-eval-modifier` (the historic `/e`-modifier RCE) and `php-lfi-include` (dynamic `include`/`require`), which don't have a direct analogue in the Go/Python/JS rulesets — PHP-specific classes of bug.
- `php-sql-injection` deliberately covers only `->query(`/`->exec(` (PDO/mysqli OOP style), not procedural `mysqli_query()`/`mysql_query()`/`pg_query()` — different argument signatures per function, and OOP is the dominant modern idiom. Add the procedural forms if they turn out to matter.
- Re-applied the `.Text(nil)` lesson from the JS/TS work above: every `.Text()` call in `php.go` passes the real source buffer; grepped for `.Text(nil)` before calling this done, found none.

Ruby shipped the same way: a test program confirmed `gotreesitter`'s ruby grammar parses safe navigation (`&.`), pattern matching (`case/in`), endless methods, keyword arguments, hash shorthand, heredocs, backticks/`%x{}` subshells, and numbered block parameters (`_1`) cleanly, before any rule was written.

- Rules live in `internal/sast/ruby.go` (10 rules — see `docs/guide/scanner/sast.md`), curated against semgrep-rules' ruby ruleset the same way. Includes two Rails-specific classes with no analogue elsewhere: `ruby-mass-assignment` (`params.permit!`, a strong-parameters bypass) and `ruby-open-redirect` (`redirect_to` fed from `params`/`request`).
- **A second instance of the JS/TS `.Text(nil)` mistake happened here, worth remembering harder this time:** `hasDescendant` (a helper defined in `php.go`, shared across files) hardcoded `phpLang` inside `c.Type(phpLang)` regardless of which language's node it was actually walking. Called from Ruby's `rubyIsDynamicString` on a Ruby `string` node's `interpolation` child, it silently looked up Ruby's numeric symbol ID in *PHP's* symbol table — and got lucky for the backtick/subshell case (fired correctly) but silently failed for the plain-string-with-interpolation case (`ruby-sql-injection` didn't fire on `User.where("...#{x}...")`), because the same wrong-language lookup landed on a different (wrong) name for a different symbol ID. Caught by the full fixture test, not a targeted one — this time. Fixed by giving `hasDescendant` an explicit `*gts.Language` parameter; added a dedicated regression test (`TestRubySQLInjectionViaStringInterpolation`) so it can't silently regress. **The generalizable lesson:** any helper shared across `python.go`/`javascript.go`/`php.go`/`ruby.go` that touches a `*gts.Node` needs its language passed in explicitly — never hardcode one language's global inside a "shared" helper, and grep every shared function for a hardcoded `xxxLang` before calling a new language integration done.

Java shipped the same way: a test program confirmed `gotreesitter`'s java grammar parses records, sealed interfaces/`permits`, switch expressions (`->`), text blocks (`"""`), `var`, lambdas, try-with-resources, and `instanceof` pattern matching cleanly, before any rule was written.

- Rules live in `internal/sast/java.go` (9 rules — see `docs/guide/scanner/sast.md`), curated against semgrep-rules' java ruleset the same way. Includes `java-xxe` (flags `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory.newInstance()` unconditionally, since XXE hardening is an opt-in a simple query can't verify the absence of) and `java-tls-trust-manager-bypass` (flags any custom `X509TrustManager`/`HostnameVerifier` implementation, same unconditional-flag reasoning) — enterprise-Java-specific bug classes with no direct analogue in the other languages' rulesets.
- Re-applied both lessons from the Ruby work above before calling this done: grepped `java.go` for `.Text(nil)` (none), and grepped every shared cross-language helper (`hasDescendant`, `nameLooksSecret`) to confirm none of them hardcode a specific `*gts.Language` — `java.go` always compiles its own queries against `javaLang` and passes it explicitly to every `.Type()`/`.Text()` call.
- Java's `+` string concatenation is the only "dynamic string" signal needed (unlike Python/JS/Ruby/PHP, there's no interpolation syntax to also check pre-text-blocks) — `javaIsDynamicString` is correspondingly the simplest of the five language's dynamism checks.

Everything beyond Go/Python/JS/TS/TSX/PHP/Ruby/Java is still out of scope — evaluate the next language's candidate parser from scratch the same way, don't assume gotreesitter's grammar table for it is as solid as these are without testing it.

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
2. ~~SARIF~~ — shipped.
3. Config file (unblocks nothing else, but is cheap and improves ergonomics for everything above) — up next.
4. SAST beyond Go / local DB / mobile binary scanning — all three are genuinely large and independent; pick whichever has an actual driving need rather than doing them speculatively. If mobile comes up, start with Android manifest/permission analysis only (smallest real slice, see that section).
