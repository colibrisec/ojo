# Coverage

What ojo can actually scan today.

## Language ecosystems (`ojo fs`, vulnerability scanner)

| Ecosystem | Manifest | Status |
|---|---|---|
| Go | `go.mod` | ✅ |
| npm | `package-lock.json` (v1 and v2/v3) | ✅ |
| PyPI | `requirements.txt` (pinned `==` only), `Pipfile.lock`, `poetry.lock` | ✅ |
| Maven | `pom.xml` (literal + same-file `${property}` versions only), `gradle.lockfile` | ✅ |
| Packagist (PHP) | `composer.lock` | ✅ |
| NuGet (.NET) | `packages.lock.json` (opt-in file) | ✅ |
| Pub (Dart) | `pubspec.lock` | ✅ |
| crates.io (Rust) | `Cargo.lock` | ✅ |
| RubyGems | `Gemfile.lock` | ✅ |
| SwiftURL | `Package.resolved` (Swift Package Manager) | ✅ |
| npm (other lockfiles) | `yarn.lock`, `pnpm-lock.yaml` | ❌ Not implemented — only `package-lock.json` is read |
| PyPI (other lockfiles) | `uv.lock`, `pdm.lock` | ❌ Not implemented |
| CocoaPods | `Podfile.lock` | ❌ Not possible via OSV — no CocoaPods ecosystem exists in OSV's schema |
| Everything else (Scala/sbt, Elixir, C/C++, ...) | — | ❌ Not implemented. Scala note: libraries publish under Maven coordinates, so the `Maven` ecosystem above already covers them — the blocker is that sbt's `build.sbt` is a Scala program, not data, same reasoning as `build.gradle` being out of scope. |

## Operating systems (`ojo image`)

| OS family | Package manager | Status |
|---|---|---|
| Alpine | apk | ✅ |
| Debian | dpkg | ✅ |
| Ubuntu | dpkg | ✅ |
| RHEL / CentOS / Fedora / Amazon Linux / Rocky / AlmaLinux | rpm | ❌ Detected but explicitly rejected with a clear error, rather than silently returning zero packages |

`ojo image` also reports vulnerable Node.js packages installed in the image, found through `node_modules/<package>/package.json` (including the npm bundled with Node.js base images). Other language runtimes are not scanned inside images yet. A `scratch`-style image with no OS at all is scanned for Node.js packages only. Images are pulled as `linux/amd64` unless `--platform` says otherwise.

## IaC / misconfiguration formats

| Format | Status |
|---|---|
| Dockerfile | ✅ |
| Kubernetes YAML | ✅ (raw manifests only — no Helm/Kustomize rendering) |
| Terraform (AWS/Azure/GCP providers) | ✅ (`local`/`var` defaults resolved within one directory — no module graph traversal) |
| CloudFormation (YAML or JSON) | ✅ (literal values only — unresolved intrinsic functions like `!Ref`/`!Sub` are skipped, not guessed at) |
| MCP server configs (JSON) | ✅ (static config only — a server's live `tools/list` response isn't inspected) |
| Claude Code skill definitions (`SKILL.md`) | ✅ |
| Android manifests (inside `*.apk`) | ✅ (literal attribute values only — resource references aren't resolved) |
| Azure ARM (native JSON templates), Ansible, Helm charts | ❌ |

## SAST languages

| Language | Status |
|---|---|
| Go | ✅ (`go/ast`-based, 19 rules) |
| Python | ✅ (`gotreesitter`-based, 28 rules) |
| JavaScript / TypeScript / TSX | ✅ (`gotreesitter`-based, 24 rules; `.js`/`.jsx`/`.mjs`/`.cjs`/`.ts`/`.mts`/`.cts`/`.tsx`) |
| PHP | ✅ (`gotreesitter`-based, 25 rules) |
| Ruby | ✅ (`gotreesitter`-based, 24 rules) |
| Java | ✅ (`gotreesitter`-based, 23 rules) |
| Everything else | ❌ — see [SAST scanner](../guide/scanner/sast.md) for why |

Custom rules (`--rules-dir`) are supported for every language above except Go.

## Code quality languages (`--scanners quality`)

| Language | Status |
|---|---|
| Go | ✅ |
| Python | ✅ |
| JavaScript / TypeScript / TSX | ✅ |
| PHP | ✅ |
| Ruby | ✅ |
| Java | ✅ |

Same six languages as the SAST scanner, all four AST metrics (complexity/length/nesting/parameter-count) and TODO/FIXME comment tracking cover all six. Duplicate-code detection is language-agnostic (line-based) and isn't scoped per-language the same way. See [Code Quality scanner](../guide/scanner/quality.md).

## Output formats

| Format | `ojo fs` | `ojo image` |
|---|---|---|
| `table`, `json` | ✅ | ✅ |
| `sarif` (SARIF 2.1.0) | ✅ | ✅ |
| `sbom` (CycloneDX JSON, 1.2–1.7) | ✅ | ✅ |
| `vex` (OpenVEX) | ✅ | ✅ |
| GitLab security reports (`-g`) | ✅ | ❌ |
| SPDX | ❌ | ❌ |

## Vulnerability data source

[OSV.dev](https://osv.dev) only, queried live (no local database). This means Alpine/Debian/Ubuntu coverage is exactly whatever OSV itself aggregates from those distros' security trackers. `--kev` additionally pulls CISA's Known Exploited Vulnerabilities catalog (cached locally for a day) to annotate findings.
