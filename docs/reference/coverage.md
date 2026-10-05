# Coverage

What ojo can actually scan today.

## Language ecosystems (`ojo fs`, vulnerability scanner)

| Ecosystem | Manifest | Status |
|---|---|---|
| Go | `go.mod` | ✅ |
| npm | `package-lock.json` (v1 and v2/v3), `yarn.lock` (classic and Berry), `pnpm-lock.yaml` (v5–v9) | ✅ |
| PyPI | `requirements.txt` (pinned `==` only), `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pdm.lock` | ✅ |
| Maven | `pom.xml` (literal + same-file `${property}` versions only), `gradle.lockfile` | ✅ |
| Packagist (PHP) | `composer.lock` | ✅ |
| NuGet (.NET) | `packages.lock.json` (opt-in file) | ✅ |
| Pub (Dart) | `pubspec.lock` | ✅ |
| crates.io (Rust) | `Cargo.lock` | ✅ |
| RubyGems | `Gemfile.lock` | ✅ |
| SwiftURL | `Package.resolved` (Swift Package Manager) | ✅ |
| CocoaPods | `Podfile.lock` | ✅ Matched against OSV's SwiftURL advisories through each pod's git repository (resolved from the public CocoaPods spec CDN). Private pods and pods without a git source are listed but can't be checked. |
| Everything else (Scala/sbt, Elixir, C/C++, ...) | — | ❌ Not implemented. Scala note: libraries publish under Maven coordinates, so the `Maven` ecosystem above already covers them — the blocker is that sbt's `build.sbt` is a Scala program, not data, same reasoning as `build.gradle` being out of scope. |

## Operating systems (`ojo image`)

| OS family | Package manager | Status |
|---|---|---|
| Alpine | apk | ✅ |
| Debian | dpkg | ✅ |
| Ubuntu | dpkg | ✅ |
| RHEL / UBI (7, 8, 9, 10) | rpm | ✅ |
| Rocky Linux | rpm | ✅ |
| AlmaLinux | rpm | ✅ |
| Amazon Linux (2, 2023) | rpm | ✅ Checked against Amazon's own advisories, core repository only |
| Fedora / CentOS / Oracle Linux / SUSE / Amazon Linux 1 / other rpm-based | rpm | ⚠️ Packages are read (`-f sbom` works), but ojo has no advisories it can match for these, so a vulnerability scan is refused with a clear error rather than reporting a misleading zero |

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
| `sbom` (CycloneDX JSON, 1.2–1.7, with package licenses) | ✅ | ✅ |
| `vex` (OpenVEX) | ✅ | ✅ |
| GitLab security reports (`-g`) | ✅ | ❌ |
| SPDX | ❌ | ❌ |

## Vulnerability data source

[OSV.dev](https://osv.dev), queried live (no local database). This means OS package coverage is exactly whatever OSV itself aggregates from those distros' security trackers. The one exception is Amazon Linux, which OSV doesn't cover: its packages are checked against the advisory feed in Amazon's own package repository, also fetched live. `--kev` additionally pulls CISA's Known Exploited Vulnerabilities catalog (cached locally for a day) to annotate findings.

Two other services are queried, each for one purpose: [deps.dev](https://deps.dev) for package licenses in SBOM output (skippable with `--no-license-lookup`), and the CocoaPods spec CDN to resolve pods from a `Podfile.lock`.
