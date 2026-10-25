# CLI Reference

```console
$ ojo --help
ojo is a security scanner for dependencies, secrets, misconfig, and code.

Scanners (--scanners, comma-separated; ojo image and ojo sbom take vuln and license only):
  vuln       known CVEs in dependency manifests (default)
  secret     hardcoded credentials, API keys, tokens
  misconfig  Dockerfile / Kubernetes / Terraform / CloudFormation / MCP / skill / APK misconfiguration
  sast       source-level issues (Go, Python, JS/TS, PHP, Ruby, Java)
  quality    maintainability smells: complexity, length, nesting, params, duplication
  license    dependency licenses against the policy in .ojo.yaml

Output formats (-f/--format, every command):
  table      human-readable box-drawn table (default)
  json       machine-readable
  sbom       CycloneDX SBOM of discovered packages and their licenses, skips vulnerability scanning
  spdx       SPDX 2.3 JSON SBOM, as sbom
  sarif      SARIF 2.1.0, for GitHub code scanning and similar tooling
  vex        OpenVEX document for the vulnerability findings

Usage:
  ojo [command]

Examples:
  ojo fs .
  ojo fs --scanners vuln,secret,misconfig,sast,quality .
  ojo fs -f sarif . > results.sarif
  ojo fs -g .
  ojo image python:3.14-slim
  ojo sbom bom.cdx.json

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  fs          Scan a filesystem path for vulnerabilities, secrets, and misconfiguration
  help        Help about any command
  image       Scan a container image for vulnerable OS and Node.js packages
  sbom        Scan the packages listed in a CycloneDX or SPDX SBOM for vulnerabilities

Flags:
  -h, --help      help for ojo
  -v, --version   version for ojo

Use "ojo [command] --help" for more information about a command.
```

## `ojo --version`

```console
$ ojo --version
ojo version v0.2.2
```

Set at build time via `-ldflags -X .../internal/cli.Version=...` — every published binary/package/image reports the release tag it was built from. Building from source without that flag reports `dev`.

## `ojo fs`

```
Usage:
  ojo fs [path] [flags]

Flags:
      --config string              path to a .ojo.yaml config file (default: .ojo.yaml in the current directory, if present)
      --cyclonedx-version string   CycloneDX spec version for -f sbom output, e.g. 1.4 (default: latest)
  -f, --format string              output format: table, json, sbom, spdx, sarif, vex (default "table")
  -g, --gitlab                     write GitLab-compatible security reports (gl-dependency-scanning-report.json, gl-sast-report.json, gl-secret-detection-report.json, gl-sbom-report.cdx.json) instead of -f/--format output; runs the vuln, secret, misconfig, and sast scanners, plus quality (and gl-code-quality-report.json) when --scanners or .ojo.yaml includes it
  -h, --help                       help for fs
      --ignore-file string         path to a .ojoignore file (default: .ojoignore in the current directory, if present)
      --kev                        flag findings whose CVE is in CISA's Known Exploited Vulnerabilities catalog (confirmed real-world exploitation); annotation only, doesn't affect exit code
      --no-license-lookup          don't look up package licenses online (deps.dev, CocoaPods); only licenses found locally are used
      --respect-gitignore          skip untracked files that git ignores (e.g. build output, coverage reports); no effect outside a git repository
      --rules-dir string           directory of custom *.yaml SAST rules (default: <path>/.ojo/rules, if present); runs alongside --scanners sast
      --sarif-omit-suppressed      omit results suppressed by .ojoignore or a VEX file from -f sarif output instead of marking them suppressed; for consumers such as GitHub code scanning that ignore SARIF suppressions
      --scanners string            comma-separated scanners to run: vuln, secret, misconfig, sast, quality, license (default "vuln")
      --secret-git-history         also scan git commit history (current branch) for secrets that were committed and later removed; requires root to be a git repository
      --secret-rules-file string   path to a YAML file of additional secret rules (same shape as the built-in rules), run alongside --scanners secret
      --vex-file string            path to an OpenVEX document; suppresses findings its not_affected/fixed statements cover (matched by product purl and CVE/alias)
```

`path` defaults to `.` (the current directory) if omitted.

### `--cyclonedx-version`

Selects the CycloneDX spec version for `-f sbom` output (and `-g`'s `gl-sbom-report.cdx.json`): `1.2` through `1.7`, default `1.7`. Anything else is an error. Works on both `ojo fs` and `ojo image`. See [SBOM](../guide/sbom.md).

### `--scanners quality`

Maintainability smells (complexity, length, nesting, parameter count, duplicate code) — not security findings. Off by default, opt in with `--scanners quality` (combine with others, e.g. `--scanners vuln,quality`). See [Code Quality scanner](../guide/scanner/quality.md) for the full rule list and thresholds, which `.ojo.yaml` can override. With `-g/--gitlab`, its findings go to `gl-code-quality-report.json`.

### `--scanners license`

Checks dependency licenses against the `license` policy in `.ojo.yaml` (an allow or deny list). Off by default, and an error without a policy. See [License scanner](../guide/scanner/license.md).

### `--no-license-lookup`

`-f sbom` (and `-g`'s SBOM), and the license scanner, look up package licenses online: [deps.dev](https://deps.dev) for Go, npm, PyPI, Maven, NuGet, crates.io, and RubyGems packages, and the CocoaPods spec CDN for pods. This flag skips those lookups, so the SBOM contains only licenses recorded locally and needs no network access. Works on both `ojo fs` and `ojo image`. See [SBOM: Licenses](../guide/sbom.md#licenses).

### `--rules-dir`

Loads user-authored SAST rules from `--rules-dir` (default `<path>/.ojo/rules`) and runs them alongside the built-in rules whenever `sast` is in `--scanners`. See [SAST scanner: Custom rules](../guide/scanner/sast.md#custom-rules) for the YAML format.

### `--kev`

Cross-references `vuln` scanner findings against [CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — a CVE being in KEV means confirmed real-world exploitation, a stronger signal than CVSS severity alone. Matched findings get a `[KEV: exploited in the wild]` marker in `table` output, `kev`/`kevDateAdded` fields in `json`, and a `kev`/`kevDateAdded` SARIF result property. Annotation only — doesn't change severity, doesn't affect exit code.

The catalog is cached at `~/.cache/ojo/kev.json` (refreshed once a day); if CISA's feed is briefly unreachable, a stale cache is used instead of failing the scan (a warning is printed). Works on both `ojo fs` and `ojo image`.

### `--secret-rules-file`

Loads additional secret rules from a YAML file — the same `rules: [...]` shape as the built-in rules (`id`/`description`/`regex`/`keywords`/`minEntropy`/`severity`) — and runs them alongside the built-in rules whenever `secret` is in `--scanners`. A custom rule `id` colliding with a built-in one is a load error.

### `--sarif-omit-suppressed`

With `-f sarif`, suppressed results are normally kept in the output as native SARIF `suppressions`. GitHub code scanning doesn't use that property, so those results stay open as alerts. This flag leaves suppressed results (and rules only they used) out of the SARIF entirely, so their alerts close on the next scan. Applies to `ojo fs` and `ojo image`; the exit code and other formats are unaffected.

### `--respect-gitignore`

Skips untracked files that git ignores (build output, coverage reports, local `.env` files), so a scan of a working copy matches what CI sees in a fresh checkout. Off by default, because an ignored file such as a real `.env` on disk is otherwise still scanned. Tracked files are always scanned, even if they match an ignore pattern. No effect outside a git repository or without `git` on `PATH`.

### `--secret-git-history`

Also scans `git log -p` on the current branch for secrets, so one that was committed and later deleted from the working tree is still caught. Requires `path` to be a git repository. Off by default (can be slow on a repo with a long history); one finding per commit a secret was added in, not deduplicated.

### VEX (`-f vex`, `--vex-file`)

[OpenVEX](https://openvex.dev) support, in both directions:

- **`-f vex`** emits an OpenVEX document for the current `vuln` scan's findings. Every statement asserts `status: affected` — ojo has no reachability analysis, so that's the only status it can honestly claim on its own; the value is a standard structure for a human or another tool to annotate further, not a judgment ojo is making.
- **`--vex-file path`** reads an existing OpenVEX document and suppresses any finding covered by a `not_affected` or `fixed` statement (an `affected`/`under_investigation` statement changes nothing). Matched by CVE ID/alias plus the product's `@id`/`identifiers.purl` against ojo's own package-url for that dependency — same purl format as `-f sbom`. Suppressed findings show up in `Report.SuppressedFindings` the same as `.ojoignore` suppressions (native SARIF `suppressions`, omitted elsewhere); applied after `.ojoignore`.

No default path (unlike `.ojoignore`) — only active when `--vex-file` is explicitly passed, and a missing explicit path is an error. Works on both `ojo fs` and `ojo image`.

### `--ignore-file`

Suppresses findings/issues matched by a `--ignore-file` (default `.ojoignore` in the current directory). Applies to every scanner and every output format — see [Configuration: Risk acceptance](../guide/configuration.md#risk-acceptance-ojoignore) for the file format and SARIF's native-suppression behavior.

### `-g/--gitlab`

Writes four report files (five with `quality`) to the current directory instead of printing `-f/--format` output, for GitLab CI's [Security Dashboard](https://docs.gitlab.com/ee/user/application_security/security_dashboard/):

- `gl-dependency-scanning-report.json` — `vuln` scanner findings
- `gl-sast-report.json` — `sast` and `misconfig` scanner issues (GitLab's own IaC analyzers report under the `sast` category too)
- `gl-secret-detection-report.json` — `secret` scanner issues
- `gl-sbom-report.cdx.json` — CycloneDX SBOM of discovered packages
- `gl-code-quality-report.json` — `quality` scanner issues, only when `quality` is in `--scanners` or `.ojo.yaml`

`-g` runs the `vuln`, `secret`, `misconfig`, and `sast` scanners regardless of `--scanners`, adding `quality` only if `--scanners` (or `.ojo.yaml`) asks for it, so existing pipelines don't start failing on code-quality findings. `.ojoignore` and `--vex-file` suppressions apply to the reports, and `--cyclonedx-version` to the SBOM. Wire the files up as `artifacts:reports:` entries in `.gitlab-ci.yml` (`dependency_scanning`, `sast`, `secret_detection`, `cyclonedx`, and `codequality`) so GitLab ingests them into the Security Dashboard.

## `ojo image`

```
Usage:
  ojo image [ref] [flags]

Flags:
      --config string              path to a .ojo.yaml config file (default: .ojo.yaml in the current directory, if present)
      --cyclonedx-version string   CycloneDX spec version for -f sbom output, e.g. 1.4 (default: latest)
  -f, --format string              output format: table, json, sbom, spdx, sarif, vex (default "table")
  -h, --help                       help for image
      --ignore-file string         path to a .ojoignore file (default: .ojoignore in the current directory, if present)
      --kev                        flag findings whose CVE is in CISA's Known Exploited Vulnerabilities catalog (confirmed real-world exploitation); annotation only, doesn't affect exit code
      --no-license-lookup          don't look up package licenses online (deps.dev, CocoaPods); only licenses found locally are used
      --platform string            image platform to pull as os/arch, e.g. linux/arm64 (default: linux/amd64)
      --sarif-omit-suppressed      omit results suppressed by .ojoignore or a VEX file from -f sarif output instead of marking them suppressed; for consumers such as GitHub code scanning that ignore SARIF suppressions
      --scanners string            comma-separated scanners to run: vuln, license (default "vuln")
      --vex-file string            path to an OpenVEX document; suppresses findings its not_affected/fixed statements cover (matched by product purl and CVE/alias)
```

`ref` is required — any reference `docker pull` would accept (`nginx:1.25`, `myregistry.example.com/app:latest`, `python@sha256:...`).

`--kev`, `--vex-file`/`-f vex`, `--ignore-file`, `--cyclonedx-version`, `--no-license-lookup`, and `--sarif-omit-suppressed` behave as described under [`ojo fs`](#ojo-fs). `--scanners` takes `vuln` (default) and `license`; see [License scanner](../guide/scanner/license.md).

### `--platform`

Pulls the given `os/arch` platform of a multi-arch image, e.g. `--platform linux/arm64`. Default: `linux/amd64`.

## `ojo sbom`

```
Usage:
  ojo sbom [file] [flags]

Flags:
      --config string              path to a .ojo.yaml config file (default: .ojo.yaml in the current directory, if present)
      --cyclonedx-version string   CycloneDX spec version for -f sbom output, e.g. 1.4 (default: latest)
  -f, --format string              output format: table, json, sbom, spdx, sarif, vex (sbom and spdx convert the input) (default "table")
  -h, --help                       help for sbom
      --ignore-file string         path to a .ojoignore file (default: .ojoignore in the current directory, if present)
      --kev                        flag findings whose CVE is in CISA's Known Exploited Vulnerabilities catalog (confirmed real-world exploitation); annotation only, doesn't affect exit code
      --no-license-lookup          don't look up package licenses online (deps.dev, CocoaPods); only licenses found locally are used
      --sarif-omit-suppressed      omit results suppressed by .ojoignore or a VEX file from -f sarif output instead of marking them suppressed; for consumers such as GitHub code scanning that ignore SARIF suppressions
      --scanners string            comma-separated scanners to run: vuln, license (default "vuln")
      --vex-file string            path to an OpenVEX document; suppresses findings its not_affected/fixed statements cover (matched by product purl and CVE/alias)
```

Reads a CycloneDX (JSON or XML) or SPDX 2.x JSON SBOM and checks the packages it lists, the same way `ojo image` checks an image's packages. See [SBOM target](../guide/target/sbom.md) for how entries are matched and what gets skipped. With `-f sbom` or `-f spdx` it converts the SBOM instead of scanning it.

`--kev`, `--vex-file`/`-f vex`, `--ignore-file`, `--cyclonedx-version`, `--no-license-lookup`, and `--sarif-omit-suppressed` behave as described under [`ojo fs`](#ojo-fs). `--scanners` takes `vuln` (default) and `license`; see [License scanner](../guide/scanner/license.md).

## Config file

See [Configuration](../guide/configuration.md#config-file-ojoyaml).

## Risk acceptance (`.ojoignore`)

See [Configuration](../guide/configuration.md#risk-acceptance-ojoignore).

## Exit codes

See [Exit Codes](exit-codes.md).
