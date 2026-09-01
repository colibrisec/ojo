# CLI Reference

```console
$ ojo --help
ojo is a security scanner for dependencies, secrets, misconfig, and code.

Scanners (--scanners, comma-separated, ojo fs only):
  vuln       known CVEs in dependency manifests (default)
  secret     hardcoded credentials, API keys, tokens
  misconfig  Dockerfile / Kubernetes / Terraform misconfiguration
  sast       source-level issues (Go, Python, JS/TS, PHP, Ruby, Java)
  quality    maintainability smells: complexity, length, nesting, params, duplication

Output formats (-f/--format, both commands):
  table      human-readable box-drawn table (default)
  json       machine-readable
  sbom       CycloneDX SBOM of discovered packages, skips vulnerability scanning
  sarif      SARIF 2.1.0, for GitHub code scanning and similar tooling

Usage:
  ojo [command]

Examples:
  ojo fs .
  ojo fs --scanners vuln,secret,misconfig,sast,quality .
  ojo fs -f sarif . > results.sarif
  ojo fs -g .
  ojo image python:3.14-slim

Available Commands:
  fs          Scan a filesystem path for vulnerabilities, secrets, and misconfiguration
  image       Scan a container image for vulnerable OS packages

Flags:
  -h, --help      help for ojo
  -v, --version   version for ojo
```

## `ojo --version`

```console
$ ojo --version
ojo version v0.1.0
```

Set at build time via `-ldflags -X .../internal/cli.Version=...` — every published binary/package/image reports the release tag it was built from. Building from source without that flag reports `dev`.

## `ojo fs`

```
Usage:
  ojo fs [path] [flags]

Flags:
      --config string              path to a .ojo.yaml config file (default: .ojo.yaml in the current directory, if present)
      --cyclonedx-version string   CycloneDX spec version for -f sbom output, e.g. 1.4 (default: latest)
  -f, --format string              output format: table, json, sbom, sarif, vex (default "table")
  -g, --gitlab                     write GitLab-compatible security reports instead of -f/--format output; runs all scanners
      --ignore-file string         path to a .ojoignore file (default: .ojoignore in the current directory, if present)
      --kev                        flag findings whose CVE is in CISA's Known Exploited Vulnerabilities catalog (confirmed real-world exploitation); annotation only, doesn't affect exit code
      --rules-dir string           directory of custom *.yaml SAST rules (default: <path>/.ojo/rules, if present); runs alongside --scanners sast
      --scanners string            comma-separated scanners to run: vuln, secret, misconfig, sast, quality (default "vuln")
      --secret-git-history         also scan git commit history (current branch) for secrets that were committed and later removed; requires root to be a git repository
      --secret-rules-file string   path to a YAML file of additional secret rules (same shape as the built-in rules), run alongside --scanners secret
      --vex-file string            path to an OpenVEX document; suppresses findings its not_affected/fixed statements cover (matched by product purl and CVE/alias)
```

`path` defaults to `.` (the current directory) if omitted.

### `--scanners quality`

Maintainability smells (complexity, length, nesting, parameter count, duplicate code) — not security findings. Off by default, opt in with `--scanners quality` (combine with others, e.g. `--scanners vuln,quality`). See [Code Quality scanner](../guide/scanner/quality.md) for the full rule list and thresholds. Not included in `-g/--gitlab`'s report set — no GitLab Code Quality (`gl-code-quality-report.json`) writer yet.

### `--rules-dir`

Loads user-authored SAST rules from `--rules-dir` (default `<path>/.ojo/rules`) and runs them alongside the built-in rules whenever `sast` is in `--scanners`. See [SAST scanner: Custom rules](../guide/scanner/sast.md#custom-rules) for the YAML format.

### `--kev`

Cross-references `vuln` scanner findings against [CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — a CVE being in KEV means confirmed real-world exploitation, a stronger signal than CVSS severity alone. Matched findings get a `[KEV: exploited in the wild]` marker in `table` output, `kev`/`kevDateAdded` fields in `json`, and a `kev`/`kevDateAdded` SARIF result property. Annotation only — doesn't change severity, doesn't affect exit code.

The catalog is cached at `~/.cache/ojo/kev.json` (refreshed once a day); if CISA's feed is briefly unreachable, a stale cache is used instead of failing the scan (a warning is printed). Works on both `ojo fs` and `ojo image`.

### `--secret-rules-file`

Loads additional secret rules from a YAML file — the same `rules: [...]` shape as the built-in rules (`id`/`description`/`regex`/`keywords`/`minEntropy`/`severity`) — and runs them alongside the built-in rules whenever `secret` is in `--scanners`. A custom rule `id` colliding with a built-in one is a load error.

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

Writes four report files to the current directory instead of printing `-f/--format` output, for GitLab CI's [Security Dashboard](https://docs.gitlab.com/ee/user/application_security/security_dashboard/):

- `gl-dependency-scanning-report.json` — `vuln` scanner findings
- `gl-sast-report.json` — `sast` and `misconfig` scanner issues (GitLab's own IaC analyzers report under the `sast` category too)
- `gl-secret-detection-report.json` — `secret` scanner issues
- `gl-sbom-report.cdx.json` — CycloneDX SBOM of discovered packages

`-g` runs all four scanners regardless of `--scanners`. Wire the files up as `artifacts:reports:` entries in `.gitlab-ci.yml` (`dependency_scanning`, `sast`, `secret_detection`, `cyclonedx`) so GitLab ingests them into the Security Dashboard.

## `ojo image`

```
Usage:
  ojo image [ref] [flags]

Flags:
      --config string              path to a .ojo.yaml config file (default: .ojo.yaml in the current directory, if present)
      --cyclonedx-version string   CycloneDX spec version for -f sbom output, e.g. 1.4 (default: latest)
  -f, --format string              output format: table, json, sbom, sarif, vex (default "table")
      --ignore-file string         path to a .ojoignore file (default: .ojoignore in the current directory, if present)
      --kev                        flag findings whose CVE is in CISA's Known Exploited Vulnerabilities catalog (confirmed real-world exploitation); annotation only, doesn't affect exit code
      --platform string            image platform to pull as os/arch, e.g. linux/arm64 (default: linux/amd64)
      --vex-file string            path to an OpenVEX document; suppresses findings its not_affected/fixed statements cover (matched by product purl and CVE/alias)
```

`ref` is required — any reference `docker pull` would accept (`nginx:1.25`, `myregistry.example.com/app:latest`, `python@sha256:...`).

## Config file

See [Configuration](../guide/configuration.md#config-file-ojoyaml).

## Risk acceptance (`.ojoignore`)

See [Configuration](../guide/configuration.md#risk-acceptance-ojoignore).

## Exit codes

See [Exit Codes](exit-codes.md).
