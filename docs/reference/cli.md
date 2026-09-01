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
  -f, --format string              output format: table, json, sbom, sarif (default "table")
  -g, --gitlab                     write GitLab-compatible security reports instead of -f/--format output; runs all scanners
      --ignore-file string         path to a .ojoignore file (default: .ojoignore in the current directory, if present)
      --rules-dir string           directory of custom *.yaml SAST rules (default: <path>/.ojo/rules, if present); runs alongside --scanners sast
      --scanners string            comma-separated scanners to run: vuln, secret, misconfig, sast, quality (default "vuln")
      --secret-git-history         also scan git commit history (current branch) for secrets that were committed and later removed; requires root to be a git repository
      --secret-rules-file string   path to a YAML file of additional secret rules (same shape as the built-in rules), run alongside --scanners secret
```

`path` defaults to `.` (the current directory) if omitted.

### `--scanners quality`

Maintainability smells (complexity, length, nesting, parameter count, duplicate code) — not security findings. Off by default, opt in with `--scanners quality` (combine with others, e.g. `--scanners vuln,quality`). See [Code Quality scanner](../guide/scanner/quality.md) for the full rule list and thresholds. Not included in `-g/--gitlab`'s report set — no GitLab Code Quality (`gl-code-quality-report.json`) writer yet.

### `--rules-dir`

Loads user-authored SAST rules from `--rules-dir` (default `<path>/.ojo/rules`) and runs them alongside the built-in rules whenever `sast` is in `--scanners`. See [SAST scanner: Custom rules](../guide/scanner/sast.md#custom-rules) for the YAML format.

### `--secret-rules-file`

Loads additional secret rules from a YAML file — the same `rules: [...]` shape as the built-in rules (`id`/`description`/`regex`/`keywords`/`minEntropy`/`severity`) — and runs them alongside the built-in rules whenever `secret` is in `--scanners`. A custom rule `id` colliding with a built-in one is a load error.

### `--secret-git-history`

Also scans `git log -p` on the current branch for secrets, so one that was committed and later deleted from the working tree is still caught. Requires `path` to be a git repository. Off by default (can be slow on a repo with a long history); one finding per commit a secret was added in, not deduplicated.

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
  -f, --format string              output format: table, json, sbom, sarif (default "table")
      --ignore-file string         path to a .ojoignore file (default: .ojoignore in the current directory, if present)
      --platform string            image platform to pull as os/arch, e.g. linux/arm64 (default: linux/amd64)
```

`ref` is required — any reference `docker pull` would accept (`nginx:1.25`, `myregistry.example.com/app:latest`, `python@sha256:...`).

## Config file

See [Configuration](../guide/configuration.md#config-file-ojoyaml).

## Risk acceptance (`.ojoignore`)

See [Configuration](../guide/configuration.md#risk-acceptance-ojoignore).

## Exit codes

See [Exit Codes](exit-codes.md).
