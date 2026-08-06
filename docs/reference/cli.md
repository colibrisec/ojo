# CLI Reference

```console
$ ojo --help
ojo is a security scanner for dependencies, secrets, misconfig, and code.

Scanners (--scanners, comma-separated, ojo fs only):
  vuln       known CVEs in dependency manifests (default)
  secret     hardcoded credentials, API keys, tokens
  misconfig  Dockerfile / Kubernetes / Terraform misconfiguration
  sast       source-level issues (Go, Python, JS/TS, PHP, Ruby, Java)

Output formats (-f/--format, both commands):
  table      human-readable box-drawn table (default)
  json       machine-readable
  sbom       CycloneDX SBOM of discovered packages, skips vulnerability scanning
  sarif      SARIF 2.1.0, for GitHub code scanning and similar tooling

Usage:
  ojo [command]

Examples:
  ojo fs .
  ojo fs --scanners vuln,secret,misconfig,sast .
  ojo fs -f sarif . > results.sarif
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
  -f, --format string     output format: table, json, sbom, sarif (default "table")
      --scanners string   comma-separated scanners to run: vuln, secret, misconfig, sast (default "vuln")
```

`path` defaults to `.` (the current directory) if omitted.

## `ojo image`

```
Usage:
  ojo image [ref] [flags]

Flags:
  -f, --format string   output format: table, json, sbom, sarif (default "table")
```

`ref` is required — any reference `docker pull` would accept (`nginx:1.25`, `myregistry.example.com/app:latest`, `python@sha256:...`).

## Exit codes

See [Exit Codes](exit-codes.md).
