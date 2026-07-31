# CLI Reference

```console
$ ojo --help
ojo is a security scanner for dependencies, secrets, misconfig, and code

Usage:
  ojo [command]

Available Commands:
  fs          Scan a filesystem path for vulnerabilities, secrets, and misconfiguration
  image       Scan a container image for vulnerable OS packages
```

## `ojo fs`

```
Usage:
  ojo fs [path] [flags]

Flags:
  -f, --format string     output format: table, json, sbom (default "table")
      --scanners string   comma-separated scanners to run: vuln, secret, misconfig, sast (default "vuln,secret")
```

`path` defaults to `.` (the current directory) if omitted.

## `ojo image`

```
Usage:
  ojo image [ref] [flags]

Flags:
  -f, --format string   output format: table, json, sbom (default "table")
```

`ref` is required — any reference `docker pull` would accept (`nginx:1.25`, `myregistry.example.com/app:latest`, `python@sha256:...`).

## Exit codes

See [Exit Codes](exit-codes.md).
