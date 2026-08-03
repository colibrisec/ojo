# ojo

ojo is an open source security scanner for dependencies, secrets, misconfiguration, and code — a single self-contained Go binary, no daemon, no local database to sync.

```console
$ ojo fs .                    # dependency vulnerabilities + secrets in a repo
$ ojo image python:3.14-slim  # OS package vulnerabilities in a container image
```

## Documentation

Full docs (installation, per-scanner guides, CLI reference, coverage matrix, and an honest list of current limitations) live in **[`docs/`](docs/index.md)**, built with MkDocs Material — build and browse them locally:

```console
$ pip install -r docs-requirements.txt
$ mkdocs serve
```

## Scanners

| Scanner | What it finds | Runs by default |
|---|---|---|
| Vulnerability | Known CVEs in dependency manifests (Go, npm, PyPI) and container OS packages (Alpine, Debian, Ubuntu), via [OSV.dev](https://osv.dev) | ✅ |
| Secret | Hardcoded credentials, API keys, tokens, private keys | ✅ |
| Misconfiguration | Dockerfile / Kubernetes / Terraform security misconfigurations | Opt-in (`--scanners misconfig`) |
| SAST | Injection, weak crypto, and other source-level issues in Go (`go/ast`-based), Python, JavaScript/TypeScript, PHP, Ruby, and Java (tree-sitter-based) | Opt-in (`--scanners sast`) |

Every command also supports `-f sbom` for a CycloneDX SBOM.

## Building from source

Requires Go 1.22+.

```console
$ go build -o ojo .
```

## Status

ojo is young — see [Roadmap & Limitations](docs/roadmap.md) for what isn't supported yet (rpm-based images, non-Go SAST, license scanning, and more).
