# ojo

[![ojo-scanner](https://snapcraft.io/ojo-scanner/badge.svg)](https://snapcraft.io/ojo-scanner)
[![ojo-scanner](https://snapcraft.io/ojo-scanner/trending.svg?name=0)](https://snapcraft.io/ojo-scanner)

ojo is an open source security scanner for dependencies, secrets, misconfiguration, and code — a single self-contained Go binary, no daemon, no local database to sync.

```console
$ ojo fs .                    # dependency vulnerabilities in a repo
$ ojo image python:3.14-slim  # OS package vulnerabilities in a container image
```

## Installation

```console
$ brew tap colibrisec/tap && brew install ojo        # macOS
$ sudo apt install ./ojo_X.Y.Z_linux_amd64.deb        # Debian/Ubuntu
$ sudo dnf install ojo_X.Y.Z_linux_amd64.rpm           # Fedora/RHEL
$ sudo snap install ojo-scanner && sudo snap alias ojo-scanner.ojo ojo  # Linux (Snap)
$ winget install colibrisec.ojo                        # Windows
$ docker run --rm ghcr.io/colibrisec/ojo:latest fs --help  # Container
$ go install github.com/colibrisec/ojo@latest          # go install
```

Prebuilt binaries (Linux/macOS/Windows, amd64+arm64) and checksums are on the [Releases page](https://github.com/colibrisec/ojo/releases). Full install instructions, including MSI/deb/rpm download URLs and Snap confinement caveats, are in [`docs/getting-started/installation.md`](docs/getting-started/installation.md).

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
| Secret | Hardcoded credentials, API keys, tokens, private keys | Opt-in (`--scanners secret`) |
| Misconfiguration | Dockerfile / Kubernetes / Terraform security misconfigurations | Opt-in (`--scanners misconfig`) |
| SAST | Injection, weak crypto, and other source-level issues in Go (`go/ast`-based), Python, JavaScript/TypeScript, PHP, Ruby, and Java (tree-sitter-based) | Opt-in (`--scanners sast`) |

Every command also supports `-f sbom` for a CycloneDX SBOM.

## Building from source

Requires Go 1.22+.

```console
$ git clone https://github.com/colibrisec/ojo.git && cd ojo
$ go build -o ojo .
```

## Status

ojo is young — see [Roadmap & Limitations](docs/roadmap.md) for what isn't supported yet (rpm-based container images, dependency license scanning, and more).

## License

[GPL-2.0](LICENSE)
