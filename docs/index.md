# ojo

**ojo** is an open source security scanner for dependencies, secrets, misconfiguration, and code.

It scans:

- **Filesystems and source repos** (`ojo fs`) — dependency manifests across eleven ecosystems, hardcoded secrets, misconfiguration (Dockerfile, Kubernetes, Terraform, CloudFormation, MCP server configs, skill definitions, Android APK manifests), and source-level SAST and code-quality checks across Go, Python, JavaScript/TypeScript, PHP, Ruby, and Java
- **Container images** (`ojo image`) — installed OS packages (apk/dpkg/rpm) and Node.js packages against known vulnerabilities

Vulnerability data comes from [OSV.dev](https://osv.dev), the same aggregated advisory database (GitHub Security Advisories, PyPA, RustSec, Debian/Alpine security trackers, and more) that underpins most modern scanners.

```console
$ ojo image python:3.14-slim
python:3.14-slim (debian 13)
============================
Total: 19 (UNKNOWN: 8, INFO: 0, LOW: 1, MEDIUM: 9, HIGH: 1, CRITICAL: 0)

┌────────────┬────────────────┬──────────┬──────────┬────────────────────┬───────────────┬─────────────────────────────────────────────┐
│  Library   │ Vulnerability  │ Severity │  Status  │ Installed Version  │ Fixed Version │                    Title                     │
├────────────┼────────────────┼──────────┼──────────┼────────────────────┼───────────────┼─────────────────────────────────────────────┤
│ apt        │ CVE-2011-3374  │ LOW      │ affected │ 3.0.3              │               │ It was found that apt-key in apt, all        │
│            │                │          │          │                    │               │ versions, do not correctly validate gpg...   │
├────────────┼────────────────┼──────────┼──────────┼────────────────────┼───────────────┼─────────────────────────────────────────────┤
│ gzip       │ CVE-2026-41992 │ HIGH     │          │ 1.13-1             │               │ GNU gzip contains a global buffer overflow   │
│            │                │          │          │                    │               │ vulnerability in the LZH decompression...    │
└────────────┴────────────────┴──────────┴──────────┴────────────────────┴───────────────┴─────────────────────────────────────────────┘
```

## Why ojo

Most scanners either reimplement vulnerability databases from scratch (unrealistic to maintain) or wrap several third-party tools behind a thin CLI. ojo takes a middle path: it's a single self-contained Go binary that owns its own scanning logic (manifest parsing, secret regexes, misconfiguration checks, a SAST engine built on `go/ast` for Go and tree-sitter queries for everything else), but sources raw vulnerability data from OSV.dev instead of hand-maintaining a CVE feed.

## Scanners

| Scanner | What it finds | Default |
|---|---|---|
| [Vulnerability](guide/scanner/vulnerability.md) | Known CVEs in dependency manifests, and in OS and Node.js packages inside container images | On |
| [Secret](guide/scanner/secret.md) | Hardcoded credentials, API keys, tokens, private keys | Off (`--scanners secret`) |
| [Misconfiguration](guide/scanner/misconfiguration.md) | Security misconfigurations in Dockerfiles, Kubernetes, Terraform, CloudFormation, MCP server configs, skill definitions, and Android APK manifests | Off (`--scanners misconfig`) |
| [SAST](guide/scanner/sast.md) | Injection, weak crypto, and other source-level issues across Go, Python, JS/TS, PHP, Ruby, and Java | Off (`--scanners sast`) |
| [Code Quality](guide/scanner/quality.md) | Maintainability smells: complexity, length, nesting, parameter count, duplicate code, TODO/FIXME comments | Off (`--scanners quality`) |

## Getting started

Head to [Installation](getting-started/installation.md), then [Quick Start](getting-started/quick-start.md).

!!! note "ojo is still growing!"
    See [Roadmap & Limitations](roadmap.md) for an honest list of what's not supported yet — Kubernetes cluster scanning, license policy checks, custom policy languages, and more.
