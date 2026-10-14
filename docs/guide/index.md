# User Guide

ojo has three commands, one per **target** type. Each command can run one or more **scanners** against that target.

|  | [Filesystem](target/filesystem.md) | [Container Image](target/container-image.md) | [SBOM](target/sbom.md) |
|---|---|---|---|
| Command | `ojo fs [path]` | `ojo image [ref]` | `ojo sbom [file]` |
| [Vulnerability](scanner/vulnerability.md) | ✅ (dependency manifests) | ✅ (OS and Node.js packages) | ✅ (listed packages) |
| [Secret](scanner/secret.md) | ✅ | ❌ | ❌ |
| [Misconfiguration](scanner/misconfiguration.md) | ✅ | ❌ | ❌ |
| [SAST](scanner/sast.md) | ✅ (Go, Python, JS/TS, PHP, Ruby, Java) | ❌ | ❌ |
| [Code Quality](scanner/quality.md) | ✅ (same six languages) | ❌ | ❌ |
| [SBOM](sbom.md) output | ✅ | ✅ | ✅ (conversion) |

Every scan produces the same two things: a list of `Finding`s (vulnerable packages) and a list of `Issue`s (everything else — secrets, misconfigurations, SAST hits, code-quality smells). See [Configuration](configuration.md) for how to choose which scanners run and what output format you get.
