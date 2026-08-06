# User Guide

ojo has two commands, one per **target** type. Each command can run one or more **scanners** against that target.

|  | [Filesystem](target/filesystem.md) | [Container Image](target/container-image.md) |
|---|---|---|
| Command | `ojo fs [path]` | `ojo image [ref]` |
| [Vulnerability](scanner/vulnerability.md) | ✅ (dependency manifests) | ✅ (OS packages) |
| [Secret](scanner/secret.md) | ✅ | ❌ |
| [Misconfiguration](scanner/misconfiguration.md) | ✅ | ❌ |
| [SAST](scanner/sast.md) | ✅ (Go, Python, JS/TS, PHP, Ruby, Java) | ❌ |
| [SBOM](sbom.md) output | ✅ | ✅ |

Every scan produces the same two things: a list of `Finding`s (vulnerable packages) and a list of `Issue`s (everything else — secrets, misconfigurations, SAST hits). See [Configuration](configuration.md) for how to choose which scanners run and what output format you get.
