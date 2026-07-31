# Coverage

What ojo can actually scan today.

## Language ecosystems (`ojo fs`, vulnerability scanner)

| Ecosystem | Manifest | Status |
|---|---|---|
| Go | `go.mod` | ✅ |
| npm | `package-lock.json` (v1 and v2/v3) | ✅ |
| PyPI | `requirements.txt` (pinned `==` only) | ✅ |
| Maven, Rust, Ruby, PHP, .NET, ... | — | ❌ Not implemented. `model.EcosystemMaven` exists as a constant but has no manifest parser wired up yet. |

## Operating systems (`ojo image`)

| OS family | Package manager | Status |
|---|---|---|
| Alpine | apk | ✅ |
| Debian | dpkg | ✅ |
| Ubuntu | dpkg | ✅ |
| RHEL / CentOS / Fedora / Amazon Linux / Rocky / AlmaLinux | rpm | ❌ Detected but explicitly rejected with a clear error, rather than silently returning zero packages |

## IaC / misconfiguration formats

| Format | Status |
|---|---|
| Dockerfile | ✅ |
| Kubernetes YAML | ✅ (raw manifests only — no Helm/Kustomize rendering) |
| Terraform | ✅ (literal values only — no variable/module resolution) |
| CloudFormation, Azure ARM, Ansible, Helm charts | ❌ |

## SAST languages

| Language | Status |
|---|---|
| Go | ✅ (`go/ast`-based) |
| Everything else | ❌ — see [SAST scanner](../guide/scanner/sast.md) for why |

## Vulnerability data source

[OSV.dev](https://osv.dev) only, queried live (no local database). This means Alpine/Debian/Ubuntu coverage is exactly whatever OSV itself aggregates from those distros' security trackers.
