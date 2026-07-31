# Scanner: Misconfiguration

Checks Dockerfiles, Kubernetes manifests, and Terraform for common security misconfigurations.

Off by default — enable with `--scanners misconfig` (or combine: `--scanners vuln,secret,misconfig`).

## How files are matched

| Format | Matched by | Parser |
|---|---|---|
| Dockerfile | filename `Dockerfile` or `Dockerfile.*` | Hand-rolled line parser (handles `\` line continuation) |
| Kubernetes | `*.yaml`/`*.yml` containing `apiVersion` + `kind` | Generic `map[string]any` walk — works uniformly across Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob without needing a struct per kind |
| Terraform | `*.tf` | [`hashicorp/hcl/v2`](https://github.com/hashicorp/hcl) — the real HCL parser, not a hand-rolled one |

## Built-in checks (15)

**Dockerfile**

- Container runs as root (no `USER` instruction, or `USER root`)
- `FROM` with no pinned tag / `:latest`
- Secret-looking `ENV`/`ARG` name (`PASSWORD`, `SECRET`, `API_KEY`, `TOKEN`, ...)
- `ADD` used for local files instead of `COPY`

**Kubernetes**

- `hostNetwork: true`
- `hostPID: true`
- `hostIPC: true`
- `securityContext.privileged: true`
- `allowPrivilegeEscalation` not explicitly `false`
- `runAsNonRoot` not explicitly `true`
- Missing `resources.limits`

**Terraform**

- `aws_s3_bucket` with a public ACL
- `aws_security_group`/`aws_security_group_rule` ingress from `0.0.0.0/0`
- `aws_db_instance`/`aws_ebs_volume` with `storage_encrypted = false`
- IAM policy with `Action = "*"` and `Resource = "*"`

## Limitations

!!! note "Terraform checks read literal values only"
    No `var.x`/interpolated-expression resolution and no module graph traversal. A resource whose relevant attribute is a variable reference, rather than a literal, is silently skipped instead of guessed at.

!!! note "Kubernetes checks read raw manifests only"
    No Helm template rendering, no Kustomize overlay resolution.

There's no data-driven policy language (no Rego/OPA) — each check is a small Go function, same idiom as the manifest parsers. Adding a check means writing a function, not authoring a policy file.
