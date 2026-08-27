# Scanner: Misconfiguration

Checks Dockerfiles, Kubernetes manifests, Terraform (AWS/Azure/GCP), CloudFormation templates, MCP server configs, and Claude Code skill definitions for common security misconfigurations.

Off by default — enable with `--scanners misconfig` (or combine: `--scanners vuln,secret,misconfig`).

## How files are matched

| Format | Matched by | Parser |
|---|---|---|
| Dockerfile | filename `Dockerfile` or `Dockerfile.*` | Hand-rolled line parser (handles `\` line continuation) |
| Kubernetes | `*.yaml`/`*.yml` containing `apiVersion` + `kind` | Generic `map[string]any` walk — works uniformly across Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob without needing a struct per kind |
| Terraform | `*.tf` | [`hashicorp/hcl/v2`](https://github.com/hashicorp/hcl) — the real HCL parser, not a hand-rolled one |
| CloudFormation | `*.yaml`/`*.yml`/`*.json`/`*.template` containing a `Resources` map with an `AWS::`/`Alexa::`/`Custom::` resource `Type` | `gopkg.in/yaml.v3` (YAML) or `encoding/json` (JSON), both stdlib-adjacent — no new dependency for either |
| MCP server config | `*.json` containing a top-level `mcpServers` object, or a `servers` object whose own filename also contains "mcp" | `encoding/json` |
| Skill definition | filename `SKILL.md` (case-insensitive) | Line-based regex, same idiom as the Dockerfile parser |

Every `*.yaml`/`*.yml` file is tried as both a Kubernetes manifest and a CloudFormation template; each is a no-op on a file that doesn't look like its format (missing `apiVersion`+`kind`, or no CloudFormation-shaped `Resources`), so there's no real ambiguity cost to trying both. Every `*.json` file is similarly tried as both a CloudFormation template and an MCP config.

## Built-in checks (131)

**Dockerfile**

- Container runs as root (no `USER` instruction, or `USER root`)
- `FROM` with no pinned tag / `:latest`
- Secret-looking `ENV`/`ARG` name (`PASSWORD`, `SECRET`, `API_KEY`, `TOKEN`, ...)
- `ADD` used for local files instead of `COPY`
- No `HEALTHCHECK` instruction

**Kubernetes**

- `hostNetwork: true`
- `hostPID: true`
- `hostIPC: true`
- `securityContext.privileged: true`
- `allowPrivilegeEscalation` not explicitly `false`
- `runAsNonRoot` not explicitly `true`
- Missing `resources.limits`

**Terraform — AWS provider (56 checks)**

- `aws_s3_bucket` with a public ACL, a non-DNS-compliant name, or missing versioning / access logging / encryption / a complete `aws_s3_bucket_public_access_block` (covers both the pre-v4 inline-block style and the v4+ separate-resource style)
- `aws_security_group`/`aws_default_security_group`/`aws_security_group_rule` ingress or egress open to `0.0.0.0/0`/`::/0`, or missing a rule description
- `aws_vpc` with no `aws_flow_log` resource anywhere in the directory
- `aws_db_instance`/`aws_ebs_volume` with `storage_encrypted = false`; `aws_db_instance` missing Performance Insights (or its CMK), or IAM database authentication (MySQL/Postgres)
- `aws_instance`/`aws_launch_template` root block device (`root_block_device.encrypted`) when explicitly declared
- IAM policy with `Action = "*"`, `s3:*`, or unconditioned `iam:PassRole` granted on `Resource = "*"`; a policy attached directly to an `aws_iam_user`; a weak `aws_iam_account_password_policy`
- `aws_instance`/`aws_launch_template` without IMDSv2 enforced (`metadata_options.http_tokens = "required"`)
- `aws_lambda_function` without X-Ray tracing; `aws_lambda_function_url` with `authorization_type = "NONE"`
- `aws_ecs_task_definition` running a privileged container or with no read-only root filesystem (string match on `container_definitions`)
- `aws_lb`/`aws_alb` that's internet-facing or doesn't drop invalid headers; `aws_lb_listener` using plain HTTP
- `aws_api_gateway_stage`/`aws_apigatewayv2_stage` without access logging; `aws_api_gateway_method` with `authorization = "NONE"`
- `aws_cloudwatch_log_group` not encrypted with a CMK
- `aws_ecr_repository` with mutable tags or non-CMK encryption
- `aws_sns_topic`/`aws_sqs_queue`/`aws_secretsmanager_secret` not encrypted with a CMK
- `aws_kms_key` without rotation enabled
- `aws_cloudfront_distribution` without a WAF or access logging, weak/missing minimum TLS version, or a cache behavior allowing plain HTTP
- `aws_eks_cluster` with a public API endpoint or no control-plane logging
- `aws_cloudtrail` without log file validation, multi-region, or CMK encryption
- `aws_guardduty_detector` explicitly disabled
- `aws_dynamodb_table` without point-in-time recovery
- `aws_elasticache_replication_group` without at-rest or in-transit encryption
- `aws_redshift_cluster` unencrypted or publicly accessible
- `aws_efs_file_system` unencrypted
- `aws_kinesis_stream` not encrypted with KMS
- `data "aws_ami"` with no `owners` filter

**Terraform — Azure provider, `azurerm_*` (20 checks)**

- `azurerm_storage_account` allowing plain HTTP, weak TLS, public blob access, or an open network ACL default
- `azurerm_storage_container` with non-`private` access type
- `azurerm_network_security_group`/`azurerm_network_security_rule` with an inbound Allow rule from `*`
- `azurerm_key_vault` without purge protection, or an open network ACL default
- `azurerm_mssql_server`/`azurerm_sql_server` allowing public network access or weak TLS
- `azurerm_postgresql_server`/`azurerm_mysql_server` without SSL enforcement
- `azurerm_kubernetes_cluster` with a public API server, or no `network_profile`
- `azurerm_app_service`/`azurerm_linux_web_app`/`azurerm_windows_web_app` without HTTPS-only or weak TLS
- `azurerm_container_registry` with public network access or admin (shared-key) access enabled
- `azurerm_cosmosdb_account` with public network access enabled
- `azurerm_redis_cache` allowing non-SSL connections or weak TLS

**Terraform — GCP provider, `google_*` (16 checks)**

- `google_storage_bucket` without uniform bucket-level access or versioning
- `google_project_iam_binding`/`_member`, `google_storage_bucket_iam_binding`/`_member` granting `allUsers`/`allAuthenticatedUsers`
- `google_compute_firewall` allowing ingress from `0.0.0.0/0`
- `google_compute_instance`/`_instance_template` without Shielded VM config, with a public IP (`access_config` present), or an overly broad `cloud-platform` service-account scope
- `google_sql_database_instance` with a public IP, no backups, or SSL not required
- `google_kms_crypto_key` without a `rotation_period`
- `google_container_cluster` (GKE) without a private cluster config, authorized networks, or network policy; or with legacy ABAC enabled
- `google_pubsub_topic` without a customer-managed (`kms_key_name`) key

**CloudFormation — AWS resources, YAML or JSON (15 checks)**

Same resource-type coverage as the Terraform AWS checks where CloudFormation has an equivalent: `AWS::S3::Bucket` (public ACL, encryption, versioning, public access block), `AWS::EC2::SecurityGroup`/`SecurityGroupIngress`/`SecurityGroupEgress` (open CIDR), `AWS::RDS::DBInstance` (encryption, public access), `AWS::IAM::Policy`/`ManagedPolicy` (wildcard statements), `AWS::EC2::Instance`/`LaunchTemplate` (IMDSv2), `AWS::ElasticLoadBalancingV2::LoadBalancer` (internet-facing), `AWS::KMS::Key` (rotation), `AWS::CloudTrail::Trail` (log validation, multi-region), `AWS::DynamoDB::Table` (point-in-time recovery), `AWS::ECR::Repository` (tag mutability).

**MCP server config (8 checks)**

- `mcp-unpinned-launcher` (MEDIUM) — a server launched via `npx`/`bunx`/`uvx`/`pipx` with no version pin on the package it fetches (`pkg@x.y.z` / `pkg==x.y.z`). The same unpinned-supply-chain concern as an unpinned Docker base image, just for a process re-fetched on every client startup instead of an image build.
- `mcp-shell-wrapper` (MEDIUM) — `command` is a raw shell (`sh`/`bash`/`zsh`/`cmd`/`powershell`/`pwsh`) rather than a direct binary. The actually-executed command then lives inside an opaque `-c`/`/c` string argument instead of being visible as `command`+`args`.
- `mcp-plaintext-transport` (HIGH) — a remote server's `url` is `http://` rather than `https://` (localhost/`127.0.0.1`/`::1` excluded).
- `mcp-prompt-injection-language` (MEDIUM) — a server's `description` field contains known prompt-injection/tool-poisoning phrasing ("ignore previous instructions," "do not tell the user," ...). A concrete phrase list, not a semantic classifier — see the ceiling note below.
- `mcp-hidden-unicode` (HIGH) — a server's `description`/`command`/`args`/`url` contains a codepoint with real history as an invisible payload carrier (the Unicode "tag" block, zero-width space/word joiner, a bidi override control, a mid-text ZWNBSP).
- `mcp-auto-approve-wildcard` (MEDIUM) — a server's `autoApprove`/`alwaysAllow` list includes `"*"`: every tool call, present or added later, skips user confirmation entirely.
- `mcp-remote-server-unpinned` (LOW) — any server reached over `url` rather than launched locally. Informational: a remote server's behavior can change at any time without a local config change (the "MCP rug pull" pattern) — this flags every remote server for periodic review, not a specific misconfiguration.
- `mcp-cross-origin-credential` (MEDIUM) — an `env` var name recognizably names a well-known vendor (GitHub, AWS, GCP, Azure, Slack, Stripe, OpenAI, Anthropic, Docker) while nothing in the server's own `command`/`args`/`url` references that vendor — a credential handed to code that doesn't obviously come from where it's for.

Secrets hardcoded in a server's `env` block aren't a separate check here — the [secret scanner](secret.md) already walks every `.json` file and flags them.

**Skill definition (4 checks)**

- `skill-fetch-execute` (HIGH) — `curl`/`wget`/`iwr` piped directly into a shell/interpreter (`sh`/`bash`/`zsh`/`python`/`iex`), the classic fetch-and-execute supply-chain pattern.
- `skill-credential-exfil-reference` (HIGH) — a well-known credential file path (`.ssh/id_rsa`, `.aws/credentials`, `.netrc`, `.env`, `.npmrc`, `.git-credentials`, `.docker/config.json`) appearing on the same line as an outbound-transfer verb (`curl`, `wget`, `post`, `upload`, `send`).
- `skill-prompt-injection-language` (MEDIUM) — the body contains the same known prompt-injection phrasing `mcp-prompt-injection-language` checks for.
- `skill-hidden-unicode` (HIGH) — the body contains the same hidden-Unicode codepoints `mcp-hidden-unicode` checks for.
- `skill-broad-tool-permissions` (MEDIUM) — frontmatter `allowed-tools` is `"*"` or an unscoped dangerous grant (`Bash`, `Bash(*)`, `Shell`, `Execute`). A scoped grant like `Bash(git:*)` doesn't match.

Hardcoded secrets in `SKILL.md` also aren't a separate check — `.md` is already in the secret scanner's file list.

## Limitations

!!! note "Terraform variable/local resolution is best-effort, single-directory"
    `local.x` and `var.x` (when the variable has a literal `default`) are resolved before checks run, including short chains of locals referencing each other or a variable. Anything beyond that — module inputs, a value computed from another resource's attribute, dynamic blocks — can't be resolved and is treated the same as "unset," which for attributes whose insecure state is the default (e.g. a security group's absent `internal` defaults to internet-facing) means it gets flagged. That can be a false positive on a value that's actually fine but was unresolvable.

!!! note "Cross-resource Terraform checks see one directory, not the whole module graph"
    All `.tf` files in the same directory are scanned together — the AWS S3 checks that correlate a bucket with its `aws_s3_bucket_versioning`/`..._logging`/`..._public_access_block`/`..._server_side_encryption_configuration` resources (and the VPC/flow-log check) match references across files in that directory. They don't follow `module` blocks into subdirectories, so a bucket in one module and its protections in another won't be linked. Azure and GCP checks are all single-resource (no cross-resource correlation) for now.

!!! note "CloudFormation checks read literal values only"
    An unresolved intrinsic function — `!Ref`/`!GetAtt`/`!Sub`/`!If`/... in YAML's short form, or `{"Ref": ...}`/`{"Fn::*": ...}` in JSON's long form — is treated the same as "property not set," not evaluated. That's the same trade-off the Terraform checks make for unresolvable expressions, and for the same reason: no parameter/mapping/condition evaluation engine here.

!!! note "Far short of a Rego/OPA engine"
    There's no data-driven policy language here — each check is a small Go function, same idiom as the manifest parsers (adding a check means writing a function, not authoring a policy file). That keeps ojo a single dependency-light binary, but it will never match the breadth of a rule engine like Trivy's (~1000+ checks across AWS/Azure/GCP/Kubernetes/CloudFormation). Expect real gaps even with AWS/Azure/GCP/CloudFormation all covered — this is resource-type breadth on the most common misconfigurations, not exhaustive policy coverage.

!!! note "Kubernetes checks read raw manifests only"
    No Helm template rendering, no Kustomize overlay resolution.

!!! note "No Azure ARM (native JSON) templates, Ansible, or Helm charts"
    Azure coverage here is the `azurerm` Terraform provider, not native ARM/Bicep templates.

!!! note "Prompt-injection/tool-poisoning detection is a phrase list, not a classifier"
    `mcp-prompt-injection-language`/`skill-prompt-injection-language` match a short, concrete set of known phrasings ("ignore previous instructions," "do not tell the user," ...) — real signal for the crude, common form of the attack, but trivially evaded by rewording, and with a real false-positive risk on legitimate text that happens to use similar phrasing (e.g. a skill that legitimately documents "don't expose this to the user" as a design note about its own output). Expect a higher false-positive/false-negative rate here than every other check in this file; use `.ojoignore` to accept a reviewed false positive.

!!! note "Tool poisoning via a live MCP `tools/list` response isn't checked at all"
    The checks above read static config files (`command`/`args`/`url`/`description` as written on disk) and a skill's own `SKILL.md`. An MCP server's actual tool descriptions are returned at runtime over the protocol after connecting — ojo is a static file scanner, not an MCP client, so a server that serves clean descriptions in its source but poisoned ones at runtime (or changes them after initial review) isn't detectable this way. `mcp-remote-server-unpinned` flags the underlying exposure (a remote server's behavior isn't pinned by the config) but can't see the actual drift.

!!! note "Cross-origin escalation across multiple connected servers isn't checked"
    The real multi-server attack — one compromised server's tool output manipulating the model into misusing a *different*, more-privileged server in the same session — is a runtime interaction pattern, invisible in any single config file. `mcp-cross-origin-credential` only catches a narrower, static proxy: a credential env var named for one vendor handed to a server whose own command/args/URL don't reference that vendor. It's a curated ~10-vendor keyword table, so a legitimate multi-service wrapper will trip it and an untabled vendor won't.

!!! note "Skill permission checks assume `allowed-tools` frontmatter; no schema validation beyond that"
    `skill-broad-tool-permissions` reads a frontmatter key named `allowed-tools` specifically — if a client uses a different field name for the same concept, this check silently sees nothing to flag rather than erroring, the same "no schema to validate against" gap as the rest of this section.
