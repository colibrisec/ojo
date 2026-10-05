# Roadmap & Limitations

ojo is young. This page is the honest, unvarnished list of what it doesn't do yet — read it before assuming feature parity with more mature scanners.

## Targets

- **rpm-based images**: RHEL/UBI, Rocky Linux, AlmaLinux, and Amazon Linux 2/2023 are scanned (Amazon Linux from Amazon's own advisories, core repository only — not AL2 extras). Fedora, CentOS, Oracle Linux, SUSE, and Amazon Linux 1 packages are read (so `-f sbom` works) but can't be checked for vulnerabilities — ojo has no advisories it can match for them, and `ojo image` refuses rather than report zero. On RHEL 7–9 only the BaseOS/AppStream (RHEL 7: Server) repositories are covered, and modular streams aren't distinguished. See [Container Image](guide/target/container-image.md#rpm-specifics).
- **No Kubernetes cluster scanning.** The misconfiguration scanner reads static YAML manifests on disk; there's no `ojo image` equivalent that talks to a live cluster.
- **Image scanning covers OS packages and Node.js packages only** — no other language runtimes inside images, and no secret/misconfiguration/SAST scanning of image contents. One platform per scan (`--platform os/arch`, default `linux/amd64`).
- **One target per invocation.** No combined multi-artifact report (e.g. scanning an image *and* its app manifests together in one summary).

## Ecosystems

- See [Coverage](reference/coverage.md) for the current, authoritative list of supported dependency ecosystems, OS package managers, IaC formats, and SAST languages — it changes often enough that duplicating it here just goes stale.
- `requirements.txt` parsing is pinned `name==version` lines only — no version ranges, extras, environment markers, or VCS URLs.
- **CocoaPods** (`Podfile.lock`) is matched through each pod's git repository, so private pods and pods without a git source can't be checked (ojo reports how many).
- No unlocked-manifest support anywhere (`package.json` without a lockfile, `build.gradle`/`build.gradle.kts` DSL parsing) — ojo only reads already-resolved dependency data.

## Scanners

- **Secret scanner**: `--secret-git-history` scans `git log -p` on the current branch (current-branch history only, one finding per commit a secret was added in, not deduplicated); `--secret-rules-file` loads additional rules (same YAML shape as the built-in set). `.ojoignore` suppression already works — secret findings are `model.Issue`s like any other scanner's, and flow through the same suppression pass.
- **Misconfiguration scanner**: no data-driven policy language (Rego/OPA) — checks are hand-written Go, not a pluggable policy format. Terraform checks cover AWS/Azure/GCP providers, resolve `local.x`/`var.x` (literal defaults only), and correlate resources within one directory, including one level into a local module subdirectory (`module "x" { source = "./..." }`) for the specific "attachment resource passed a parent resource's id via a variable" pattern (S3 bucket protections, VPC flow logs) — not general module input/output resolution, and a nested module's own `module` blocks aren't followed. CloudFormation (YAML or JSON) is covered too, literal values only — unresolved intrinsic functions are skipped. Kubernetes checks don't render Helm charts or resolve Kustomize overlays. No native Azure ARM templates, Ansible, or Helm chart support. MCP server config and skill-definition checks are static (phrase lists and config shape, no live `tools/list` inspection); Android checks read the APK's manifest only — no DEX/native-library analysis, no iOS.
- **SAST scanner**: covers Go, Python, JavaScript/TypeScript, PHP, Ruby, and Java. Intraprocedural taint tracking across all six (sees through one local variable between a request/env source and a sink, on whichever rules structurally support it — see the SAST guide for exact coverage); user-authorable custom rules via `--rules-dir` for the five gotreesitter-backed languages (raw tree-sitter queries, not a Semgrep-style metavariable pattern language — no Go, see [SAST scanner: Custom rules](guide/scanner/sast.md#custom-rules)); interprocedural tracking is same-file only and one direction (a tainted argument seeds the callee's parameter; calls are resolved by name, never across files or through qualified/method calls) — see [SAST scanner](guide/scanner/sast.md) for the full per-language rule lists and honest ceiling.
- **Code quality scanner** (`--scanners quality`): cyclomatic complexity, function length, nesting depth, parameter count, and cross-file duplicate-code detection, across the same six languages. Thresholds are hardcoded, not yet `.ojo.yaml`-configurable; duplicate detection is textual (line-based), not semantic; no GitLab Code Quality report format yet — see [Code Quality scanner](guide/scanner/quality.md) for the full rule list and honest ceiling.
- **CWE mapping** covers `secret`, `misconfig`, and built-in `sast` rules; custom SAST rules and `quality` rules carry none.
- **Licenses** are identified in SBOM output (see [SBOM](guide/sbom.md#licenses)), but there's no license policy: no allow/deny list, no findings, no exit code tied to a license. Pub and SwiftURL packages get no license at all, and only a common subset of SPDX identifiers is recognized as such — anything else is written as a free-form name.
- **VEX**: `-f vex` emits an [OpenVEX](https://openvex.dev) document (every statement asserts `affected` — ojo has no reachability analysis to justify anything else); `--vex-file` consumes one, suppressing findings its `not_affected`/`fixed` statements cover. Product matching is exact purl equality, no normalization.

## Vulnerability data

- **No local database.** Every scan queries the live [OSV.dev](https://osv.dev) API — no offline/air-gapped mode. (`-f sbom --no-license-lookup` is the one fully offline operation.)
- **Fixed-version resolution** uses a generic, approximate version comparator, not each ecosystem's exact comparison rules (dpkg epoch/tilde semantics, real semver, PEP 440).
- **Ubuntu LTS detection** is a release-history heuristic (even year, April release), not derived from an authoritative source.
- `--kev` cross-references findings against CISA's Known Exploited Vulnerabilities catalog (annotation only, doesn't affect exit code).

## Supply chain

- SBOM output is CycloneDX JSON only — no SPDX format, and no SBOM *input* scanning (can't point ojo at an existing SBOM the way some scanners can). `--cyclonedx-version` selects the spec version (default: latest).
- No signature verification, no attestation, no Rekor integration.

## Operations

- **Config file (`.ojo.yaml`) covers `scanners`/`format` only** — see [Configuration](guide/configuration.md#config-file-ojoyaml). No severity-threshold field yet (see below), and no hierarchical/per-directory config resolution — one file, looked up in the current directory only.
- **No `--exit-code`/severity-threshold flag** — any finding at all produces exit code 1; there's no "only fail on HIGH and above."
- **No full CI integration guides yet.** The pieces exist — `-f sarif` for GitHub code scanning (example step in [Configuration](guide/configuration.md#-f-format)), `-g` for GitLab's Security Dashboard ([CLI Reference](reference/cli.md#-g-gitlab)), and a [`colibrisec/ojo-action`](https://github.com/colibrisec/ojo-action) GitHub Action — but there isn't a written end-to-end tutorial.

---

None of this is set in stone — it's a snapshot of what's built, not a promise about what won't be. If something here blocks you, that's useful signal.
