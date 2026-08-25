# Roadmap & Limitations

ojo is young. This page is the honest, unvarnished list of what it doesn't do yet — read it before assuming feature parity with more mature scanners.

## Targets

- **rpm-based images** (RHEL, CentOS, Fedora, Amazon Linux, Rocky, AlmaLinux) aren't scanned — rpm databases (Berkeley DB/SQLite/NDB) need a real parser like [go-rpmdb](https://github.com/knqyf263/go-rpmdb), not hand-rolled parsing. `ojo image` detects these and refuses with a clear error instead of silently returning zero packages.
- **No Kubernetes cluster scanning.** The misconfiguration scanner reads static YAML manifests on disk; there's no `ojo image` equivalent that talks to a live cluster.
- **`linux/amd64` only** for image pulls — no `--platform` flag.
- **One target per invocation.** No combined multi-artifact report (e.g. scanning an image *and* its app manifests together in one summary).

## Ecosystems

- See [Coverage](reference/coverage.md) for the current, authoritative list of supported dependency ecosystems, OS package managers, IaC formats, and SAST languages — it changes often enough that duplicating it here just goes stale.
- `requirements.txt` parsing is pinned `name==version` lines only — no version ranges, extras, environment markers, or VCS URLs.
- No unlocked-manifest support anywhere (`package.json` without a lockfile, `build.gradle`/`build.gradle.kts` DSL parsing) — ojo only reads already-resolved dependency data.

## Scanners

- **Secret scanner**: no git history scanning (working tree only), no custom rules file, no suppression/baseline file.
- **Misconfiguration scanner**: no data-driven policy language (Rego/OPA) — checks are hand-written Go, not a pluggable policy format. Terraform checks cover AWS/Azure/GCP providers, resolve `local.x`/`var.x` (literal defaults only), and correlate resources within one directory, but don't traverse `module` blocks into subdirectories. CloudFormation (YAML or JSON) is covered too, literal values only — unresolved intrinsic functions are skipped. Kubernetes checks don't render Helm charts or resolve Kustomize overlays. No native Azure ARM templates, Ansible, or Helm chart support.
- **SAST scanner**: covers Go, Python, JavaScript/TypeScript, PHP, Ruby, and Java. Intraprocedural taint tracking across all six (sees through one local variable between a request/env source and a sink, on whichever rules structurally support it — see the SAST guide for exact coverage); user-authorable custom rules via `--rules-dir` for the five gotreesitter-backed languages (raw tree-sitter queries, not a Semgrep-style metavariable pattern language — no Go, see [SAST scanner: Custom rules](guide/scanner/sast.md#custom-rules)); no interprocedural analysis (taint doesn't cross a function call) — see [SAST scanner](guide/scanner/sast.md) for the full per-language rule lists and honest ceiling.
- **Code quality scanner** (`--scanners quality`): cyclomatic complexity, function length, nesting depth, parameter count, and cross-file duplicate-code detection, across the same six languages. Thresholds are hardcoded, not yet `.ojo.yaml`-configurable; duplicate detection is textual (line-based), not semantic; no GitLab Code Quality report format yet — see [Code Quality scanner](guide/scanner/quality.md) for the full rule list and honest ceiling.
- **License scanning**: not implemented.
- **VEX**: not implemented.

## Vulnerability data

- **No local database.** Every scan queries the live [OSV.dev](https://osv.dev) API — no offline/air-gapped mode.
- **Fixed-version resolution** uses a generic, approximate version comparator, not each ecosystem's exact comparison rules (dpkg epoch/tilde semantics, real semver, PEP 440).
- **Ubuntu LTS detection** is a release-history heuristic (even year, April release), not derived from an authoritative source.

## Supply chain

- SBOM output (CycloneDX 1.7 JSON) only — no SPDX format, and no SBOM *input* scanning (can't point ojo at an existing SBOM the way some scanners can).
- No signature verification, no attestation, no Rekor integration.

## Operations

- **Config file (`.ojo.yaml`) covers `scanners`/`format` only** — see [Configuration](guide/configuration.md#config-file-ojoyaml). No severity-threshold field yet (see below), and no hierarchical/per-directory config resolution — one file, looked up in the current directory only.
- **No `--exit-code`/severity-threshold flag** — any finding at all produces exit code 1; there's no "only fail on HIGH and above."
- **No CI integration guides yet** (GitHub Actions, GitLab CI, etc.) — plain binary invocation works fine in any CI today, there just isn't a written tutorial.

---

None of this is set in stone — it's a snapshot of what's built, not a promise about what won't be. If something here blocks you, that's useful signal.
