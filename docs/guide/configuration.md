# Configuration

ojo is configured through CLI flags, with an optional `.ojo.yaml` file for repo-wide defaults.

## Config file (`.ojo.yaml`)

Drop a `.ojo.yaml` in the directory you run ojo from to set defaults without repeating flags every invocation:

```yaml
scanners: vuln,secret,misconfig,sast
format: sarif
```

| Key | Mirrors | Applies to |
|---|---|---|
| `scanners` | `--scanners` | `ojo fs` only |
| `format` | `-f`/`--format` | `ojo fs` and `ojo image` |

**Precedence:** an explicit flag always wins, then the config file, then the built-in default (`vuln` / `table`).

ojo looks for `.ojo.yaml` in the current directory by default. Point it elsewhere with `--config`:

```console
$ ojo fs --config ci/.ojo.yaml .
```

A missing default `.ojo.yaml` is not an error — it just means no overrides. An explicit `--config path` that doesn't exist *is* an error (almost certainly a typo), and so is an unrecognized key in the file.

## Risk acceptance (`.ojoignore`)

Drop a `.ojoignore` in the directory you run ojo from to suppress specific findings/issues — accepted risk, false positives, whatever the reason — without editing scanner code:

```
# <id> <path-glob>  # reason (expires: YYYY-MM-DD)
CVE-2022-28346  requirements.txt              # accepted risk, reviewed by security (expires: 2026-12-31)
go-sql-injection  internal/legacy/*.go        # false positive, parameterized via a wrapper
```

- **`id`** matches a vulnerability's ID or any alias (so a `GHSA-...`/`PYSEC-...` alias works too), or an Issue's rule ID (`go-sql-injection`, `aws-access-key-id`, etc.) — exactly.
- **`path-glob`** is matched against the finding/issue's path relative to the scan root (`*` spans one path segment, doesn't cross `/`).
- **`# reason`** is required — an entry with no reason is a load error, same policy as an unrecognized `.ojo.yaml` key.
- **`(expires: YYYY-MM-DD)`** at the end of the reason is optional. Past that date the entry just stops suppressing (the finding reappears) rather than erroring the scan.

ojo looks for `.ojoignore` in the current directory by default. Point it elsewhere with `--ignore-file`:

```console
$ ojo fs --ignore-file ci/.ojoignore .
```

A missing default `.ojoignore` is not an error. An explicit `--ignore-file path` that doesn't exist, or a malformed line, is.

**Suppressed results are omitted from `table`/`json`/`sbom`/GitLab output entirely** — they don't count toward the exit code either. `-f sarif` is the exception: suppressed results stay in the output as native SARIF `suppressions` (`kind: external`, your reason as `justification`), so tools that understand SARIF suppressions (like GitHub's Security tab) can still show them as accepted rather than hiding the audit trail.

## `--scanners`

`ojo fs` only. Comma-separated list of scanners to run.

```console
$ ojo fs --scanners vuln,secret,misconfig,sast .
```

| Value | Runs by default? |
|---|---|
| `vuln` | ✅ |
| `secret` | ❌ |
| `misconfig` | ❌ |
| `sast` | ❌ |

Default: `vuln`. `ojo image` doesn't take `--scanners` — it always runs the vulnerability scanner against OS packages.

## `-f` / `--format`

Both commands.

| Value | Output |
|---|---|
| `table` (default) | Box-drawn human-readable table |
| `json` | Machine-readable, for piping into other tools |
| `sbom` | CycloneDX 1.7 SBOM (see [SBOM](sbom.md)) — skips vulnerability scanning entirely |
| `sarif` | [SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) 2.1.0, for `github/codeql-action/upload-sarif` and similar tooling (validated against the official schema) |

```console
$ ojo fs -f sarif . > results.sarif
```

A minimal example CI step to surface findings in GitHub's Security tab:

```yaml
- run: ojo fs -f sarif . > results.sarif || true  # ojo exits 1 on findings; capture the file first
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Color

Table output is colored automatically when stdout is an interactive terminal, and suppressed automatically when piped/redirected (so CI logs stay clean). Force it off explicitly by setting `NO_COLOR` to any non-empty value.

```console
$ NO_COLOR=1 ojo fs .
```

## Exit codes

See [Exit Codes](../reference/exit-codes.md) — this is what CI pipelines actually gate on.
