# Configuration

ojo is configured entirely through CLI flags — there's no config file yet (see [Roadmap](../roadmap.md)).

## `--scanners`

`ojo fs` only. Comma-separated list of scanners to run.

```console
$ ojo fs --scanners vuln,secret,misconfig,sast .
```

| Value | Runs by default? |
|---|---|
| `vuln` | ✅ |
| `secret` | ✅ |
| `misconfig` | ❌ |
| `sast` | ❌ |

Default: `vuln,secret`. `ojo image` doesn't take `--scanners` — it always runs the vulnerability scanner against OS packages.

## `-f` / `--format`

Both commands.

| Value | Output |
|---|---|
| `table` (default) | Box-drawn human-readable table |
| `json` | Machine-readable, for piping into other tools |
| `sbom` | CycloneDX 1.7 SBOM (see [SBOM](sbom.md)) — skips vulnerability scanning entirely |

## Color

Table output is colored automatically when stdout is an interactive terminal, and suppressed automatically when piped/redirected (so CI logs stay clean). Force it off explicitly by setting `NO_COLOR` to any non-empty value.

```console
$ NO_COLOR=1 ojo fs .
```

## Exit codes

See [Exit Codes](../reference/exit-codes.md) — this is what CI pipelines actually gate on.
