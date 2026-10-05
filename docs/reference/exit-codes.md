# Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, nothing found |
| `1` | Scan completed, at least one vulnerability or issue was found — **or** the scan failed to run (bad flag, network error pulling an image, OSV.dev unreachable, etc.) |

ojo doesn't currently distinguish "found problems" from "scan itself failed" with different exit codes — both are `1`. This is the standard convention for wiring a scanner into CI as a gate:

```console
$ ojo fs . && echo "no findings, proceed"
$ ojo fs . || echo "findings (or a scan error) — check output"
```

Findings suppressed by `.ojoignore` or a `--vex-file` don't count toward the exit code, and neither does a `--kev` annotation. `-f sbom` never runs a scan, so it exits `0` unless something fails.

There's no `--exit-code` / severity-threshold flag yet to control this (e.g. "only fail on HIGH and above") — see [Roadmap](../roadmap.md).
