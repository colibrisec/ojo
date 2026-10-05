# Scanner: Secret

Scans common configuration files for hardcoded credentials using a regex + keyword + entropy rule engine.

Off by default — enable with `--scanners secret` (or combine: `--scanners vuln,secret`).

## How matching works

Each rule has:

- a **regex** the line must match
- optional **keywords** — if set, the line must contain one (case-insensitive) before the regex even runs, keeping cheap generic rules fast and lower-noise
- an optional **minimum Shannon entropy** the matched text must clear, to filter out low-entropy false positives like `password = "changeme"`

Only common configuration files are scanned — not every source file in the tree. This keeps noise and runtime down, since hardcoded secrets overwhelmingly land in config, not application code.

Matched by extension: `.env` (and `.env.*`), `.yaml`, `.yml`, `.json`, `.toml`, `.ini`, `.cfg`, `.conf`, `.properties`, `.xml`, `.pem`, `.key`, `.md`.

Matched by exact filename (case-insensitive): `Dockerfile`, `.npmrc`, `.pypirc`, `.netrc`, `.htpasswd`, `.git-credentials`, `.dockercfg`.

Files are also skipped if they're binary (null byte in the first 512 bytes) or larger than 5MB.

## Test-file placeholder suppression

A match is suppressed (not reported) when **both** of these hold:

1. The file is recognizably a test file by naming/path convention — a `_test.go`, `.test.`, or `.spec.` basename, or a `test`, `tests`, `testdata`, `fixtures`, `__tests__`, or `mocks` path segment.
2. The matched text itself looks like a placeholder rather than a real credential — it contains a common marker word (`example`, `fake`, `dummy`, `changeme`, `sample`, `hunter2`, etc.), or has a run of 8+ identical or sequentially-ascending characters (like a hand-typed run of the alphabet, or eight zeros in a row) — the kind of pattern a human types by hand, which real generated secrets essentially never produce.

Both conditions are required. A real credential accidentally committed into a test file — one with no marker words and no hand-typed structure — is still reported. See `internal/secret/placeholder.go` for the exact rules.

The one exception that applies in any file: AWS's own documentation example credentials (`AKIAIOSFODNN7EXAMPLE` and its matching secret key) are never reported.

## Built-in rules (14)

| Rule | Severity |
|---|---|
| AWS Access Key ID | CRITICAL |
| AWS Secret Access Key (keyword+entropy gated) | CRITICAL |
| GitHub Personal Access Token | CRITICAL |
| GitHub Fine-Grained PAT | CRITICAL |
| Private Key (`-----BEGIN ... PRIVATE KEY-----`) | CRITICAL |
| Stripe Live API Key | CRITICAL |
| Slack Token | HIGH |
| Google API Key | HIGH |
| Twilio API Key | HIGH |
| npm Access Token | HIGH |
| Database connection string with embedded password | HIGH |
| Slack Webhook URL | MEDIUM |
| JSON Web Token | MEDIUM |
| Generic secret/password/token assignment (keyword+entropy gated, highest false-positive risk) | LOW |

Rules are embedded in the binary (`internal/secret/default_rules.yaml`) — nothing to download or sync. Issues carry CWE IDs (e.g. CWE-798) in every output format.

## Custom rules (`--secret-rules-file`)

Add your own rules in a YAML file with the same shape as the built-in set, and pass it with `--secret-rules-file`. They run alongside the built-in rules whenever `secret` is in `--scanners`:

```yaml
rules:
  - id: acme-internal-token
    description: ACME internal service token
    regex: 'acme_[a-z0-9]{32}'
    keywords: [acme_]     # optional
    minEntropy: 3.5       # optional
    severity: HIGH
```

```console
$ ojo fs --scanners secret --secret-rules-file ci/secret-rules.yaml .
```

A custom rule `id` that collides with a built-in one is a load error. Custom rules add to the built-in set; there's no way to disable a built-in rule other than suppressing its findings.

## Git history (`--secret-git-history`)

By default only the working tree is scanned. Add `--secret-git-history` to also scan `git log -p` on the current branch, so a secret that was committed and later removed is still caught:

```console
$ ojo fs --scanners secret --secret-git-history .
```

`path` must be a git repository and `git` must be on `PATH`. Only the checked-out branch's history is read (not every ref), and a secret is reported once per commit that added it, without deduplication — so it can be slow and noisy on a long history.

## Suppressing findings

Acknowledge a known false positive or accepted risk in [`.ojoignore`](../configuration.md#risk-acceptance-ojoignore), by rule ID and path glob. There's no separate baseline file.

## What it doesn't do (yet)

- **Only config-shaped files are scanned**, not source code (see the list above). The [SAST scanner](sast.md)'s `*-hardcoded-secret` rules cover literals assigned in source.
- **Git history scanning is current-branch only**, with no deduplication across commits.
- **No live verification** of whether a matched credential is still valid.

See [Roadmap & Limitations](../../roadmap.md).
