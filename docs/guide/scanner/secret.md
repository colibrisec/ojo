# Scanner: Secret

Scans source files for hardcoded credentials using a regex + keyword + entropy rule engine.

Off by default — enable with `--scanners secret` (or combine: `--scanners vuln,secret`).

## How matching works

Each rule has:

- a **regex** the line must match
- optional **keywords** — if set, the line must contain one (case-insensitive) before the regex even runs, keeping cheap generic rules fast and lower-noise
- an optional **minimum Shannon entropy** the matched text must clear, to filter out low-entropy false positives like `password = "changeme"`

Files are skipped if they're binary (null byte in the first 512 bytes) or larger than 5MB.

## Test-file placeholder suppression

A match is suppressed (not reported) when **both** of these hold:

1. The file is recognizably a test file by naming/path convention — a `_test.go`, `.test.`, or `.spec.` basename, or a `test`, `tests`, `testdata`, `fixtures`, `__tests__`, or `mocks` path segment.
2. The matched text itself looks like a placeholder rather than a real credential — it contains a common marker word (`example`, `fake`, `dummy`, `changeme`, `sample`, `hunter2`, etc.), or has a run of 8+ identical or sequentially-ascending characters (like a hand-typed run of the alphabet, or eight zeros in a row) — the kind of pattern a human types by hand, which real generated secrets essentially never produce.

Both conditions are required. A real credential accidentally committed into a test file — one with no marker words and no hand-typed structure — is still reported. See `internal/secret/placeholder.go` for the exact rules.

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

Rules are embedded in the binary (`internal/secret/default_rules.yaml`) — no external rules file to manage.

## What it doesn't do (yet)

- **No git history scanning.** ojo scans the working tree, not past commits — a secret that was committed and later removed won't be found. This is gitleaks' actual differentiator; ojo doesn't have it.
- **No custom rules file / `--rules-dir` override.** The 14 built-in rules are all you get today.
- **No suppression/baseline file** for acknowledging known false positives.

See [Roadmap & Limitations](../../roadmap.md).
