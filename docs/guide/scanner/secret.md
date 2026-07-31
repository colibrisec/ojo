# Scanner: Secret

Scans source files for hardcoded credentials using a regex + keyword + entropy rule engine.

Runs by default; part of `--scanners vuln,secret,...`.

## How matching works

Each rule has:

- a **regex** the line must match
- optional **keywords** — if set, the line must contain one (case-insensitive) before the regex even runs, keeping cheap generic rules fast and lower-noise
- an optional **minimum Shannon entropy** the matched text must clear, to filter out low-entropy false positives like `password = "changeme"`

Files are skipped if they're binary (null byte in the first 512 bytes) or larger than 5MB.

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
