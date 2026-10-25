# Scanner: License

Checks the licenses of your dependencies against a policy you set in `.ojo.yaml`. Off by default; enable it with `--scanners license`.

```yaml
# .ojo.yaml
license:
  deny: [AGPL-*, GPL-3.0-only, SSPL-1.0]
  exceptions: [internal-tool]
  unknown: warn
```

```console
$ ojo fs --scanners vuln,license .
```

Licenses come from the same sources as [SBOM output](../sbom.md#licenses): lockfiles that record them, plus [deps.dev](https://deps.dev) and the CocoaPods spec CDN. `--no-license-lookup` skips the online lookups, which leaves most packages without a known license.

## Policy

| Key | Meaning |
|---|---|
| `allow` | Only these licenses pass. Anything else is a `license-not-allowed` finding. |
| `deny` | These licenses fail with `license-denied`; everything else passes. |
| `exceptions` | Package names (`lodash`) or name and version (`lodash@4.17.21`) the policy doesn't apply to. |
| `unknown` | What to do with a package that has no known license: `warn` (default; prints a warning to stderr), `fail` (a `license-unknown` finding), or `ignore`. |

Set `allow` or `deny`, not both. The scanner is an error without a policy: it needs `allow`, `deny`, or `unknown: fail`.

Entries are SPDX identifiers or free-form license names, matched case-insensitively. A trailing `*` matches a prefix, so `GPL-*` covers every GPL version. The deprecated GNU identifiers are treated as their current names (`GPL-2.0` is `GPL-2.0-only`, `GPL-2.0+` is `GPL-2.0-or-later`), so a policy written either way matches both.

## License expressions

A package licensed under an SPDX expression is judged by what the expression lets you choose:

- `MIT OR GPL-3.0-only` passes if either license is acceptable, since you can take it under that one.
- `MIT AND GPL-3.0-only` passes only if both are.
- `GPL-2.0-only WITH Classpath-exception-2.0` matches a policy entry for either the full text or the base license.

A license that isn't a valid expression (such as `Apache License 2.0`) is matched as one name.

## Rules

| Rule | Severity | Detects |
|---|---|---|
| `license-denied` | HIGH | A license on the `deny` list |
| `license-not-allowed` | HIGH | A license missing from the `allow` list |
| `license-unknown` | LOW | No known license, with `unknown: fail` |

Findings point at the manifest the package came from. Like any other finding, they make ojo exit 1 and can be suppressed with [`.ojoignore`](../configuration.md#risk-acceptance-ojoignore) by rule ID and path. To exempt one package, use `exceptions`.

## Limitations

- `ojo fs` only. `ojo image` and `ojo sbom` don't run it yet.
- Only a common subset of SPDX identifiers is recognized; see [SBOM: Licenses](../sbom.md#licenses).
- Pub and SwiftURL packages never get a license, so they always count as unknown.
