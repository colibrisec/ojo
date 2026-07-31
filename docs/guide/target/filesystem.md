# Target: Filesystem

```console
$ ojo fs [path]
```

Scans a directory (default `.`) for dependency manifests, secrets, misconfiguration, and (Go) source code. Which scanners run is controlled by [`--scanners`](../configuration.md).

`node_modules/`, `.git/`, and `vendor/` are always skipped.

## Dependency discovery

ojo walks the tree and parses every recognized manifest/lockfile it finds:

| Ecosystem | Files | Notes |
|---|---|---|
| Go | `go.mod` | Parsed with `golang.org/x/mod/modfile`; includes indirect requires |
| npm | `package-lock.json` | Supports both the v1 (`dependencies`) and v2/v3 (`packages`) lockfile shapes |
| PyPI | `requirements.txt` | Only pinned `name==version` lines. Ranges (`>=`, `~=`), extras, and VCS URLs are not parsed — an unpinned line is silently skipped rather than guessed at |

There is no `package.json`-only (unlocked) support and no `poetry.lock`/`Pipfile.lock`/`Gemfile.lock`/`pom.xml` support yet — see [Roadmap & Limitations](../../roadmap.md).

## Example

```console
$ ojo fs --scanners vuln,secret,misconfig,sast ./my-project
```

## See also

- [Vulnerability scanner](../scanner/vulnerability.md)
- [Secret scanner](../scanner/secret.md)
- [Misconfiguration scanner](../scanner/misconfiguration.md)
- [SAST scanner](../scanner/sast.md)
