# Target: Container Image

```console
$ ojo image [ref]
```

Pulls an image reference (from any registry `docker pull` could reach — no Docker daemon required), reads its installed OS package database, and checks those packages against [OSV.dev](https://osv.dev).

Only the **vulnerability** scanner runs against images today; `--scanners` doesn't apply to `ojo image` (see [Roadmap](../../roadmap.md)).

## Supported package managers

| Package manager | Distros | Status |
|---|---|---|
| apk | Alpine | ✅ Supported (`lib/apk/db/installed`) |
| dpkg | Debian, Ubuntu | ✅ Supported (`var/lib/dpkg/status`) |
| rpm | RHEL, CentOS, Fedora, Amazon Linux, Rocky, AlmaLinux | ❌ Not supported — `ojo image` errors out with a clear message rather than silently returning zero packages. rpm databases (Berkeley DB/SQLite/NDB depending on version) need a real parser like [go-rpmdb](https://github.com/knqyf263/go-rpmdb); this hasn't been wired in yet. |

## Platform

Images are always pulled as `linux/amd64`. There's no `--platform` flag yet.

## OS/version detection

ojo reads `/etc/os-release` to determine the ecosystem string it sends to OSV (`Alpine:v3.18`, `Debian:13`, `Ubuntu:22.04:LTS`, ...). On some images `/etc/os-release` is a symlink to `/usr/lib/os-release` — ojo follows that correctly. If the OS/version can't be determined, the scan is refused outright rather than sending OSV an unscoped query (an unscoped ecosystem causes OSV to loosely match package *names* across unrelated ecosystems — this was a real bug caught while building ojo, not a hypothetical).

## Example

```console
$ ojo image nginx:1.25
$ ojo image -f sbom myregistry.example.com/app:latest
```

## See also

- [Vulnerability scanner](../scanner/vulnerability.md)
- [Coverage](../../reference/coverage.md)
