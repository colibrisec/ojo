# Target: Container Image

```console
$ ojo image [ref]
```

Pulls an image reference (from any registry `docker pull` could reach — no Docker daemon required), reads its installed OS package database and any Node.js packages in it, and checks those packages against [OSV.dev](https://osv.dev).

Only the **vulnerability** scanner runs against images today; `--scanners` doesn't apply to `ojo image` (see [Roadmap](../../roadmap.md)).

## Supported package managers

| Package manager | Distros | Status |
|---|---|---|
| apk | Alpine | ✅ Supported (`lib/apk/db/installed`) |
| dpkg | Debian, Ubuntu | ✅ Supported (`var/lib/dpkg/status`) |
| rpm | RHEL, CentOS, Fedora, Amazon Linux, Rocky, AlmaLinux | ❌ Not supported — `ojo image` errors out with a clear message rather than silently returning zero packages. rpm databases (Berkeley DB/SQLite/NDB depending on version) need a real parser like [go-rpmdb](https://github.com/knqyf263/go-rpmdb); this hasn't been wired in yet. |

## Node.js packages

Alongside OS packages, ojo reports Node.js packages installed anywhere in the image, found through `node_modules/<package>/package.json` (scoped packages included, and the npm bundled with Node.js base images). They're queried against OSV's npm ecosystem. Other language runtimes aren't scanned inside images yet.

## Platform

Images are pulled as `linux/amd64` by default. Pass `--platform os/arch` to pull a different platform of a multi-arch image:

```console
$ ojo image --platform linux/arm64 python:3.14-slim
```

## OS/version detection

ojo reads `/etc/os-release` to determine the ecosystem string it sends to OSV (`Alpine:v3.18`, `Debian:13`, `Ubuntu:22.04:LTS`, ...). On some images `/etc/os-release` is a symlink to `/usr/lib/os-release` — ojo follows that correctly. If the OS/version can't be determined, the scan is refused outright rather than sending OSV an unscoped query (an unscoped ecosystem causes OSV to loosely match package *names* across unrelated ecosystems — this was a real bug caught while building ojo, not a hypothetical).

The exception is an image with no `os-release` *and* no apk/dpkg database — a `scratch`-style image holding just a static binary. There are no OS packages to scope, so the scan proceeds (Node.js packages are still reported) instead of being refused.

With `-f json`, `sarif`, `sbom`, or `vex`, an image with no packages still produces an empty, well-formed document rather than the plain-text `No packages found.` line.

## Flags

`ojo image` shares `-f`/`--format`, `--config`, `--ignore-file`, `--vex-file`, `--kev`, `--cyclonedx-version`, and `--sarif-omit-suppressed` with `ojo fs` — see the [CLI Reference](../../reference/cli.md#ojo-image).

In a `.ojoignore` entry, the path an image finding is matched against is `apk` or `dpkg` for OS packages (so `*` works as the glob), and the package's `package.json` path inside the image for Node.js packages (e.g. `usr/local/lib/node_modules/npm/package.json` — `*` doesn't cross `/`, so spell out the segments).

## Example

```console
$ ojo image nginx:1.25
$ ojo image -f sbom myregistry.example.com/app:latest
$ ojo image --kev -f sarif nginx:1.25 > image.sarif
```

## See also

- [Vulnerability scanner](../scanner/vulnerability.md)
- [Coverage](../../reference/coverage.md)
