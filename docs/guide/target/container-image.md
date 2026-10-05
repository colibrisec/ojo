# Target: Container Image

```console
$ ojo image [ref]
```

Pulls an image reference (from any registry `docker pull` could reach — no Docker daemon required), reads its installed OS package database and any Node.js packages in it, and checks those packages against [OSV.dev](https://osv.dev) — or, for Amazon Linux, against Amazon's own security advisories.

Only the **vulnerability** scanner runs against images today; `--scanners` doesn't apply to `ojo image` (see [Roadmap](../../roadmap.md)).

## Supported package managers

| Package manager | Distros | Status |
|---|---|---|
| apk | Alpine | ✅ Supported (`lib/apk/db/installed`) |
| dpkg | Debian, Ubuntu | ✅ Supported (`var/lib/dpkg/status`) |
| rpm | RHEL / UBI, Rocky Linux, AlmaLinux | ✅ Supported (`var/lib/rpm` or `usr/lib/sysimage/rpm`; Berkeley DB, NDB, and SQLite backends, read with [go-rpmdb](https://github.com/knqyf263/go-rpmdb)) |
| rpm | Amazon Linux 2, Amazon Linux 2023 | ✅ Supported, checked against [Amazon Linux Security Center](https://alas.aws.amazon.com) advisories rather than OSV — see [Amazon Linux](#amazon-linux) |
| rpm | Fedora, CentOS, Oracle Linux, SUSE, Amazon Linux 1, others | ⚠️ Packages are read, so `-f sbom` works. A vulnerability scan is refused: ojo has no advisories it can match for these distributions, and reporting zero findings would look like a clean result. |

### rpm specifics

- Advisories are matched by **source package** (`openssl`, not `openssl-libs`), taken from each package's `SOURCERPM`, and reported against the installed binary package.
- **RHEL 7–9** advisories are filed per repository. An installed rpm doesn't record which repository it came from, so each package is checked against BaseOS and AppStream (RHEL 7: Server). Packages installed from other repositories (CRB, EPEL, third-party) aren't covered. **RHEL 10** is matched by minor version.
- **AlmaLinux** advisories carry no CVE alias or severity in OSV, so findings show the `ALSA-…` ID and `UNKNOWN` severity.
- Modular streams (`dnf module`) aren't distinguished: a package is matched by name and version only.

### Amazon Linux

OSV publishes nothing for Amazon Linux, so its packages are checked against the advisories Amazon ships with the distribution: the `updateinfo` of the release's core repository, the same data `dnf updateinfo` reads. It's downloaded from `cdn.amazonlinux.com` on every scan (about 2 MB), with no local database.

- A package is vulnerable when an advisory lists a newer version of it than the one installed, compared with rpm's own version ordering. Matching is by **binary package name**, which is how Amazon's advisories list packages.
- Each CVE an advisory covers is one finding, with the `ALAS…` advisory as an alias and the advisory page as its link. Severity is Amazon's advisory priority (`Important` is shown as `HIGH`), which applies to the advisory as a whole rather than to each CVE in it.
- Only the **core** repository is covered. Packages installed from Amazon Linux 2 *extras* topics or from third-party repositories aren't checked.
- An advisory only exists once Amazon has released a fix, so a CVE that is still unfixed in Amazon Linux isn't reported.
- **Amazon Linux 1** (2018.03) is end of life and isn't covered; a vulnerability scan of it is refused.

If the advisories can't be downloaded, the scan fails rather than report nothing.

## Node.js packages

Alongside OS packages, ojo reports Node.js packages installed anywhere in the image, found through `node_modules/<package>/package.json` (scoped packages included, and the npm bundled with Node.js base images). They're queried against OSV's npm ecosystem, whatever the image's OS. Other language runtimes aren't scanned inside images yet.

## Platform

Images are pulled as `linux/amd64` by default. Pass `--platform os/arch` to pull a different platform of a multi-arch image:

```console
$ ojo image --platform linux/arm64 python:3.14-slim
```

## OS/version detection

ojo reads `/etc/os-release` to determine the ecosystem string it sends to OSV (`Alpine:v3.18`, `Debian:13`, `Ubuntu:22.04:LTS`, ...). On some images `/etc/os-release` is a symlink to `/usr/lib/os-release` — ojo follows that correctly. If the OS/version can't be determined, the scan is refused outright rather than sending OSV an unscoped query (an unscoped ecosystem causes OSV to loosely match package *names* across unrelated ecosystems — this was a real bug caught while building ojo, not a hypothetical).

The exception is an image with no `os-release` *and* no apk/dpkg/rpm database — a `scratch`-style image holding just a static binary. There are no OS packages to scope, so the scan proceeds (Node.js packages are still reported) instead of being refused.

With `-f json`, `sarif`, `sbom`, or `vex`, an image with no packages still produces an empty, well-formed document rather than the plain-text `No packages found.` line.

## Flags

`ojo image` shares `-f`/`--format`, `--config`, `--ignore-file`, `--vex-file`, `--kev`, `--cyclonedx-version`, and `--sarif-omit-suppressed` with `ojo fs` — see the [CLI Reference](../../reference/cli.md#ojo-image).

In a `.ojoignore` entry, the path an image finding is matched against is `apk`, `dpkg`, or `rpm` for OS packages (so `*` works as the glob), and the package's `package.json` path inside the image for Node.js packages (e.g. `usr/local/lib/node_modules/npm/package.json` — `*` doesn't cross `/`, so spell out the segments).

## Example

```console
$ ojo image nginx:1.25
$ ojo image -f sbom myregistry.example.com/app:latest
$ ojo image --kev -f sarif nginx:1.25 > image.sarif
```

## See also

- [Vulnerability scanner](../scanner/vulnerability.md)
- [Coverage](../../reference/coverage.md)
