# Installation

ojo is a single static Go binary with no runtime dependencies.

## Prebuilt binaries

Every release publishes binaries for Linux, macOS, and Windows (amd64 + arm64, Windows amd64 only) on the [GitHub Releases page](https://github.com/colibrisec/ojo/releases), alongside a `checksums.txt` — verify the download before running it:

```console
$ curl -LO https://github.com/colibrisec/ojo/releases/latest/download/ojo_vX.Y.Z_linux_amd64
$ curl -LO https://github.com/colibrisec/ojo/releases/latest/download/checksums.txt
$ sha256sum --ignore-missing -c checksums.txt
$ chmod +x ojo_vX.Y.Z_linux_amd64
```

Releases are cut automatically on the 1st of every month (see `.github/workflows/release.yml`) — `vX.Y.Z` won't be `latest` in the URL above; check the releases page for the current tag.

## Package managers

Each release also publishes native packages, built from the same binaries above:

=== "macOS (Homebrew)"

    ```console
    $ brew tap colibrisec/tap
    $ brew install ojo
    ```

=== "Debian/Ubuntu (.deb)"

    ```console
    $ curl -LO https://github.com/colibrisec/ojo/releases/latest/download/ojo_X.Y.Z_linux_amd64.deb
    $ sudo apt install ./ojo_X.Y.Z_linux_amd64.deb
    ```

=== "Fedora/RHEL (.rpm)"

    ```console
    $ sudo dnf install https://github.com/colibrisec/ojo/releases/latest/download/ojo_X.Y.Z_linux_amd64.rpm
    ```

=== "Windows (winget)"

    ```console
    $ winget install colibrisec.ojo
    ```

=== "Windows (MSI)"

    Download `ojo_vX.Y.Z_windows_amd64.msi` from the [releases page](https://github.com/colibrisec/ojo/releases) and run it — it installs to `Program Files\ojo` and adds that directory to `PATH`.

=== "Linux (Snap)"

    ```console
    $ sudo snap install ojo-scanner
    ```

    The Snap Store had already taken the `ojo` name, so the published snap is `ojo-scanner` — the command it installs is still `ojo`.

    This snap runs under [strict confinement](https://snapcraft.io/docs/classic-confinement), so by default it can only read/write inside your `$HOME` and reach the network (for OSV.dev/registry lookups). To scan a path outside `$HOME` — a mounted drive, `/opt`, etc. — connect the extra interface first:

    ```console
    $ sudo snap connect ojo-scanner:removable-media
    ```

    Paths elsewhere on the filesystem (e.g. directly under `/etc` or `/srv`) aren't reachable under strict confinement at all; use one of the other install methods on this page if you need to scan those.

## Container image

Each release also publishes a `scratch`-based image (just the static binary and a CA bundle) to GHCR:

```console
$ docker run --rm ghcr.io/colibrisec/ojo:latest fs --help
```

Mount a directory to scan it: `docker run --rm -v "$PWD:/src" ghcr.io/colibrisec/ojo:latest fs /src`.

## Build from source

Requires [Go 1.22+](https://go.dev/dl/).

```console
$ git clone https://github.com/colibrisec/ojo.git
$ cd ojo
$ go build -o ojo .
$ ./ojo --help
```

## `go install`

```console
$ go install github.com/colibrisec/ojo@latest
```

## Container image pulling

`ojo image` pulls images the same way `docker pull` does — it reads registry credentials from `~/.docker/config.json` and ambient cloud credentials (no Docker daemon required to scan). If you can `docker pull` an image, `ojo image` can scan it.

## Verifying it works

```console
$ ojo fs --help
$ ojo image --help
```
