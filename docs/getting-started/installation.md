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
