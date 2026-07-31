# Installation

ojo is a single static Go binary with no runtime dependencies.

!!! note
    ojo doesn't have tagged releases or prebuilt binaries yet. Until it does, build from source — it's one command.

## Build from source

Requires [Go 1.22+](https://go.dev/dl/).

```console
$ git clone https://github.com/colibrisec/ojo.git
$ cd ojo
$ go build -o ojo .
$ ./ojo --help
```

## `go install`

Once this repository has at least one tagged release, this will also work directly:

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
