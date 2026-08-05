# Quick Start

## Scan a filesystem or repo

```console
$ ojo fs .
```

By default this runs only the **vulnerability** scanner against the current directory. Add `--scanners` to change that:

```console
# Everything ojo can check
$ ojo fs --scanners vuln,secret,misconfig,sast .

# Vulnerabilities plus hardcoded secrets
$ ojo fs --scanners vuln,secret .

# Just misconfiguration checks (Dockerfile / Kubernetes / Terraform)
$ ojo fs --scanners misconfig .
```

## Scan a container image

```console
$ ojo image python:3.14-slim
```

This pulls the image, reads its installed OS packages (apk or dpkg), and checks them against [OSV.dev](https://osv.dev).

## Output formats

Every command supports `-f`/`--format`:

```console
$ ojo fs -f table .   # default: human-readable box-drawn table
$ ojo fs -f json .    # machine-readable, for piping into other tools
$ ojo fs -f sbom .    # CycloneDX 1.7 SBOM of discovered packages
```

## Exit codes

ojo exits `1` if it found any vulnerabilities or issues, and `0` otherwise — the standard convention for wiring a scanner into CI. See [Exit Codes](../reference/exit-codes.md).

```console
$ ojo fs . ; echo "exit code: $?"
```

## Next steps

- [Filesystem scanning](../guide/target/filesystem.md) in depth
- [Container image scanning](../guide/target/container-image.md) in depth
- [CLI Reference](../reference/cli.md) for every flag
