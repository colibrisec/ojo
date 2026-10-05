# Quick Start

## Scan a filesystem or repo

```console
$ ojo fs .
```

By default this runs only the **vulnerability** scanner against the current directory. Add `--scanners` to change that:

```console
# Everything ojo can check
$ ojo fs --scanners vuln,secret,misconfig,sast,quality .

# Vulnerabilities plus hardcoded secrets
$ ojo fs --scanners vuln,secret .

# Just misconfiguration checks (Dockerfile, Kubernetes, Terraform, CloudFormation, ...)
$ ojo fs --scanners misconfig .
```

## Scan a container image

```console
$ ojo image python:3.14-slim
```

This pulls the image, reads its installed OS packages (apk or dpkg) and Node.js packages, and checks them against [OSV.dev](https://osv.dev).

## Output formats

Every command supports `-f`/`--format`:

```console
$ ojo fs -f table .   # default: human-readable box-drawn table
$ ojo fs -f json .    # machine-readable, for piping into other tools
$ ojo fs -f sarif .   # SARIF 2.1.0, for GitHub code scanning and similar tooling
$ ojo fs -f sbom .    # CycloneDX 1.7 SBOM of discovered packages
$ ojo fs -f vex .     # OpenVEX document for the vulnerability findings
```

`ojo fs -g .` writes GitLab security report files instead — see the [CLI Reference](../reference/cli.md#-g-gitlab).

## Exit codes

ojo exits `1` if it found any vulnerabilities or issues, and `0` otherwise — the standard convention for wiring a scanner into CI. See [Exit Codes](../reference/exit-codes.md).

```console
$ ojo fs . ; echo "exit code: $?"
```

## Next steps

- [Filesystem scanning](../guide/target/filesystem.md) in depth
- [Container image scanning](../guide/target/container-image.md) in depth
- [Configuration](../guide/configuration.md) for `.ojo.yaml` defaults and suppressing findings with `.ojoignore`
- [CLI Reference](../reference/cli.md) for every flag
