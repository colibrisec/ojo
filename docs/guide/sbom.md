# SBOM

Every command supports `-f sbom` to emit a [CycloneDX](https://cyclonedx.org/) 1.7 JSON Software Bill of Materials of the packages it discovered, instead of running the vulnerability scanner.

```console
$ ojo fs -f sbom . > sbom.json
$ ojo image -f sbom python:3.14-slim > sbom.json
```

Each component includes a [package URL (purl)](https://github.com/package-url/purl-spec) built from the package's name, version, and ecosystem:

| Ecosystem | purl type |
|---|---|
| Go | `pkg:golang/...` |
| npm | `pkg:npm/...` |
| PyPI | `pkg:pypi/...` |
| everything else (OS packages, etc.) | `pkg:generic/...` |

## Spec version

Output is CycloneDX 1.7 by default. Pass `--cyclonedx-version` to target an older consumer — `1.2` through `1.7` are accepted (ojo's SBOM output is JSON, which CycloneDX only defines from 1.2 onward):

```console
$ ojo fs -f sbom --cyclonedx-version 1.4 . > sbom.json
```

`ojo fs -g` also writes an SBOM, as `gl-sbom-report.cdx.json`, and honors the same flag.

!!! note
    `-f sbom` only enumerates packages — it doesn't run the vulnerability scanner, so it works even without network access to OSV.dev. There's no SPDX output format yet, and no SBOM *input* support (ojo can't scan an existing SBOM the way `trivy sbom` can) — see [Roadmap](../roadmap.md).
