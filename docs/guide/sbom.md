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
| CocoaPods | `pkg:cocoapods/...` |
| everything else (OS packages, etc.) | `pkg:generic/...` |

## Spec version

Output is CycloneDX 1.7 by default. Pass `--cyclonedx-version` to target an older consumer — `1.2` through `1.7` are accepted (ojo's SBOM output is JSON, which CycloneDX only defines from 1.2 onward):

```console
$ ojo fs -f sbom --cyclonedx-version 1.4 . > sbom.json
```

`ojo fs -g` also writes an SBOM, as `gl-sbom-report.cdx.json`, and honors the same flag.

## Licenses

Each component carries its license where one can be determined, written as an SPDX license ID, an SPDX expression, or — for a name that isn't a recognized SPDX identifier, such as a distribution's own `GPLv2+` — a free-form license name.

Where the license comes from:

| Packages | Source |
|---|---|
| npm (`package-lock.json` v2/v3), Node.js packages in images | The `license` field recorded locally |
| Packagist (`composer.lock`) | The `license` field recorded in the lockfile; several licenses there are a choice, written as an SPDX `OR` expression |
| Alpine (apk), rpm-based images | The license field of the package database |
| Debian/Ubuntu (dpkg) | Each package's `/usr/share/doc/<package>/copyright` file, when it's in Debian's machine-readable format |
| Go, npm, PyPI, Maven, NuGet, crates.io, RubyGems | [deps.dev](https://deps.dev) (Google's Open Source Insights), looked up by package and version |
| CocoaPods | The pod's podspec, from the CocoaPods spec CDN |
| Pub, SwiftURL | Not available — no license is recorded |

The deps.dev and CocoaPods lookups need network access, and send package names and versions to those services. Pass `--no-license-lookup` to skip them and include only locally recorded licenses:

```console
$ ojo fs -f sbom --no-license-lookup . > sbom.json
```

If a lookup fails, ojo prints a warning and still writes the SBOM, without the licenses that needed the network. A component with no `licenses` entry means the license is unknown, not that the package is unlicensed.

This identifies licenses; it doesn't evaluate them. There's no allow/deny policy or exit code tied to a license — see [Roadmap](../roadmap.md).

!!! note
    `-f sbom` only enumerates packages — it doesn't run the vulnerability scanner or contact OSV.dev, and with `--no-license-lookup` it needs no network access at all. There's no SPDX output format yet, and no SBOM *input* support (ojo can't scan an existing SBOM the way `trivy sbom` can) — see [Roadmap](../roadmap.md).
