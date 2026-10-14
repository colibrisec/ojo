# SBOM

Every command supports `-f sbom` to emit a [CycloneDX](https://cyclonedx.org/) 1.7 JSON Software Bill of Materials of the packages it discovered, and `-f spdx` for an [SPDX](https://spdx.dev) 2.3 JSON one, instead of running the vulnerability scanner.

```console
$ ojo fs -f sbom . > sbom.cdx.json
$ ojo image -f spdx python:3.14-slim > sbom.spdx.json
```

To scan an SBOM, ojo's or another tool's, see [SBOM target](target/sbom.md).

Each package includes a [package URL (purl)](https://github.com/package-url/purl-spec) built from its name, version, and ecosystem:

| Ecosystem | purl |
|---|---|
| Go | `pkg:golang/github.com/pkg/errors@v0.9.1` |
| npm | `pkg:npm/%40babel/core@7.0.0` |
| PyPI | `pkg:pypi/django@3.2.0` |
| Maven | `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` |
| crates.io, RubyGems, NuGet, Pub | `pkg:cargo/...`, `pkg:gem/...`, `pkg:nuget/...`, `pkg:pub/...` |
| Packagist | `pkg:composer/laravel/framework@8.0.0` |
| SwiftURL | `pkg:swift/github.com/apple/swift-nio@2.0.0` |
| CocoaPods | `pkg:cocoapods/GoogleUtilities@7.5.2#NSData%2Bzlib` (subspec as subpath) |
| Debian, Ubuntu | `pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12&upstream=openssl` |
| Alpine | `pkg:apk/alpine/libcrypto3@3.1.4-r5?distro=alpine-3.19&upstream=openssl` |
| RHEL, Rocky, AlmaLinux, Amazon Linux | `pkg:rpm/redhat/openssl-libs@3.0.7-25.el9_3?distro=rhel-9&epoch=1&upstream=openssl` |

OS packages carry their source package as `upstream` when it differs from the binary package name, and an rpm epoch as `epoch`, the same convention syft uses, so the SBOM can be scanned later with nothing lost.

!!! note "Changed purls"
    Before ojo listed every ecosystem in this table, everything but Go, npm, PyPI and CocoaPods was written as `pkg:generic/...`, and Go versions had no `v` prefix. A VEX document whose products were written against those old purls needs updating, since `--vex-file` matches purls exactly.

## SPDX

`-f spdx` writes an SPDX 2.3 JSON document: one package per distinct package, each with its purl as a `PACKAGE-MANAGER` external reference and its license as `licenseDeclared`. A license name SPDX doesn't recognise (a distribution's own short name such as `GPLv2+`) is written as a `LicenseRef-` with the original text in `hasExtractedLicensingInfos`. `--cyclonedx-version` doesn't apply.

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
