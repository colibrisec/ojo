# Target: SBOM

`ojo sbom` checks the packages listed in an existing Software Bill of Materials for known vulnerabilities, without access to the source tree or image it describes.

```console
$ ojo sbom bom.cdx.json
$ syft alpine:3.19 -o spdx-json > bom.spdx.json && ojo sbom bom.spdx.json
```

`--scanners license` checks the SBOM's licenses against your [license policy](../scanner/license.md) instead of, or alongside (`--scanners vuln,license`), the vulnerability check. Licenses recorded in the SBOM are used as they are; missing ones are looked up online unless you pass `--no-license-lookup`.

## Formats

| Format | Read |
|---|---|
| CycloneDX JSON | ✅ (any spec version) |
| CycloneDX XML | ✅ |
| SPDX 2.x JSON | ✅ |
| SPDX tag-value, SPDX 3.0 | ❌ |

The format is detected from the file's content, not its name.

## How entries are matched

Each package is identified by its [purl](https://github.com/package-url/purl-spec), which carries the ecosystem, name and version ojo needs to query advisories. Every ecosystem `ojo fs` and `ojo image` check is recognised, with the same purl shapes ojo itself writes (see [SBOM](../sbom.md)), so `-f sbom`/`-f spdx` output from ojo scans the same way the original target did. SBOMs from other tools work too:

- **OS packages** (`pkg:deb`, `pkg:apk`, `pkg:rpm`) need a `distro` qualifier (`distro=debian-12`, `distro=alpine-3.19.1`, `distro=rhel-9.3`, …) to know which release's advisories apply. Distribution advisories are filed under the source package, read from the purl's `upstream` qualifier (syft), a `aquasecurity:trivy:SrcName` CycloneDX property, or an SPDX `sourceInfo` of the form `built package from: <name> ...` (Trivy). An `epoch` qualifier is applied to the version.
- Checked through the same sources as an image scan: OSV, plus Amazon's own advisories for Amazon Linux.
- CycloneDX components nested under other components are included; the BOM's `metadata.component` (the thing being described) isn't. In SPDX, the package the document `DESCRIBES` and packages whose purpose is `OPERATING-SYSTEM` or `CONTAINER` are skipped when they aren't a checkable package.

Scanning a Trivy-generated SBOM of `debian:12-slim` this way gives the same findings as `ojo image debian:12-slim`.

## What isn't checked

Entries ojo can't check are listed in a warning on stderr rather than silently dropped, since a quiet skip would read as a clean result:

- a library component with a version but no purl
- a purl type ojo has no advisories for (`pkg:github`, `pkg:oci`, `pkg:generic`, …), or one without a version
- OS packages of a distribution ojo has no advisories for (Fedora, CentOS, …) or with no `distro` qualifier

## Converting

`-f sbom` and `-f spdx` write the SBOM's packages back out instead of scanning them, so `ojo sbom bom.spdx.json -f sbom` converts SPDX to CycloneDX and the reverse. Licenses are carried over; anything else in the input (dependency relationships, hashes, suppliers) isn't.

## Flags

`ojo sbom` takes the same `--kev`, `--vex-file`/`-f vex`, `--ignore-file`, `--cyclonedx-version`, and `--sarif-omit-suppressed` flags as `ojo image`; see [CLI Reference](../../reference/cli.md#ojo-sbom).
