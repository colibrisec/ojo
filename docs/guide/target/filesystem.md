# Target: Filesystem

```console
$ ojo fs [path]
```

Scans a directory (default `.`) for dependency manifests, secrets, misconfiguration, and source-level SAST and code-quality issues (Go, Python, JS/TS, PHP, Ruby, Java). Which scanners run is controlled by [`--scanners`](../configuration.md).

`node_modules/`, `.git/`, and `vendor/` are always skipped. Pass `--respect-gitignore` to also skip untracked files that git ignores (build output, coverage reports), so a local scan matches what CI sees in a fresh checkout — see the [CLI Reference](../../reference/cli.md#-respect-gitignore).

## Dependency discovery

ojo walks the tree and parses every recognized manifest/lockfile it finds:

| Ecosystem | Files | Notes |
|---|---|---|
| Go | `go.mod` | Parsed with `golang.org/x/mod/modfile`; includes indirect requires |
| npm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `package-lock.json`: both the v1 (`dependencies`) and v2/v3 (`packages`) shapes. `yarn.lock`: both classic (v1) and Berry (v2+). `pnpm-lock.yaml`: lockfile versions 5 through 9. Workspace members, `link:`/`file:` dependencies, and git/tarball dependencies with no registry version are skipped; aliases are reported under the real package name. |
| PyPI | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pdm.lock` | `requirements.txt`: only pinned `name==version` lines — ranges (`>=`, `~=`), extras, and VCS URLs are silently skipped rather than guessed at. The four lockfiles are fully resolved, no such gap. In `uv.lock`, the project itself and editable/path workspace members are skipped. |
| PHP / Packagist | `composer.lock` | Fully-resolved lockfile |
| .NET / NuGet | `packages.lock.json` | Opt-in file (`RestorePackagesWithLockFile=true`) — most .NET projects won't have it |
| Dart / Pub | `pubspec.lock` | Fully-resolved lockfile |
| Rust / crates.io | `Cargo.lock` | Fully-resolved lockfile |
| Ruby / RubyGems | `Gemfile.lock` | Fully-resolved lockfile |
| Java / Maven | `pom.xml`, `gradle.lockfile` | `gradle.lockfile` is Gradle's opt-in dependency-locking output — fully resolved. `pom.xml` is **not** a lockfile: property placeholders (`${spring.version}`) are resolved against that same file's `<properties>` block only; anything requiring parent-POM inheritance or a `<dependencyManagement>` section elsewhere is silently skipped rather than guessed at. |
| Swift / SwiftURL | `Package.resolved` | Fully-resolved lockfile (both the pre-Xcode-13 v1 shape and the v2/v3 shape). Branch/revision-pinned dependencies with no tagged version are skipped — OSV's SwiftURL ecosystem matches by SemVer tag. |
| CocoaPods | `Podfile.lock` | Subspecs (`Firebase/Core`) are reported as their root pod. OSV has no CocoaPods ecosystem, so vulnerability matching goes through the pod's git repository — see [CocoaPods](#cocoapods) below. |

### CocoaPods

OSV files advisories for Swift and Objective-C libraries under SwiftURL, keyed by git repository (`github.com/apple/swift-nio`), not by pod name. To check a pod, ojo fetches its podspec from the public CocoaPods spec CDN (`cdn.cocoapods.org`), reads the git repository it's built from, and queries OSV for that repository at the pod's version.

A pod can't be checked if it has no public podspec (a private pod) or its podspec points at a plain archive instead of a git repository. ojo prints how many pods were skipped for that reason rather than silently reporting fewer packages. Such pods still appear in `-f sbom` output. Matching also assumes the pod version is the repository's release tag, which is the convention but not a guarantee.

There is no unlocked-manifest support (`package.json` without a lockfile, `build.gradle`/`build.gradle.kts` DSL parsing) — ojo only reads already-resolved dependency data. See [Roadmap & Limitations](../../roadmap.md).

## Example

```console
$ ojo fs --scanners vuln,secret,misconfig,sast,quality ./my-project
```

## See also

- [Vulnerability scanner](../scanner/vulnerability.md)
- [Secret scanner](../scanner/secret.md)
- [Misconfiguration scanner](../scanner/misconfiguration.md)
- [SAST scanner](../scanner/sast.md)
- [Code Quality scanner](../scanner/quality.md)
