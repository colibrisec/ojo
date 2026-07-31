# Target: Filesystem

```console
$ ojo fs [path]
```

Scans a directory (default `.`) for dependency manifests, secrets, misconfiguration, and (Go) source code. Which scanners run is controlled by [`--scanners`](../configuration.md).

`node_modules/`, `.git/`, and `vendor/` are always skipped.

## Dependency discovery

ojo walks the tree and parses every recognized manifest/lockfile it finds:

| Ecosystem | Files | Notes |
|---|---|---|
| Go | `go.mod` | Parsed with `golang.org/x/mod/modfile`; includes indirect requires |
| npm | `package-lock.json` | Supports both the v1 (`dependencies`) and v2/v3 (`packages`) lockfile shapes |
| PyPI | `requirements.txt`, `Pipfile.lock`, `poetry.lock` | `requirements.txt`: only pinned `name==version` lines — ranges (`>=`, `~=`), extras, and VCS URLs are silently skipped rather than guessed at. `Pipfile.lock`/`poetry.lock` are fully-resolved lockfiles, no such gap. |
| PHP / Packagist | `composer.lock` | Fully-resolved lockfile |
| .NET / NuGet | `packages.lock.json` | Opt-in file (`RestorePackagesWithLockFile=true`) — most .NET projects won't have it |
| Dart / Pub | `pubspec.lock` | Fully-resolved lockfile |
| Rust / crates.io | `Cargo.lock` | Fully-resolved lockfile |
| Ruby / RubyGems | `Gemfile.lock` | Fully-resolved lockfile |
| Java / Maven | `pom.xml`, `gradle.lockfile` | `gradle.lockfile` is Gradle's opt-in dependency-locking output — fully resolved. `pom.xml` is **not** a lockfile: property placeholders (`${spring.version}`) are resolved against that same file's `<properties>` block only; anything requiring parent-POM inheritance or a `<dependencyManagement>` section elsewhere is silently skipped rather than guessed at. |
| Swift / SwiftURL | `Package.resolved` | Fully-resolved lockfile (both the pre-Xcode-13 v1 shape and the v2/v3 shape). Branch/revision-pinned dependencies with no tagged version are skipped — OSV's SwiftURL ecosystem matches by SemVer tag. **CocoaPods (`Podfile.lock`) is not supported: OSV has no CocoaPods ecosystem at all**, so there's nowhere to send a query regardless of parsing effort. |

There is no unlocked-manifest support (`package.json` without a lockfile, `build.gradle`/`build.gradle.kts` DSL parsing) — ojo only reads already-resolved dependency data. See [Roadmap & Limitations](../../roadmap.md).

## Example

```console
$ ojo fs --scanners vuln,secret,misconfig,sast ./my-project
```

## See also

- [Vulnerability scanner](../scanner/vulnerability.md)
- [Secret scanner](../scanner/secret.md)
- [Misconfiguration scanner](../scanner/misconfiguration.md)
- [SAST scanner](../scanner/sast.md)
