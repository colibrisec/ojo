# Android manifest misconfiguration checks — design

Status: approved, not yet implemented.

## Motivation

`TODO.md`'s "Mobile app binary scanning (APK / IPA)" backlog item recommends
starting with just Android manifest/permission analysis — the smallest real
slice of that item, and one that fits ojo's existing `misconfig` scanner
shape rather than requiring a new target type or `--scanners` value. This
spec covers that slice only. Native `.so` library fingerprinting, DEX
bytecode analysis, and anything iOS/IPA-related remain out of scope and
un-started, same as `TODO.md` already documents.

## Why this needs a design doc, not just a bounded change

Every other file format `internal/misconfig` reads (Dockerfile, YAML, JSON,
`.tf`) is plain text. Android's manifest is compiled into a binary format
(AXML) before it ships inside the `.apk` zip — that's a real new piece of
parsing machinery, and how to get it (hand-roll vs. dependency) plus how to
validate it (no Android SDK is installed on this dev machine) are both
genuine decisions, not mechanical extensions of an existing flow.

## Decisions

### 1. AXML decoding: use `github.com/shogo82148/androidbinary`

New dependency. MIT license, 280 stars, pushed within the last week at
research time, ships its own fuzz tests (`fuzz_test.go`) and real APK test
fixtures (`apk/testdata/helloworld.apk`).

We use **only its root package** (`androidbinary.NewXMLFile`), not its
`apk` subpackage. The root package decodes raw AXML bytes into a
`*bytes.Reader` of genuine XML text (verified by reading `xml.go`: typed
boolean attribute values render as the literal strings `"true"`/`"false"`,
string-valued attributes render as-is) — from there we parse with stdlib
`encoding/xml` ourselves, the same way `k8s.go`/`cloudformation.go` already
parse their formats.

The `apk` subpackage's typed `Manifest` struct was deliberately **not**
used: it has no `exported` field and no `service`/`receiver`/`provider`
fields on `Application` (only `Activities`/`ActivityAliases`/`MetaData`),
which are exactly what `android-exported-component-no-permission` needs. It
also pulls in `resources.arsc` parsing and `image/jpeg`/`image/png`
decoding for icon extraction, neither of which this feature needs.

Rejected alternative: hand-rolling our own AXML decoder. Consistent with
this project's general dependency-averse default (see `TODO.md`'s ecosystem
parser tiers), but rejected here because AXML is a real binary chunk format
(string pools, typed values, namespace chunks) and there is no Android
tooling on this machine to validate a hand-rolled decoder against real
manifests. A silent misdecode is the same "silent zero-results" failure
mode `TODO.md` already warns is the worst outcome for a security tool — the
existing library is fuzz-tested and MIT-licensed, so reusing it is the
lower-risk choice.

### 2. Where the code lives

- `internal/misconfig/android.go` — zip/decode plumbing, the manifest
  struct, and the four check functions.
- `internal/misconfig/misconfig.go` gains one more `switch` case in `Scan`,
  alongside the existing `isDockerfile`/`.tf`/`.yaml` cases:

  ```go
  case isAPKFile(name):
      found, err := scanAndroidManifest(path)
      if err != nil {
          return nil // skip unparsable/non-manifest .apk, don't fail the whole scan
      }
      issues = append(issues, found...)
  ```

  This mirrors the existing comment and behavior on the Dockerfile case
  directly above it — no new error-handling policy introduced.
- No new CLI flag, command, or `--scanners` value. An `.apk` file anywhere
  under the scanned root is picked up automatically under
  `--scanners misconfig` (already opt-in, not part of the default `vuln`
  scanner set) the same way a `Dockerfile` or `.tf` file is.

### 3. Manifest struct shape

```go
type androidManifest struct {
    XMLName          xml.Name              `xml:"manifest"`
    Package          string                `xml:"package,attr"`
    UsesPermissions  []androidPermission   `xml:"uses-permission"`
    Application      androidApplication    `xml:"application"`
}

type androidPermission struct {
    Name string `xml:"http://schemas.android.com/apk/res/android name,attr"`
}

type androidApplication struct {
    Debuggable           string              `xml:"http://schemas.android.com/apk/res/android debuggable,attr"`
    UsesCleartextTraffic string              `xml:"http://schemas.android.com/apk/res/android usesCleartextTraffic,attr"`
    Permission           string              `xml:"http://schemas.android.com/apk/res/android permission,attr"` // app-level fallback guard
    Activities []androidComponent `xml:"activity"`
    Services   []androidComponent `xml:"service"`
    Receivers  []androidComponent `xml:"receiver"`
    Providers  []androidComponent `xml:"provider"`
}

type androidComponent struct {
    Name          string                  `xml:"http://schemas.android.com/apk/res/android name,attr"`
    Exported      string                  `xml:"http://schemas.android.com/apk/res/android exported,attr"` // "" means unset
    Permission    string                  `xml:"http://schemas.android.com/apk/res/android permission,attr"`
    IntentFilters []struct{}              `xml:"intent-filter"`
}
```

Namespace-qualified `xml:"URI local,attr"` tags follow the same pattern the
`androidbinary`-decoded output actually emits (`xmlns:android="http://schemas.android.com/apk/res/android"`
on the root element) — confirmed by reading `xml.go`'s `addNamespacePrefix`.

### 4. The four checks

All four live in `internal/misconfig/android.go`, following the existing
`newIssue(ruleID, severity, path, line, title, message)` helper. Manifests
decoded this way carry no line numbers (same as every other struct-based
misconfig check in this codebase — CloudFormation/K8s findings are also
package/resource-level, not line-level), so `line` is `0` throughout.

| Rule ID | Severity | Condition | CWE |
|---|---|---|---|
| `android-debuggable` | HIGH | `<application android:debuggable="true">` | CWE-489 |
| `android-cleartext-traffic` | MEDIUM | `<application android:usesCleartextTraffic="true">` (explicit only — default has been `false` since API 28, so an explicit `true` is the actionable signal, not the attribute's absence) | CWE-319 |
| `android-exported-component-no-permission` | HIGH | A component (`activity`/`service`/`receiver`/`provider`) is exported — `exported="true"` explicitly, **or** `exported` is absent *and* it has at least one `<intent-filter>` (real pre-API-31 platform default: a component with an intent filter and no explicit `exported` attribute is exported) — **and** neither the component's own `android:permission` nor the `<application>`-level fallback `android:permission` is set | CWE-926 (the CWE that names this exact Android issue) |
| `android-broad-permission` | MEDIUM | Any `<uses-permission>` name matches a small curated list: `QUERY_ALL_PACKAGES`, `SYSTEM_ALERT_WINDOW`, `REQUEST_INSTALL_PACKAGES`, `READ_SMS`, `RECEIVE_SMS`, `BIND_ACCESSIBILITY_SERVICE`, `WRITE_SECURE_SETTINGS`, `MANAGE_EXTERNAL_STORAGE` | CWE-250 |

`android-broad-permission` is deliberately a curated, documented-as-non-exhaustive
list — same precedent as the existing SSRF sink list and weak-cipher
algorithm list elsewhere in `internal/misconfig`/`internal/sast`. One
`model.Issue` per matched permission, not one issue for the whole manifest.

### 5. Explicit non-goals (documented, not silently dropped)

- No `resources.arsc` parsing, so an attribute expressed as a resource
  reference (`android:debuggable="@bool/is_debug"`) rather than a literal
  is not resolved and will not fire any check — same "flag the candidate,
  don't resolve everything" ceiling this codebase already accepts for
  several SAST rules.
- Split APKs (Android App Bundle's per-ABI/density split `.apk` files, only
  the base APK carries the full manifest) are not specially merged — each
  `.apk` file found is checked independently, using whatever manifest it
  contains.
- iOS/IPA is untouched by this slice, as already noted in `TODO.md`.
- Native library fingerprinting and DEX bytecode analysis remain future,
  separately-scoped `TODO.md` items.

## Testing

- `internal/misconfig/android_test.go` — one test per check plus negative
  cases (e.g., an exported component *with* a permission guard doesn't
  fire; `exported="false"` with an intent-filter doesn't fire).
- A test-only AXML encoder (its own file, not compiled into the `ojo`
  binary — e.g. `internal/misconfig/axml_fixture_test.go`) builds minimal
  valid binary chunks (string pool, namespace, element + typed attributes)
  for each fixture manifest. Correctness is established by round-tripping
  each encoded fixture through the real `androidbinary` decoder and
  asserting the expected attributes come back out — the same "verify
  against the real thing" discipline this codebase already applies to
  tree-sitter grammar onboarding, applied here to fixture generation
  instead of to a parser.
- One end-to-end test using a real binary manifest: the
  `AndroidManifest.xml` entry (1,904 bytes) extracted from
  `shogo82148/androidbinary`'s own MIT-licensed `apk/testdata/helloworld.apk`
  test fixture, committed as
  `internal/misconfig/testdata/android/helloworld_AndroidManifest.xml`
  with a comment noting its source and license. **Correction from an
  earlier draft of this spec, found by actually decoding it during
  implementation prototyping rather than assumed:** this manifest is not
  clean — it has `android:debuggable="true"` and one `<activity>` with an
  `<intent-filter>` and no explicit `exported`/`permission` attribute
  (implicitly exported, unguarded), so it genuinely fires both
  `android-debuggable` and `android-exported-component-no-permission`. It
  has no `usesCleartextTraffic` attribute and no `<uses-permission>`
  elements at all, so it does not fire the other two rules. This makes it
  a real cross-rule end-to-end fixture, not just a decode-pipeline sanity
  check.
- Verified end-to-end through the built binary too: a real `.apk`
  (zip containing a synthesized risky `AndroidManifest.xml` entry) scanned
  via `ojo fs --scanners misconfig`, confirming all four rule IDs surface
  in `table` output — not just unit-tested in isolation, matching this
  project's established verification standard.

## Docs

- `docs/guide/scanner/misconfiguration.md` — new "Android manifest
  (`AndroidManifest.xml` inside `.apk`)" section: the four-row rule table
  plus the ceiling notes from the Non-goals section above.
- `TODO.md` — the "Mobile app binary scanning (APK / IPA)" entry gets this
  slice marked `✅ shipped` (Android manifest/permission analysis, round 1
  of that item), leaving native-lib fingerprinting, DEX analysis, and
  iOS/IPA explicitly still open, matching how every other multi-round
  `TODO.md` item is closed out incrementally.
