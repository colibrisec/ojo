# Android Manifest Misconfiguration Checks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add four misconfiguration checks (`android-debuggable`, `android-cleartext-traffic`, `android-exported-component-no-permission`, `android-broad-permission`) that fire against the `AndroidManifest.xml` inside any `.apk` file found during an `ojo fs --scanners misconfig` scan.

**Architecture:** `internal/misconfig.Scan` already walks every file in the tree and dispatches by filename (see `isDockerfile`/`isSkillFile`/the `.tf` case in `internal/misconfig/misconfig.go`). We add one more dispatch case for `.apk` files. Android's manifest ships compiled into a binary XML format (AXML) inside the APK's zip container, so a new file, `internal/misconfig/android.go`, opens the zip, decodes the `AndroidManifest.xml` entry from AXML into real XML text via a new third-party dependency, parses that text with stdlib `encoding/xml` into a small manifest struct, and runs four check functions against it — the same "decode into a struct, then check fields" shape `internal/misconfig/k8s.go` already uses for Kubernetes YAML.

**Tech Stack:** Go, stdlib `archive/zip` + `encoding/xml`, `github.com/shogo82148/androidbinary` (new dependency, MIT license, root package only — not its `apk` subpackage).

**Spec:** `docs/superpowers/specs/2026-09-18-android-manifest-misconfig-design.md`

## Global Constraints

- New dependency: `github.com/shogo82148/androidbinary` — use only its root package (`androidbinary.NewXMLFile`). Never import its `apk` subpackage (missing `exported`/`service`/`receiver`/`provider` fields we need, and pulls in `resources.arsc` + icon-image decoding we don't).
- No new CLI flag, command, or `--scanners` value. `.apk` detection is filename-based inside `internal/misconfig.Scan`'s existing walk, exactly like the `Dockerfile`/`SKILL.md`/`.tf` cases already there.
- A bad/non-APK/corrupt `.apk` or a missing `AndroidManifest.xml` entry is a skip, not a scan failure — matches the `// skip unparsable file, don't fail the whole scan` comment already on the Dockerfile case in `internal/misconfig/misconfig.go`.
- Every `model.Issue` built for these checks uses `newIssue(ruleID, severity, path, line, title, message)` (defined in `internal/misconfig/misconfig.go`) with `line` hardcoded to `1` — the same convention `internal/misconfig/mcp.go`/`internal/misconfig/k8s.go` already use for struct-decoded formats with no real line-position tracking.
- Every new rule ID gets an entry in `internal/misconfig/cwe.go`'s `ruleCWEs` map (validated generically by the existing `TestRuleCWEsWellFormed` in `internal/misconfig/cwe_test.go` — no per-rule test needed there).
- All test coverage for these checks goes through the package's top-level `Scan(dir)` entry point, matching how every existing misconfig check in `internal/misconfig/misconfig_test.go` (e.g. `TestSkillChecks`, `TestSkillBroadToolPermissions`) is tested — not through calling an internal `scanX` function directly, except where a task explicitly predates `Scan`'s wiring (Task 2, below).
- Every design decision below (dependency choice, struct shape, exported-by-default-via-intent-filter semantics, the ref-0 namespace bug workaround) was verified by actually building and round-tripping real AXML bytes through the real `androidbinary` decoder during planning, not assumed. Full working code from that verification is what's transcribed into the tasks below.

---

### Task 1: Add the `androidbinary` dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

**Interfaces:**
- Produces: the `github.com/shogo82148/androidbinary` module available to import as `"github.com/shogo82148/androidbinary"`, exposing `androidbinary.NewXMLFile(r io.ReaderAt) (*androidbinary.XMLFile, error)` and `(*androidbinary.XMLFile).Reader() *bytes.Reader`.

- [ ] **Step 1: Add the dependency**

Run: `go get github.com/shogo82148/androidbinary@v1.0.6`

- [ ] **Step 2: Verify it resolved cleanly**

Run: `go build ./...`
Expected: succeeds with no errors (the dependency adds no transitive requirements — its own `go.mod` has no `require` block).

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "Add github.com/shogo82148/androidbinary dependency for Android manifest decoding"
```

---

### Task 2: AXML fixture builder, manifest struct, and decode plumbing

**Files:**
- Create: `internal/misconfig/android.go`
- Create: `internal/misconfig/axml_fixture_test.go`

**Interfaces:**
- Consumes: `androidbinary.NewXMLFile`/`.Reader()` (Task 1).
- Produces (for later tasks):
  - `isAPKFile(name string) bool`
  - `type androidManifest struct { Package string; UsesPermissions []androidPermission; Application androidApplication }`
  - `type androidApplication struct { Debuggable, UsesCleartextTraffic, Permission string; Activities, Services, Receivers, Providers []androidComponent }`
  - `type androidComponent struct { Name, Exported, Permission string; IntentFilters []struct{} }`
  - `decodeAndroidManifest(path string) (androidManifest, error)`
  - Test-only, from `axml_fixture_test.go`: `writeTestAPK(t *testing.T, dir string, root elem) string`, `baseManifest(children ...elem) elem`, `appElem(attrs []attr, children ...elem) elem`, `boolAttr(name string, v bool) attr`, `strAttr(name, v string) attr`, `androidNS` (the `"http://schemas.android.com/apk/res/android"` namespace URI constant).

This is the one genuinely new piece of machinery in this feature: Android's manifest is compiled into a binary chunk format (AXML) before it's zipped into the `.apk`. `androidbinary.NewXMLFile` decodes those bytes into a `*bytes.Reader` of real XML text; from there we parse with stdlib `encoding/xml` like any other misconfig check. Since there's no Android SDK on this machine to compile real test manifests, `axml_fixture_test.go` is a small test-only AXML *encoder* — good enough to produce exactly the chunk shapes our checks need, verified below by decoding its own output through the real library.

- [ ] **Step 1: Write `internal/misconfig/android.go`**

```go
package misconfig

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/shogo82148/androidbinary"

	"github.com/colibrisec/ojo/internal/model"
)

func isAPKFile(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".apk")
}

type androidPermission struct {
	Name string `xml:"http://schemas.android.com/apk/res/android name,attr"`
}

// androidComponent covers an activity/service/receiver/provider -- the four
// manifest element types that share the same exported/permission/
// intent-filter shape.
type androidComponent struct {
	Name          string     `xml:"http://schemas.android.com/apk/res/android name,attr"`
	Exported      string     `xml:"http://schemas.android.com/apk/res/android exported,attr"`
	Permission    string     `xml:"http://schemas.android.com/apk/res/android permission,attr"`
	IntentFilters []struct{} `xml:"intent-filter"`
}

type androidApplication struct {
	Debuggable           string             `xml:"http://schemas.android.com/apk/res/android debuggable,attr"`
	UsesCleartextTraffic string             `xml:"http://schemas.android.com/apk/res/android usesCleartextTraffic,attr"`
	Permission           string             `xml:"http://schemas.android.com/apk/res/android permission,attr"`
	Activities           []androidComponent `xml:"activity"`
	Services             []androidComponent `xml:"service"`
	Receivers            []androidComponent `xml:"receiver"`
	Providers            []androidComponent `xml:"provider"`
}

type androidManifest struct {
	XMLName         xml.Name            `xml:"manifest"`
	Package         string              `xml:"package,attr"`
	UsesPermissions []androidPermission `xml:"uses-permission"`
	Application     androidApplication  `xml:"application"`
}

// decodeAndroidManifest opens path as a zip archive, decodes its
// AndroidManifest.xml entry from Android's compiled binary XML format
// (AXML) via androidbinary, and unmarshals the resulting plain XML into an
// androidManifest.
func decodeAndroidManifest(path string) (androidManifest, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return androidManifest{}, err
	}
	defer r.Close()

	var raw []byte
	for _, f := range r.File {
		if f.Name == "AndroidManifest.xml" {
			rc, err := f.Open()
			if err != nil {
				return androidManifest{}, err
			}
			raw, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return androidManifest{}, err
			}
			break
		}
	}
	if raw == nil {
		return androidManifest{}, fmt.Errorf("%s: no AndroidManifest.xml entry", path)
	}

	xf, err := androidbinary.NewXMLFile(bytes.NewReader(raw))
	if err != nil {
		return androidManifest{}, err
	}
	xmlBytes, err := io.ReadAll(xf.Reader())
	if err != nil {
		return androidManifest{}, err
	}

	var m androidManifest
	if err := xml.Unmarshal(xmlBytes, &m); err != nil {
		return androidManifest{}, err
	}
	return m, nil
}

// silence unused-import concerns until Task 3 adds the first caller of model.Issue in this file
var _ = model.Issue{}
```

Leave that last `var _ = model.Issue{}` line in for now — Task 3 replaces it with real use of `model.Issue` when the first check function is added, and removes this line.

- [ ] **Step 2: Write `internal/misconfig/axml_fixture_test.go`**

```go
package misconfig

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------
// A minimal, test-only encoder for Android's compiled binary XML format
// (AXML). There's no Android SDK on record-and-replay CI/dev machines to
// compile real manifests, so this builds exactly the chunk shapes our
// checks need (a string pool, one namespace, nested elements with typed
// string/boolean attributes) and is verified by decoding its own output
// through the real androidbinary library in TestAXMLFixtureBuilderRoundTrips
// below -- never shipped in the ojo binary itself.
// ---------------------------------------------------------------------

const androidNS = "http://schemas.android.com/apk/res/android"

const (
	resStringPoolChunkType   uint16 = 0x0001
	resXMLChunkType          uint16 = 0x0003
	resXMLStartNamespaceType uint16 = 0x0100
	resXMLEndNamespaceType   uint16 = 0x0101
	resXMLStartElementType   uint16 = 0x0102
	resXMLEndElementType     uint16 = 0x0103

	utf8Flag       uint32 = 1 << 8
	typeString     uint8  = 0x03
	typeIntBoolean uint8  = 0x12
	nilRef         uint32 = 0xFFFFFFFF
)

// attr is one attribute on a fixture element. If IsBool is true it's
// encoded as a typed boolean (TypeIntBoolean, decoding to the literal text
// "true"/"false"); otherwise StrValue is encoded as a raw string reference.
type attr struct {
	NS       string
	Name     string
	StrValue string
	IsBool   bool
	BoolVal  bool
}

func boolAttr(name string, v bool) attr { return attr{NS: androidNS, Name: name, IsBool: true, BoolVal: v} }
func strAttr(name, v string) attr       { return attr{NS: androidNS, Name: name, StrValue: v} }

// elem is one XML element to encode, with nested children.
type elem struct {
	Name     string
	Attrs    []attr
	Children []elem
}

func baseManifest(children ...elem) elem {
	return elem{Name: "manifest", Attrs: []attr{{Name: "package", StrValue: "com.example.app"}}, Children: children}
}

func appElem(attrs []attr, children ...elem) elem {
	return elem{Name: "application", Attrs: attrs, Children: children}
}

// axmlBuilder accumulates an interned string pool plus a sequence of XML
// structural chunks, then serializes both into a single
// AndroidManifest.xml-shaped binary blob via Build.
type axmlBuilder struct {
	strings []string
	index   map[string]uint32
	chunks  bytes.Buffer
}

func newAXMLBuilder() *axmlBuilder {
	b := &axmlBuilder{index: map[string]uint32{}}
	// Reserve string-pool index 0 for an unused placeholder. androidbinary's
	// xmlNamespaces.get() returns the Go zero value (ResStringPoolRef(0))
	// both for "no namespace found" and for a legitimately-stored ref of 0,
	// so a real namespace prefix string (e.g. "android") must never land at
	// index 0, or every namespaced element/attribute using it decodes as
	// "invalid reference" -- found by actually round-tripping through the
	// real decoder during planning, not assumed.
	b.intern("")
	return b
}

func (b *axmlBuilder) intern(s string) uint32 {
	if ref, ok := b.index[s]; ok {
		return ref
	}
	ref := uint32(len(b.strings))
	b.strings = append(b.strings, s)
	b.index[s] = ref
	return ref
}

func (b *axmlBuilder) internRef(s string) uint32 {
	if s == "" {
		return nilRef
	}
	return b.intern(s)
}

func writeU16(buf *bytes.Buffer, v uint16) {
	var raw [2]byte
	binary.LittleEndian.PutUint16(raw[:], v)
	buf.Write(raw[:])
}

func writeU32(buf *bytes.Buffer, v uint32) {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], v)
	buf.Write(raw[:])
}

// resXMLTreeNodeHeader returns the 8 bytes making up ResXMLTreeNode's own
// fields beyond the shared ResChunkHeader: LineNumber(4) + Comment(4, nil).
func resXMLTreeNodeHeader() []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf[0:4], 1)
	binary.LittleEndian.PutUint32(buf[4:8], nilRef)
	return buf
}

func (b *axmlBuilder) writeChunk(chunkType uint16, nodeHeader, body []byte) {
	headerSize := 8 + len(nodeHeader)
	size := headerSize + len(body)
	var out bytes.Buffer
	writeU16(&out, chunkType)
	writeU16(&out, uint16(headerSize))
	writeU32(&out, uint32(size))
	out.Write(nodeHeader)
	out.Write(body)
	b.chunks.Write(out.Bytes())
}

func (b *axmlBuilder) writeNamespaceStart(prefix, uri string) {
	var body bytes.Buffer
	writeU32(&body, b.intern(prefix))
	writeU32(&body, b.intern(uri))
	b.writeChunk(resXMLStartNamespaceType, resXMLTreeNodeHeader(), body.Bytes())
}

func (b *axmlBuilder) writeNamespaceEnd(prefix, uri string) {
	var body bytes.Buffer
	writeU32(&body, b.intern(prefix))
	writeU32(&body, b.intern(uri))
	b.writeChunk(resXMLEndNamespaceType, resXMLTreeNodeHeader(), body.Bytes())
}

func (b *axmlBuilder) writeElement(e elem) {
	nsRef := b.internRef("")
	nameRef := b.intern(e.Name)

	var attrBuf bytes.Buffer
	for _, a := range e.Attrs {
		writeU32(&attrBuf, b.internRef(a.NS))
		writeU32(&attrBuf, b.intern(a.Name))
		if a.IsBool {
			writeU32(&attrBuf, nilRef) // RawValue: none, typed value used instead
			writeU16(&attrBuf, 8)      // ResValue.Size
			attrBuf.WriteByte(0)       // ResValue.Res0
			attrBuf.WriteByte(typeIntBoolean)
			data := uint32(0)
			if a.BoolVal {
				data = 0xFFFFFFFF
			}
			writeU32(&attrBuf, data)
		} else {
			valRef := b.intern(a.StrValue)
			writeU32(&attrBuf, valRef) // RawValue: the string itself
			writeU16(&attrBuf, 8)
			attrBuf.WriteByte(0)
			attrBuf.WriteByte(typeString)
			writeU32(&attrBuf, valRef)
		}
	}

	var ext bytes.Buffer
	writeU32(&ext, nsRef)
	writeU32(&ext, nameRef)
	writeU16(&ext, 20) // AttributeStart: byte offset from this ext's start to the first attribute (20 = this header's own size)
	writeU16(&ext, 20) // AttributeSize: size of one ResXMLTreeAttribute (NS4+Name4+RawValue4+ResValue8)
	writeU16(&ext, uint16(len(e.Attrs)))
	writeU16(&ext, 0) // IDIndex
	writeU16(&ext, 0) // ClassIndex
	writeU16(&ext, 0) // StyleIndex
	ext.Write(attrBuf.Bytes())
	b.writeChunk(resXMLStartElementType, resXMLTreeNodeHeader(), ext.Bytes())

	for _, c := range e.Children {
		b.writeElement(c)
	}

	var endExt bytes.Buffer
	writeU32(&endExt, nsRef)
	writeU32(&endExt, nameRef)
	b.writeChunk(resXMLEndElementType, resXMLTreeNodeHeader(), endExt.Bytes())
}

// buildStringPool serializes the interned strings as a UTF-8-flavored
// ResStringPool chunk. Every fixture string used by this package is plain
// ASCII, so both the "UTF-16 length" and "UTF-8 length" prefixes AXML's
// UTF-8 string encoding requires are always the single-byte form and always
// equal to len(s).
func (b *axmlBuilder) buildStringPool() []byte {
	const headerSize = 28
	offsetsSize := 4 * len(b.strings)
	stringStart := uint32(headerSize + offsetsSize)

	var strData bytes.Buffer
	offsets := make([]uint32, len(b.strings))
	for i, s := range b.strings {
		offsets[i] = uint32(strData.Len())
		n := byte(len(s))
		strData.WriteByte(n) // UTF-16 length
		strData.WriteByte(n) // UTF-8 length
		strData.WriteString(s)
		strData.WriteByte(0) // NUL terminator
	}

	var out bytes.Buffer
	writeU16(&out, resStringPoolChunkType)
	writeU16(&out, headerSize)
	writeU32(&out, uint32(headerSize+offsetsSize+strData.Len()))
	writeU32(&out, uint32(len(b.strings))) // StringCount
	writeU32(&out, 0)                      // StyleCount
	writeU32(&out, utf8Flag)
	writeU32(&out, stringStart)
	writeU32(&out, 0) // StylesStart (unused, StyleCount == 0)
	for _, off := range offsets {
		writeU32(&out, off)
	}
	out.Write(strData.Bytes())
	return out.Bytes()
}

// Build returns the full AXML binary: an outer RES_XML_TYPE chunk wrapping
// the string pool followed by every structural chunk queued via
// writeNamespaceStart/writeElement/writeNamespaceEnd.
func (b *axmlBuilder) Build() []byte {
	var body bytes.Buffer
	body.Write(b.buildStringPool())
	body.Write(b.chunks.Bytes())

	var out bytes.Buffer
	writeU16(&out, resXMLChunkType)
	writeU16(&out, 8) // HeaderSize: bare ResChunkHeader, no extra fields on the outer chunk
	writeU32(&out, uint32(8+body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

// writeTestAPK builds a minimal AndroidManifest.xml from root (wrapped in
// the standard "android" namespace), packs it into a real zip archive under
// the entry name a real .apk uses, writes it to dir, and returns its path.
func writeTestAPK(t *testing.T, dir string, root elem) string {
	t.Helper()
	b := newAXMLBuilder()
	b.writeNamespaceStart("android", androidNS)
	b.writeElement(root)
	b.writeNamespaceEnd("android", androidNS)
	data := b.Build()

	path := filepath.Join(dir, "app.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	w, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestAXMLFixtureBuilderRoundTrips proves the fixture encoder above produces
// bytes the real androidbinary decoder accepts, and that decodeAndroidManifest
// (internal/misconfig/android.go) correctly turns them into an
// androidManifest -- before any check function depends on either.
func TestAXMLFixtureBuilderRoundTrips(t *testing.T) {
	dir := t.TempDir()
	activity := elem{Name: "activity", Attrs: []attr{strAttr("name", ".Main"), boolAttr("exported", true)}}
	path := writeTestAPK(t, dir, baseManifest(
		elem{Name: "uses-permission", Attrs: []attr{strAttr("name", "android.permission.INTERNET")}},
		appElem([]attr{boolAttr("debuggable", true)}, activity),
	))

	m, err := decodeAndroidManifest(path)
	if err != nil {
		t.Fatalf("decodeAndroidManifest: %v", err)
	}
	if m.Package != "com.example.app" {
		t.Errorf("Package = %q, want com.example.app", m.Package)
	}
	if m.Application.Debuggable != "true" {
		t.Errorf("Debuggable = %q, want true", m.Application.Debuggable)
	}
	if len(m.UsesPermissions) != 1 || m.UsesPermissions[0].Name != "android.permission.INTERNET" {
		t.Errorf("UsesPermissions = %+v", m.UsesPermissions)
	}
	if len(m.Application.Activities) != 1 || m.Application.Activities[0].Name != ".Main" {
		t.Errorf("Activities = %+v", m.Application.Activities)
	}
	if m.Application.Activities[0].Exported != "true" {
		t.Errorf("Activities[0].Exported = %q, want true", m.Application.Activities[0].Exported)
	}
}
```

- [ ] **Step 3: Run the test**

Run: `go test ./internal/misconfig/... -run TestAXMLFixtureBuilderRoundTrips -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/misconfig/android.go internal/misconfig/axml_fixture_test.go
git commit -m "Add Android manifest AXML decode plumbing and test fixture builder"
```

---

### Task 3: Wire `.apk` into `Scan`, add `android-debuggable`

**Files:**
- Modify: `internal/misconfig/android.go`
- Modify: `internal/misconfig/misconfig.go`
- Modify: `internal/misconfig/cwe.go`
- Test: `internal/misconfig/misconfig_test.go`

**Interfaces:**
- Consumes: `isAPKFile`, `decodeAndroidManifest`, `androidManifest` (Task 2); `writeTestAPK`, `baseManifest`, `appElem`, `boolAttr` (Task 2, test-only); `newIssue` (existing, `internal/misconfig/misconfig.go`).
- Produces: `scanAndroidManifest(path string) ([]model.Issue, error)`, `checkAndroidDebuggable(m androidManifest, path string) []model.Issue` — both consumed by Tasks 4-6, which append more checks to `scanAndroidManifest`.

- [ ] **Step 1: Write the failing test**

Add to `internal/misconfig/misconfig_test.go`:

```go
func TestAndroidDebuggable(t *testing.T) {
	dir := t.TempDir()
	activity := elem{Name: "activity", Attrs: []attr{strAttr("name", ".Main")}}
	writeTestAPK(t, dir, baseManifest(appElem([]attr{boolAttr("debuggable", true)}, activity)))

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	has := func(ruleID string) bool {
		for _, i := range issues {
			if i.RuleID == ruleID {
				return true
			}
		}
		return false
	}
	if !has("android-debuggable") {
		t.Errorf("expected android-debuggable, got %+v", issues)
	}
}

func TestAndroidNotDebuggable(t *testing.T) {
	dir := t.TempDir()
	writeTestAPK(t, dir, baseManifest(appElem([]attr{boolAttr("debuggable", false)})))

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range issues {
		if i.RuleID == "android-debuggable" {
			t.Errorf("did not expect android-debuggable, got %+v", issues)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/misconfig/... -run TestAndroidDebuggable -v`
Expected: FAIL — compile error, `scanAndroidManifest`/`checkAndroidDebuggable` don't exist yet and `.apk` isn't wired into `Scan`'s switch.

- [ ] **Step 3: Add the check and wire `Scan`**

In `internal/misconfig/android.go`, replace the placeholder `var _ = model.Issue{}` line at the bottom with:

```go
// scanAndroidManifest decodes path's AndroidManifest.xml and runs every
// android-* misconfig check against it.
func scanAndroidManifest(path string) ([]model.Issue, error) {
	m, err := decodeAndroidManifest(path)
	if err != nil {
		return nil, err
	}
	var issues []model.Issue
	issues = append(issues, checkAndroidDebuggable(m, path)...)
	return issues, nil
}

func checkAndroidDebuggable(m androidManifest, path string) []model.Issue {
	if m.Application.Debuggable == "true" {
		return []model.Issue{newIssue("android-debuggable", "HIGH", path, 1,
			"Application is debuggable",
			`<application android:debuggable="true"> ships in the built APK`)}
	}
	return nil
}
```

In `internal/misconfig/misconfig.go`, add a case to `Scan`'s `switch` (placed after the `isSkillFile(name)` case, alongside it as another name/type-identity check before the extension-based `.yaml`/`.json`/`.tf` cases):

```go
		case isAPKFile(name):
			found, err := scanAndroidManifest(path)
			if err != nil {
				return nil // skip unparsable/non-APK-shaped .apk file, don't fail the whole scan
			}
			issues = append(issues, found...)
```

In `internal/misconfig/cwe.go`, add to the `ruleCWEs` map (CWE-489 is "Active Debug Code" — the CWE that names exactly this issue):

```go
	"android-debuggable": {"CWE-489"},
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/misconfig/... -run TestAndroid -v`
Expected: PASS for both `TestAndroidDebuggable` and `TestAndroidNotDebuggable`.

- [ ] **Step 5: Run the full package test suite**

Run: `go test ./internal/misconfig/...`
Expected: PASS (no regressions in existing Dockerfile/K8s/Terraform/CloudFormation/MCP/Skill tests).

- [ ] **Step 6: Commit**

```bash
git add internal/misconfig/android.go internal/misconfig/misconfig.go internal/misconfig/cwe.go internal/misconfig/misconfig_test.go
git commit -m "Wire .apk files into misconfig.Scan, add android-debuggable check"
```

---

### Task 4: `android-cleartext-traffic` check

**Files:**
- Modify: `internal/misconfig/android.go`
- Modify: `internal/misconfig/cwe.go`
- Test: `internal/misconfig/misconfig_test.go`

**Interfaces:**
- Consumes: `androidManifest`, `newIssue`, `scanAndroidManifest` (Tasks 2-3, extends it).
- Produces: `checkAndroidCleartextTraffic(m androidManifest, path string) []model.Issue`, consumed by nothing later (each check task is independent from here on, all append into `scanAndroidManifest`).

- [ ] **Step 1: Write the failing test**

Add to `internal/misconfig/misconfig_test.go`:

```go
func TestAndroidCleartextTraffic(t *testing.T) {
	dir := t.TempDir()
	writeTestAPK(t, dir, baseManifest(appElem([]attr{boolAttr("usesCleartextTraffic", true)})))

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	has := func(ruleID string) bool {
		for _, i := range issues {
			if i.RuleID == ruleID {
				return true
			}
		}
		return false
	}
	if !has("android-cleartext-traffic") {
		t.Errorf("expected android-cleartext-traffic, got %+v", issues)
	}
}

func TestAndroidCleartextTrafficAbsentDoesNotFire(t *testing.T) {
	dir := t.TempDir()
	writeTestAPK(t, dir, baseManifest(appElem(nil)))

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range issues {
		if i.RuleID == "android-cleartext-traffic" {
			t.Errorf("absent usesCleartextTraffic should not fire, got %+v", issues)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/misconfig/... -run TestAndroidCleartextTraffic -v`
Expected: FAIL — `checkAndroidCleartextTraffic` doesn't exist, `android-cleartext-traffic` never fires.

- [ ] **Step 3: Implement**

In `internal/misconfig/android.go`, add:

```go
func checkAndroidCleartextTraffic(m androidManifest, path string) []model.Issue {
	if m.Application.UsesCleartextTraffic == "true" {
		return []model.Issue{newIssue("android-cleartext-traffic", "MEDIUM", path, 1,
			"Application explicitly allows cleartext network traffic",
			`<application android:usesCleartextTraffic="true">`)}
	}
	return nil
}
```

And in `scanAndroidManifest`, add the call:

```go
	issues = append(issues, checkAndroidCleartextTraffic(m, path)...)
```

In `internal/misconfig/cwe.go`, add (CWE-319 is "Cleartext Transmission of Sensitive Information"):

```go
	"android-cleartext-traffic": {"CWE-319"},
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/misconfig/... -run TestAndroidCleartextTraffic -v`
Expected: PASS for both tests.

- [ ] **Step 5: Commit**

```bash
git add internal/misconfig/android.go internal/misconfig/cwe.go internal/misconfig/misconfig_test.go
git commit -m "Add android-cleartext-traffic check"
```

---

### Task 5: `android-exported-component-no-permission` check

**Files:**
- Modify: `internal/misconfig/android.go`
- Modify: `internal/misconfig/cwe.go`
- Test: `internal/misconfig/misconfig_test.go`

**Interfaces:**
- Consumes: `androidManifest`, `androidComponent`, `newIssue`, `scanAndroidManifest` (Tasks 2-3, extends it).
- Produces: `checkAndroidExportedComponents(m androidManifest, path string) []model.Issue`.

This is the highest-value and most nuanced check: a component (activity/service/receiver/provider) counts as exported either because `android:exported="true"` is explicit, *or* because the `exported` attribute is absent and the component has an `<intent-filter>` (real pre-API-31 platform default behavior). It's guarded if either the component's own `android:permission` or the `<application>`-level fallback `android:permission` is set.

- [ ] **Step 1: Write the failing test**

Add to `internal/misconfig/misconfig_test.go`:

```go
func TestAndroidExportedComponentNoPermission(t *testing.T) {
	cases := []struct {
		name      string
		activity  elem
		appAttrs  []attr
		wantIssue bool
	}{
		{
			name:      "explicit exported, no permission",
			activity:  elem{Name: "activity", Attrs: []attr{strAttr("name", ".A"), boolAttr("exported", true)}},
			wantIssue: true,
		},
		{
			name: "explicit exported, with component permission",
			activity: elem{Name: "activity", Attrs: []attr{
				strAttr("name", ".A"), boolAttr("exported", true), strAttr("permission", "com.example.PERM"),
			}},
			wantIssue: false,
		},
		{
			name: "implicit export via intent-filter, no permission",
			activity: elem{
				Name:     "activity",
				Attrs:    []attr{strAttr("name", ".A")},
				Children: []elem{{Name: "intent-filter"}},
			},
			wantIssue: true,
		},
		{
			name: "exported=false with intent-filter does not fire",
			activity: elem{
				Name:     "activity",
				Attrs:    []attr{strAttr("name", ".A"), boolAttr("exported", false)},
				Children: []elem{{Name: "intent-filter"}},
			},
			wantIssue: false,
		},
		{
			name:      "not exported, no intent-filter",
			activity:  elem{Name: "activity", Attrs: []attr{strAttr("name", ".A")}},
			wantIssue: false,
		},
		{
			name:      "exported, guarded by application-level permission",
			activity:  elem{Name: "activity", Attrs: []attr{strAttr("name", ".A"), boolAttr("exported", true)}},
			appAttrs:  []attr{strAttr("permission", "com.example.APP_PERM")},
			wantIssue: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestAPK(t, dir, baseManifest(appElem(c.appAttrs, c.activity)))

			issues, err := Scan(dir)
			if err != nil {
				t.Fatal(err)
			}
			got := false
			for _, i := range issues {
				if i.RuleID == "android-exported-component-no-permission" {
					got = true
				}
			}
			if got != c.wantIssue {
				t.Errorf("%s: got issue=%v want %v (issues: %+v)", c.name, got, c.wantIssue, issues)
			}
		})
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/misconfig/... -run TestAndroidExportedComponentNoPermission -v`
Expected: FAIL — `checkAndroidExportedComponents` doesn't exist, the rule never fires, so every `wantIssue: true` subtest fails.

- [ ] **Step 3: Implement**

In `internal/misconfig/android.go`, add:

```go
func checkAndroidExportedComponents(m androidManifest, path string) []model.Issue {
	var issues []model.Issue
	kinds := []struct {
		kind string
		list []androidComponent
	}{
		{"activity", m.Application.Activities},
		{"service", m.Application.Services},
		{"receiver", m.Application.Receivers},
		{"provider", m.Application.Providers},
	}
	for _, k := range kinds {
		for _, c := range k.list {
			// A component with no explicit android:exported is exported by
			// default when it has an intent-filter -- real pre-API-31
			// platform behavior, not a guess.
			exported := c.Exported == "true" || (c.Exported == "" && len(c.IntentFilters) > 0)
			if !exported {
				continue
			}
			if c.Permission != "" || m.Application.Permission != "" {
				continue
			}
			issues = append(issues, newIssue("android-exported-component-no-permission", "HIGH", path, 1,
				"Exported component has no permission guard",
				fmt.Sprintf("%s %s is exported with no android:permission at the component or application level", k.kind, c.Name)))
		}
	}
	return issues
}
```

And in `scanAndroidManifest`, add the call:

```go
	issues = append(issues, checkAndroidExportedComponents(m, path)...)
```

In `internal/misconfig/cwe.go`, add (CWE-926 is "Improper Export of Android Application Components" -- the CWE that names this exact issue):

```go
	"android-exported-component-no-permission": {"CWE-926"},
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/misconfig/... -run TestAndroidExportedComponentNoPermission -v`
Expected: PASS for all six subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/misconfig/android.go internal/misconfig/cwe.go internal/misconfig/misconfig_test.go
git commit -m "Add android-exported-component-no-permission check"
```

---

### Task 6: `android-broad-permission` check

**Files:**
- Modify: `internal/misconfig/android.go`
- Modify: `internal/misconfig/cwe.go`
- Test: `internal/misconfig/misconfig_test.go`

**Interfaces:**
- Consumes: `androidManifest`, `androidPermission`, `newIssue`, `scanAndroidManifest` (Tasks 2-3, extends it).
- Produces: `checkAndroidBroadPermissions(m androidManifest, path string) []model.Issue`.

- [ ] **Step 1: Write the failing test**

Add to `internal/misconfig/misconfig_test.go`:

```go
func TestAndroidBroadPermission(t *testing.T) {
	dir := t.TempDir()
	writeTestAPK(t, dir, baseManifest(
		elem{Name: "uses-permission", Attrs: []attr{strAttr("name", "android.permission.QUERY_ALL_PACKAGES")}},
		appElem(nil),
	))

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	has := func(ruleID string) bool {
		for _, i := range issues {
			if i.RuleID == ruleID {
				return true
			}
		}
		return false
	}
	if !has("android-broad-permission") {
		t.Errorf("expected android-broad-permission, got %+v", issues)
	}
}

func TestAndroidNarrowPermissionDoesNotFire(t *testing.T) {
	dir := t.TempDir()
	writeTestAPK(t, dir, baseManifest(
		elem{Name: "uses-permission", Attrs: []attr{strAttr("name", "android.permission.INTERNET")}},
		appElem(nil),
	))

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range issues {
		if i.RuleID == "android-broad-permission" {
			t.Errorf("INTERNET should not be flagged as broad, got %+v", issues)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/misconfig/... -run TestAndroidBroadPermission -v`
Expected: FAIL — `checkAndroidBroadPermissions` doesn't exist, `android-broad-permission` never fires.

- [ ] **Step 3: Implement**

In `internal/misconfig/android.go`, add:

```go
// androidBroadPermissions is a curated, deliberately non-exhaustive list of
// high-risk permissions -- same curated-list precedent as this package's
// mcp-cross-origin-credential vendor table.
var androidBroadPermissions = map[string]bool{
	"android.permission.QUERY_ALL_PACKAGES":         true,
	"android.permission.SYSTEM_ALERT_WINDOW":        true,
	"android.permission.REQUEST_INSTALL_PACKAGES":   true,
	"android.permission.READ_SMS":                   true,
	"android.permission.RECEIVE_SMS":                true,
	"android.permission.BIND_ACCESSIBILITY_SERVICE": true,
	"android.permission.WRITE_SECURE_SETTINGS":      true,
	"android.permission.MANAGE_EXTERNAL_STORAGE":    true,
}

func checkAndroidBroadPermissions(m androidManifest, path string) []model.Issue {
	var issues []model.Issue
	for _, p := range m.UsesPermissions {
		if androidBroadPermissions[p.Name] {
			issues = append(issues, newIssue("android-broad-permission", "MEDIUM", path, 1,
				"Requests a high-risk permission",
				"uses-permission "+p.Name))
		}
	}
	return issues
}
```

And in `scanAndroidManifest`, add the call:

```go
	issues = append(issues, checkAndroidBroadPermissions(m, path)...)
```

In `internal/misconfig/cwe.go`, add (CWE-250 is "Execution with Unnecessary Privileges"):

```go
	"android-broad-permission": {"CWE-250"},
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/misconfig/... -run TestAndroid -v`
Expected: PASS for every `TestAndroid*` test written so far.

- [ ] **Step 5: Run `go vet` and the full test suite**

Run: `go vet ./internal/misconfig/... && go test ./internal/misconfig/...`
Expected: no vet warnings, all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/misconfig/android.go internal/misconfig/cwe.go internal/misconfig/misconfig_test.go
git commit -m "Add android-broad-permission check"
```

---

### Task 7: Real-fixture end-to-end test

**Files:**
- Create: `internal/misconfig/testdata/android/helloworld_AndroidManifest.xml` (binary, 1,904 bytes)
- Test: `internal/misconfig/misconfig_test.go`

**Interfaces:**
- Consumes: `Scan` (existing), all four `android-*` checks (Tasks 3-6).
- Produces: nothing consumed by later tasks — this is the final correctness gate before docs.

This uses a real compiled `AndroidManifest.xml`, not a hand-built fixture, as the last check that the whole zip-extract → AXML-decode → XML-parse → check pipeline works against genuine binary input. It's extracted from `shogo82148/androidbinary`'s own MIT-licensed `apk/testdata/helloworld.apk` test fixture. Verified during planning by actually decoding it: this manifest has `android:debuggable="true"` and one `<activity>` with an `<intent-filter>` and no explicit `exported`/`permission` attribute (implicitly exported, unguarded) — so it genuinely fires both `android-debuggable` and `android-exported-component-no-permission`. It has no `usesCleartextTraffic` attribute and no `<uses-permission>` elements at all, so the other two rules correctly don't fire on it.

- [ ] **Step 1: Fetch and extract the real fixture**

Run:
```bash
curl -sL "https://raw.githubusercontent.com/shogo82148/androidbinary/main/apk/testdata/helloworld.apk" -o /tmp/helloworld.apk
mkdir -p internal/misconfig/testdata/android
unzip -p /tmp/helloworld.apk AndroidManifest.xml > internal/misconfig/testdata/android/helloworld_AndroidManifest.xml
rm /tmp/helloworld.apk
```

Expected: `internal/misconfig/testdata/android/helloworld_AndroidManifest.xml` is exactly 1,904 bytes. Verify with `ls -la internal/misconfig/testdata/android/helloworld_AndroidManifest.xml`.

- [ ] **Step 2: Write the failing test**

Add to `internal/misconfig/misconfig_test.go`:

```go
// TestAndroidRealFixture decodes a real compiled AndroidManifest.xml (not a
// hand-built one) end to end. Source: github.com/shogo82148/androidbinary's
// MIT-licensed apk/testdata/helloworld.apk test fixture, package
// com.example.helloworld. It genuinely has android:debuggable="true" and one
// unguarded, implicitly-exported activity (an intent-filter with no explicit
// exported/permission attribute) -- verified by decoding it during planning,
// not assumed -- so both of those rules should fire; it has no
// usesCleartextTraffic attribute and no uses-permission elements at all, so
// the other two rules should not.
func TestAndroidRealFixture(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "android", "helloworld_AndroidManifest.xml"))
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "helloworld.apk")
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(src); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, i := range issues {
		got[i.RuleID] = true
	}
	for _, want := range []string{"android-debuggable", "android-exported-component-no-permission"} {
		if !got[want] {
			t.Errorf("expected %s to fire on the real fixture, got %+v", want, issues)
		}
	}
	for _, notWant := range []string{"android-cleartext-traffic", "android-broad-permission"} {
		if got[notWant] {
			t.Errorf("did not expect %s to fire on the real fixture, got %+v", notWant, issues)
		}
	}
}
```

Add `"archive/zip"` to `internal/misconfig/misconfig_test.go`'s import block (alongside the existing `"os"`, `"path/filepath"`, `"strings"`, `"testing"`).

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/misconfig/... -run TestAndroidRealFixture -v`
Expected: FAIL if Step 1 wasn't done yet (`no such file or directory`) or if any of the four expectations don't hold. If it fails on a missing testdata file, go back to Step 1.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/misconfig/... -run TestAndroidRealFixture -v`
Expected: PASS.

- [ ] **Step 5: Run the full test suite**

Run: `go test ./...`
Expected: all packages PASS, no regressions anywhere in the repo.

- [ ] **Step 6: Commit**

```bash
git add internal/misconfig/testdata/android/helloworld_AndroidManifest.xml internal/misconfig/misconfig_test.go
git commit -m "Add real-manifest end-to-end test for Android misconfig checks"
```

---

### Task 8: Docs and TODO.md

**Files:**
- Modify: `docs/guide/scanner/misconfiguration.md`
- Modify: `TODO.md`

**Interfaces:**
- Consumes: nothing (documentation only).
- Produces: nothing consumed by later tasks — this is the last task.

- [ ] **Step 1: Update the file-matching table**

In `docs/guide/scanner/misconfiguration.md`, add a row to the "How files are matched" table (after the "Skill definition" row):

```markdown
| Android manifest | `*.apk` containing an `AndroidManifest.xml` entry | [`shogo82148/androidbinary`](https://github.com/shogo82148/androidbinary) decodes the binary XML (AXML) format to plain XML text, then `encoding/xml` |
```

- [ ] **Step 2: Bump the built-in check count and add the new section**

Change the `## Built-in checks (131)` heading to `## Built-in checks (135)`.

After the "Skill definition (4 checks)" section (and its "Hardcoded secrets in `SKILL.md`..." note) and before `## Limitations`, add:

```markdown
**Android manifest (4 checks)**

- `android-debuggable` (HIGH) — `<application android:debuggable="true">` ships in the built APK.
- `android-cleartext-traffic` (MEDIUM) — `<application android:usesCleartextTraffic="true">` explicitly. The platform default has been `false` since API 28, so the attribute's absence isn't flagged — only an explicit `true` is a real signal.
- `android-exported-component-no-permission` (HIGH) — an `activity`/`service`/`receiver`/`provider` that's exported — either `android:exported="true"` explicitly, or implicitly (the attribute is absent *and* the component has an `<intent-filter>`, real pre-API-31 platform default behavior) — with no `android:permission` at either the component or the `<application>` fallback level.
- `android-broad-permission` (MEDIUM) — a `<uses-permission>` naming a curated, non-exhaustive list of high-risk permissions (`QUERY_ALL_PACKAGES`, `SYSTEM_ALERT_WINDOW`, `REQUEST_INSTALL_PACKAGES`, `READ_SMS`, `RECEIVE_SMS`, `BIND_ACCESSIBILITY_SERVICE`, `WRITE_SECURE_SETTINGS`, `MANAGE_EXTERNAL_STORAGE`).
```

- [ ] **Step 3: Add a Limitations note**

At the end of the `## Limitations` section in the same file, add:

```markdown
!!! note "Android manifest checks don't resolve resource references, and don't merge split APKs"
    An attribute expressed as a resource reference (e.g. `android:debuggable="@bool/is_debug"`) rather than a literal isn't resolved, so it won't fire any check — the same "flag the candidate, don't resolve everything" trade-off several SAST rules already make. Android App Bundle's per-ABI/density split `.apk` files aren't merged with the base APK's manifest; each `.apk` found is checked independently using whatever manifest it contains. Native `.so` library fingerprinting, DEX bytecode analysis, and iOS/IPA are separate, not-yet-started items (see `TODO.md`).
```

- [ ] **Step 4: Update `TODO.md`**

In `TODO.md`, find the `### Mobile app binary scanning (APK / IPA)` section. Change its heading to:

```markdown
### Mobile app binary scanning (APK / IPA) — Android manifest/permission analysis ✅ shipped, rest not started
```

At the end of that section (after the existing "**Recommendation:**" paragraph), add:

```markdown

**Update:** Android manifest/permission analysis (recommendation item 1 above) shipped as four checks folded into the existing `misconfig` scanner (`internal/misconfig/android.go`) — `android-debuggable`, `android-cleartext-traffic`, `android-exported-component-no-permission`, `android-broad-permission`. Decodes `AndroidManifest.xml` from a `.apk`'s binary XML (AXML) format via `github.com/shogo82148/androidbinary` (its root decoder only, not its higher-level `apk` subpackage — that one's missing `exported`/`service`/`receiver`/`provider` fields this feature needs, and pulls in `resources.arsc`/icon-image parsing it doesn't). No resource-reference resolution, no split-APK merging. Design: `docs/superpowers/specs/2026-09-18-android-manifest-misconfig-design.md`. Native library fingerprinting, DEX bytecode analysis, and iOS/IPA remain not started, as originally scoped.
```

- [ ] **Step 5: Verify the docs build (if `mkdocs` is available)**

Run: `mkdocs build --strict 2>&1 || echo "mkdocs not installed locally, skip"`
Expected: either a clean build or the skip message — don't block on mkdocs being unavailable locally.

- [ ] **Step 6: Final full-repo verification**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all PASS, no regressions.

- [ ] **Step 7: Commit**

```bash
git add docs/guide/scanner/misconfiguration.md TODO.md
git commit -m "Document Android manifest misconfig checks, mark TODO.md item shipped"
```
