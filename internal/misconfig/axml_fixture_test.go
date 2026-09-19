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

// maliciousHugeStringCountAXML returns 36 bytes shaped like a minimal valid
// AXML file's outer chunk header + string pool header, except StringCount
// declares an impossible value for a 36-byte file -- the exact shape that
// crashes androidbinary.NewXMLFile with an unrecoverable OOM if handed to it
// directly. Used to prove sanityCheckAXML rejects it before that call.
func maliciousHugeStringCountAXML() []byte {
	buf := make([]byte, 36)
	binary.LittleEndian.PutUint16(buf[0:2], resXMLChunkType)          // outer chunk Type
	binary.LittleEndian.PutUint16(buf[2:4], 8)                        // outer HeaderSize
	binary.LittleEndian.PutUint32(buf[4:8], 36)                       // outer Size
	binary.LittleEndian.PutUint16(buf[8:10], resStringPoolChunkType)  // string pool Type
	binary.LittleEndian.PutUint16(buf[10:12], 28)                     // string pool HeaderSize
	binary.LittleEndian.PutUint32(buf[12:16], 28)                     // string pool Size
	binary.LittleEndian.PutUint32(buf[16:20], 0xF0000000)             // StringCount: impossible
	binary.LittleEndian.PutUint32(buf[20:24], 0)                      // StyleCount
	binary.LittleEndian.PutUint32(buf[24:28], utf8Flag)               // Flags
	binary.LittleEndian.PutUint32(buf[28:32], 28)                     // StringStart
	binary.LittleEndian.PutUint32(buf[32:36], 0)                      // StylesStart
	return buf
}

// writeRawTestAPK packs raw bytes directly as a zip entry named
// AndroidManifest.xml, bypassing the axmlBuilder entirely -- for fixtures
// that are deliberately not well-formed AXML.
func writeRawTestAPK(t *testing.T, dir string, raw []byte) string {
	t.Helper()
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
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
