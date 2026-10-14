package sbom

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/report"
)

var samplePkgs = []model.Package{
	{Name: "django", Version: "3.2.0", Ecosystem: model.EcosystemPyPI, License: "BSD-3-Clause"},
	{Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", Ecosystem: model.EcosystemMaven, License: "Apache-2.0"},
	{Name: "libssl3", Version: "3.0.11-1~deb12u2", Origin: "openssl", Ecosystem: "Debian:12", Source: "dpkg", License: "Custom Thing"},
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertSample(t *testing.T, res Result, path, format string) {
	t.Helper()
	if res.Format != format {
		t.Errorf("format = %q, want %q", res.Format, format)
	}
	if len(res.Packages) != len(samplePkgs) || len(res.Skipped) != 0 {
		t.Fatalf("got %+v, skipped %+v", res.Packages, res.Skipped)
	}
	for i, want := range samplePkgs {
		if want.Source == "" {
			want.Source = path
		}
		if got := res.Packages[i]; got != want {
			t.Errorf("package %d = %+v, want %+v", i, got, want)
		}
	}
}

func TestReadsOwnCycloneDX(t *testing.T) {
	var buf bytes.Buffer
	if err := report.SBOM(&buf, samplePkgs, cdx.SpecVersion1_6); err != nil {
		t.Fatal(err)
	}
	path := writeFile(t, "bom.json", buf.Bytes())
	res, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	assertSample(t, res, path, "CycloneDX")
}

func TestReadsOwnSPDX(t *testing.T) {
	var buf bytes.Buffer
	if err := report.SPDX(&buf, samplePkgs, "target", "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	path := writeFile(t, "bom.spdx.json", buf.Bytes())
	res, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	assertSample(t, res, path, "SPDX")
}

func TestReadsCycloneDXXMLAndNestedComponents(t *testing.T) {
	doc := `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
  <components>
    <component type="application"><name>app</name></component>
    <component type="library">
      <name>lodash</name><version>4.17.20</version><purl>pkg:npm/lodash@4.17.20</purl>
      <components>
        <component type="library"><name>minimist</name><version>1.2.5</version><purl>pkg:npm/minimist@1.2.5</purl></component>
      </components>
    </component>
    <component type="library"><name>vendored</name><version>1.0</version></component>
    <component type="library"><name>checkout</name><version>v4</version><purl>pkg:github/actions/checkout@v4</purl></component>
  </components>
</bom>`
	res, err := Read(writeFile(t, "bom.xml", []byte(doc)))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 2 || res.Packages[0].Name != "lodash" || res.Packages[1].Name != "minimist" {
		t.Errorf("got %+v", res.Packages)
	}
	reasons := map[string]string{}
	for _, s := range res.Skipped {
		reasons[s.Name] = s.Reason
	}
	if len(reasons) != 2 || reasons["vendored"] != "no package URL" || reasons["pkg:github/actions/checkout@v4"] != "unsupported package URL" {
		t.Errorf("got skipped %+v", res.Skipped)
	}
}

func TestReadsSyftStyleSPDX(t *testing.T) {
	doc := `{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "packages": [
    {"SPDXID": "SPDXRef-root", "name": "alpine:3.19", "versionInfo": "sha256:abc"},
    {"SPDXID": "SPDXRef-busybox", "name": "busybox", "versionInfo": "1.36.1-r15", "licenseDeclared": "GPL-2.0-only",
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
       "referenceLocator": "pkg:apk/alpine/busybox@1.36.1-r15?arch=x86_64&upstream=busybox&distro=alpine-3.19.1"}]}
  ],
  "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-root"}]
}`
	res, err := Read(writeFile(t, "syft.spdx.json", []byte(doc)))
	if err != nil {
		t.Fatal(err)
	}
	want := model.Package{Name: "busybox", Version: "1.36.1-r15", Ecosystem: "Alpine:v3.19", Source: "apk", License: "GPL-2.0-only"}
	if len(res.Packages) != 1 || res.Packages[0] != want || len(res.Skipped) != 0 {
		t.Errorf("got %+v, skipped %+v", res.Packages, res.Skipped)
	}
}

func TestRejectsUnknownFormats(t *testing.T) {
	for name, doc := range map[string]string{
		"plain.json": `{"hello": "world"}`,
		"spdx3.json": `{"spdxVersion": "SPDX-3.0"}`,
		"text.txt":   `not json`,
	} {
		if _, err := Read(writeFile(t, name, []byte(doc))); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestReadsTrivySourcePackages(t *testing.T) {
	cyclonedx := `{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [
  {"type": "operating-system", "name": "debian", "version": "12.15"},
  {"type": "library", "name": "libc6", "version": "2.36-9+deb12u14",
   "purl": "pkg:deb/debian/libc6@2.36-9%2Bdeb12u14?arch=amd64&distro=debian-12.15",
   "properties": [{"name": "aquasecurity:trivy:SrcName", "value": "glibc"}]}
]}`
	spdx := `{"spdxVersion": "SPDX-2.3", "packages": [
  {"SPDXID": "SPDXRef-root", "name": "debian:12-slim", "primaryPackagePurpose": "CONTAINER",
   "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:oci/debian@sha256%3Aabc"}]},
  {"SPDXID": "SPDXRef-os", "name": "debian", "versionInfo": "12.15", "primaryPackagePurpose": "OPERATING-SYSTEM"},
  {"SPDXID": "SPDXRef-libc6", "name": "libc6", "versionInfo": "2.36-9+deb12u14", "sourceInfo": "built package from: glibc 2.36-9+deb12u14",
   "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:deb/debian/libc6@2.36-9%2Bdeb12u14?arch=amd64&distro=debian-12.15"}]}
], "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-root"}]}`

	want := model.Package{Name: "libc6", Version: "2.36-9+deb12u14", Origin: "glibc", Ecosystem: "Debian:12", Source: "dpkg"}
	for name, doc := range map[string]string{"trivy.cdx.json": cyclonedx, "trivy.spdx.json": spdx} {
		res, err := Read(writeFile(t, name, []byte(doc)))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Packages) != 1 || res.Packages[0] != want || len(res.Skipped) != 0 {
			t.Errorf("%s: got %+v, skipped %+v", name, res.Packages, res.Skipped)
		}
	}
}
