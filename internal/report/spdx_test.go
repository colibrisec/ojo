package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/colibrisec/ojo/internal/model"
)

func TestSPDX(t *testing.T) {
	pkgs := []model.Package{
		{Name: "django", Version: "3.2.0", Ecosystem: model.EcosystemPyPI, Source: "a/requirements.txt"},
		{Name: "django", Version: "3.2.0", Ecosystem: model.EcosystemPyPI, Source: "b/requirements.txt", License: "BSD-3-Clause"},
		{Name: "bash", Version: "5.2", Ecosystem: "Debian:12", Source: "dpkg", License: "GPLv3+"},
		{Name: "lodash", Version: "4.17.21", Ecosystem: model.EcosystemNpm, License: "MIT OR Apache-2.0"},
	}
	var buf bytes.Buffer
	if err := SPDX(&buf, pkgs, "my-target", "1.2.3", time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}

	if doc.SPDXVersion != "SPDX-2.3" || doc.DataLicense != "CC0-1.0" || doc.Name != "my-target" ||
		doc.CreationInfo.Created != "2026-10-14T12:00:00Z" || doc.CreationInfo.Creators[0] != "Tool: ojo-1.2.3" ||
		!strings.HasPrefix(doc.DocumentNamespace, "https://colibrisec.org/spdxdocs/ojo/") {
		t.Errorf("unexpected document header: %+v", doc)
	}
	if len(doc.Packages) != 3 || len(doc.Relationships) != 3 {
		t.Fatalf("expected django once plus bash and lodash, got %+v", doc.Packages)
	}
	licenses := map[string]string{}
	purls := map[string]string{}
	for _, p := range doc.Packages {
		licenses[p.Name] = p.LicenseDeclared
		purls[p.Name] = p.ExternalRefs[0].ReferenceLocator
	}
	if licenses["django"] != "BSD-3-Clause" || licenses["lodash"] != "MIT OR Apache-2.0" || licenses["bash"] != "LicenseRef-GPLv3" {
		t.Errorf("got licenses %v", licenses)
	}
	if len(doc.ExtractedLicenses) != 1 || doc.ExtractedLicenses[0].LicenseID != "LicenseRef-GPLv3" || doc.ExtractedLicenses[0].Name != "GPLv3+" {
		t.Errorf("got extracted licenses %+v", doc.ExtractedLicenses)
	}
	if purls["bash"] != "pkg:deb/debian/bash@5.2?distro=debian-12" {
		t.Errorf("got purl %q", purls["bash"])
	}
	for _, rel := range doc.Relationships {
		if rel.SPDXElementID != "SPDXRef-DOCUMENT" || rel.RelationshipType != "DESCRIBES" {
			t.Errorf("unexpected relationship %+v", rel)
		}
	}
}
