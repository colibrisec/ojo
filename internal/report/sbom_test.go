package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

func TestParseCycloneDXVersion(t *testing.T) {
	if v, err := ParseCycloneDXVersion(""); err != nil || v.String() != "1.7" {
		t.Errorf("expected \"\" to mean latest (1.7), got %v, err=%v", v, err)
	}
	if v, err := ParseCycloneDXVersion("1.4"); err != nil || v.String() != "1.4" {
		t.Errorf("expected 1.4, got %v, err=%v", v, err)
	}
	if _, err := ParseCycloneDXVersion("1.1"); err == nil {
		t.Error("expected an error for a pre-1.2 version, ojo only writes JSON")
	}
	if _, err := ParseCycloneDXVersion("nope"); err == nil {
		t.Error("expected an error for an unrecognized version")
	}
}

func TestSBOMRespectsSpecVersion(t *testing.T) {
	pkgs := []model.Package{{Name: "foo", Version: "1.0", Ecosystem: model.EcosystemNpm}}

	version, err := ParseCycloneDXVersion("1.4")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := SBOM(&buf, pkgs, version); err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["specVersion"] != "1.4" {
		t.Errorf("expected specVersion 1.4 in output, got %v", doc["specVersion"])
	}
}

func TestSBOMLicenses(t *testing.T) {
	pkgs := []model.Package{
		{Name: "spdx-id", Version: "1.0", Ecosystem: model.EcosystemNpm, License: "MIT"},
		{Name: "expression", Version: "1.0", Ecosystem: model.EcosystemCratesIO, License: "MIT OR Apache-2.0"},
		{Name: "distro-name", Version: "1.0", Ecosystem: "Rocky Linux:9", License: "GPLv2+ and LGPLv2+"},
		{Name: "unknown", Version: "1.0", Ecosystem: model.EcosystemNpm},
		{Name: "Alamofire", Version: "5.9.1", Ecosystem: model.EcosystemCocoaPods, License: "MIT"},
	}
	version, _ := ParseCycloneDXVersion("")
	var buf bytes.Buffer
	if err := SBOM(&buf, pkgs, version); err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Components []struct {
			Name     string `json:"name"`
			Purl     string `json:"purl"`
			Licenses []struct {
				Expression string `json:"expression"`
				License    *struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
			} `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != len(pkgs) {
		t.Fatalf("got %d components, want %d", len(doc.Components), len(pkgs))
	}

	c := doc.Components
	// A recognized SPDX ID is the only thing written as "id": the CycloneDX
	// schema rejects any other value there.
	if len(c[0].Licenses) != 1 || c[0].Licenses[0].License == nil || c[0].Licenses[0].License.ID != "MIT" {
		t.Errorf("spdx-id: %+v", c[0].Licenses)
	}
	if len(c[1].Licenses) != 1 || c[1].Licenses[0].Expression != "MIT OR Apache-2.0" {
		t.Errorf("expression: %+v", c[1].Licenses)
	}
	if len(c[2].Licenses) != 1 || c[2].Licenses[0].License == nil || c[2].Licenses[0].License.Name != "GPLv2+ and LGPLv2+" || c[2].Licenses[0].License.ID != "" {
		t.Errorf("distro-name: %+v", c[2].Licenses)
	}
	if len(c[3].Licenses) != 0 {
		t.Errorf("unknown: expected no licenses entry, got %+v", c[3].Licenses)
	}
	if c[4].Purl != "pkg:cocoapods/Alamofire@5.9.1" {
		t.Errorf("purl = %q", c[4].Purl)
	}
}
