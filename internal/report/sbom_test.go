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
