// Package sbom reads the packages listed in a CycloneDX or SPDX SBOM.
package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/colibrisec/ojo/internal/manifest"
	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/purl"
)

// Result holds the packages read from an SBOM, and the entries that
// couldn't be mapped to a package ojo can check.
type Result struct {
	Format   string
	Packages []model.Package
	Skipped  []manifest.Unscannable
}

// Read parses a CycloneDX (JSON or XML) or SPDX 2.x JSON document.
func Read(path string) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, err
	}
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("<")) {
		return readCycloneDX(path, data, cdx.BOMFileFormatXML)
	}

	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return Result{}, fmt.Errorf("%s: not a CycloneDX or SPDX JSON document: %w", path, err)
	}
	switch {
	case probe.BOMFormat == "CycloneDX":
		return readCycloneDX(path, data, cdx.BOMFileFormatJSON)
	case strings.HasPrefix(probe.SPDXVersion, "SPDX-2."):
		return readSPDX(path, trimmed)
	case probe.SPDXVersion != "":
		return Result{}, fmt.Errorf("%s: unsupported SPDX version %q (supported: SPDX 2.x JSON)", path, probe.SPDXVersion)
	}
	return Result{}, errors.New(path + ": unrecognised SBOM format (supported: CycloneDX JSON or XML, SPDX 2.x JSON)")
}

func (r *Result) add(path, name, version, ref, license, origin string) {
	if ref == "" {
		if version != "" {
			r.Skipped = append(r.Skipped, manifest.Unscannable{Name: name, Source: path, Reason: "no package URL"})
		}
		return
	}
	p, ok := purl.ToPackage(ref)
	if !ok {
		r.Skipped = append(r.Skipped, manifest.Unscannable{Name: ref, Source: path, Reason: "unsupported package URL"})
		return
	}
	if p.Source == "" {
		p.Source = path
	} else if p.Origin == "" && origin != p.Name {
		p.Origin = origin
	}
	p.License = license
	r.Packages = append(r.Packages, p)
}

func readCycloneDX(path string, data []byte, format cdx.BOMFileFormat) (Result, error) {
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), format).Decode(&bom); err != nil {
		return Result{}, fmt.Errorf("%s: parsing CycloneDX: %w", path, err)
	}
	r := Result{Format: "CycloneDX"}
	var walk func([]cdx.Component)
	walk = func(components []cdx.Component) {
		for _, c := range components {
			if c.PackageURL != "" || c.Type == cdx.ComponentTypeLibrary || c.Type == cdx.ComponentTypeFramework {
				r.add(path, c.Name, c.Version, c.PackageURL, cycloneDXLicense(c.Licenses), cycloneDXSource(c.Properties))
			}
			if c.Components != nil {
				walk(*c.Components)
			}
		}
	}
	if bom.Components != nil {
		walk(*bom.Components)
	}
	return r, nil
}

func cycloneDXSource(props *[]cdx.Property) string {
	if props == nil {
		return ""
	}
	for _, p := range *props {
		if p.Name == "aquasecurity:trivy:SrcName" {
			return p.Value
		}
	}
	return ""
}

func cycloneDXLicense(ls *cdx.Licenses) string {
	if ls == nil {
		return ""
	}
	var parts []string
	for _, l := range *ls {
		switch {
		case l.Expression != "":
			parts = append(parts, l.Expression)
		case l.License != nil && l.License.ID != "":
			parts = append(parts, l.License.ID)
		case l.License != nil && l.License.Name != "":
			parts = append(parts, l.License.Name)
		}
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return strings.Join(parts, " OR ")
}

type spdxDoc struct {
	Packages []struct {
		SPDXID           string `json:"SPDXID"`
		Name             string `json:"name"`
		VersionInfo      string `json:"versionInfo"`
		LicenseDeclared  string `json:"licenseDeclared"`
		LicenseConcluded string `json:"licenseConcluded"`
		SourceInfo       string `json:"sourceInfo"`
		Purpose          string `json:"primaryPackagePurpose"`
		ExternalRefs     []struct {
			ReferenceType    string `json:"referenceType"`
			ReferenceLocator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
	ExtractedLicenses []struct {
		LicenseID string `json:"licenseId"`
		Name      string `json:"name"`
	} `json:"hasExtractedLicensingInfos"`
	Relationships []struct {
		SPDXElementID      string `json:"spdxElementId"`
		RelationshipType   string `json:"relationshipType"`
		RelatedSPDXElement string `json:"relatedSpdxElement"`
	} `json:"relationships"`
}

func readSPDX(path string, data []byte) (Result, error) {
	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return Result{}, fmt.Errorf("%s: parsing SPDX: %w", path, err)
	}
	described := map[string]bool{}
	for _, rel := range doc.Relationships {
		if rel.SPDXElementID == "SPDXRef-DOCUMENT" && rel.RelationshipType == "DESCRIBES" {
			described[rel.RelatedSPDXElement] = true
		}
	}

	refs := map[string]string{}
	for _, l := range doc.ExtractedLicenses {
		refs[l.LicenseID] = l.Name
	}

	r := Result{Format: "SPDX"}
	for _, p := range doc.Packages {
		var ref string
		for _, er := range p.ExternalRefs {
			if er.ReferenceType == "purl" {
				ref = er.ReferenceLocator
				break
			}
		}
		if p.Purpose == "OPERATING-SYSTEM" || p.Purpose == "CONTAINER" {
			continue
		}
		if _, ok := purl.ToPackage(ref); !ok && described[p.SPDXID] {
			continue
		}
		r.add(path, p.Name, p.VersionInfo, ref, spdxLicense(refs, p.LicenseDeclared, p.LicenseConcluded), spdxSource(p.SourceInfo))
	}
	return r, nil
}

func spdxSource(info string) string {
	rest, ok := strings.CutPrefix(info, "built package from: ")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(rest, " ")
	return name
}

func spdxLicense(refs map[string]string, declared, concluded string) string {
	for _, l := range []string{declared, concluded} {
		if name, ok := refs[l]; ok && name != "" {
			return name
		}
		if l != "" && l != "NOASSERTION" && l != "NONE" && !strings.HasPrefix(l, "LicenseRef-") {
			return l
		}
	}
	return ""
}
