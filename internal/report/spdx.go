package report

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/colibrisec/ojo/internal/license"
	"github.com/colibrisec/ojo/internal/model"
)

type spdxDocument struct {
	SPDXVersion       string              `json:"spdxVersion"`
	DataLicense       string              `json:"dataLicense"`
	SPDXID            string              `json:"SPDXID"`
	Name              string              `json:"name"`
	DocumentNamespace string              `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo    `json:"creationInfo"`
	Packages          []spdxPackage       `json:"packages"`
	Relationships     []spdxRelationship  `json:"relationships"`
	ExtractedLicenses []spdxExtractedInfo `json:"hasExtractedLicensingInfos,omitempty"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

type spdxExtractedInfo struct {
	LicenseID     string `json:"licenseId"`
	ExtractedText string `json:"extractedText"`
	Name          string `json:"name"`
}

var spdxIDUnsafe = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// SPDX writes pkgs as an SPDX 2.3 JSON document named after target, one
// package per distinct package, as SBOM does.
func SPDX(w io.Writer, pkgs []model.Package, target, toolVersion string, now time.Time) error {
	doc := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              target,
		DocumentNamespace: "https://colibrisec.org/spdxdocs/ojo/" + uuid.NewString(),
		CreationInfo: spdxCreationInfo{
			Created:  now.UTC().Format(time.RFC3339),
			Creators: []string{"Tool: ojo-" + toolVersion},
		},
		Packages:      []spdxPackage{},
		Relationships: []spdxRelationship{},
	}

	seen := map[model.Package]int{}
	extracted := map[string]bool{}
	for _, p := range pkgs {
		key := model.Package{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem}
		if i, ok := seen[key]; ok {
			if doc.Packages[i].LicenseDeclared == "NOASSERTION" {
				doc.Packages[i].LicenseDeclared = spdxLicense(p.License, &doc, extracted)
			}
			continue
		}
		id := fmt.Sprintf("SPDXRef-Package-%d", len(doc.Packages)+1)
		seen[key] = len(doc.Packages)
		doc.Packages = append(doc.Packages, spdxPackage{
			Name:             p.Name,
			SPDXID:           id,
			VersionInfo:      p.Version,
			DownloadLocation: "NOASSERTION",
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  spdxLicense(p.License, &doc, extracted),
			CopyrightText:    "NOASSERTION",
			ExternalRefs: []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  Purl(p),
			}},
		})
		doc.Relationships = append(doc.Relationships, spdxRelationship{
			SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: id,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// spdxLicense returns l as an SPDX license expression; a name SPDX doesn't
// know becomes a LicenseRef with its text recorded in the document.
func spdxLicense(l string, doc *spdxDocument, extracted map[string]bool) string {
	l = strings.TrimSpace(l)
	switch {
	case l == "":
		return "NOASSERTION"
	case license.IsSPDXID(l), license.IsSPDXExpression(l):
		return l
	}
	ref := strings.Trim(spdxIDUnsafe.ReplaceAllString(l, "-"), "-")
	if ref == "" {
		return "NOASSERTION"
	}
	id := "LicenseRef-" + ref
	if !extracted[id] {
		extracted[id] = true
		doc.ExtractedLicenses = append(doc.ExtractedLicenses, spdxExtractedInfo{LicenseID: id, ExtractedText: l, Name: l})
	}
	return id
}
