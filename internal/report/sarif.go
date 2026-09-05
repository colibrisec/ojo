package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"github.com/colibrisec/ojo/internal/model"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      sarifMessage       `json:"message"`
	Locations    []sarifLocation    `json:"locations"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
	Properties   map[string]any     `json:"properties,omitempty"`
}

// kevProperties is the SARIF result.properties bag for a --kev-annotated
// finding -- CISA's confirmed-exploited signal, surfaced without changing
// Level (severity mapping stays CVSS-based; KEV is additive context, not a
// severity override).
func kevProperties(kevFlag bool, dateAdded string) map[string]any {
	if !kevFlag {
		return nil
	}
	return map[string]any{"kev": true, "kevDateAdded": dateAdded}
}

// sarifIssueRule builds the rules-table entry for a sast/misconfig/secret
// finding, pointing HelpURI at the primary (first) CWE when one is known.
func sarifIssueRule(iss model.Issue) sarifRule {
	rule := sarifRule{ID: iss.RuleID, ShortDescription: sarifMessage{Text: iss.Title}}
	if len(iss.CWEs) > 0 {
		rule.HelpURI = model.CWEURL(iss.CWEs[0])
	}
	return rule
}

// cweProperties surfaces every applicable CWE on the result itself (not
// just the rule) so a finding with more than one CWE doesn't lose the rest
// to the rule table's single HelpURI.
func cweProperties(cwes []string) map[string]any {
	if len(cwes) == 0 {
		return nil
	}
	return map[string]any{"cwe": cwes}
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func (r Report) SARIF(w io.Writer, root string) error {
	rules := map[string]sarifRule{}
	results := []sarifResult{}

	for _, f := range r.Findings {
		for _, v := range f.Vulns {
			if _, ok := rules[v.ID]; !ok {
				rules[v.ID] = sarifRule{ID: v.ID, ShortDescription: sarifMessage{Text: v.Summary}, HelpURI: v.URL}
			}
			results = append(results, sarifResult{
				RuleID:  v.ID,
				Level:   sarifLevel(v.Severity),
				Message: sarifMessage{Text: fmt.Sprintf("%s@%s: %s", f.Package.Name, f.Package.Version, v.Summary)},
				Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: sarifPath(root, f.Package.Source)},
				}}},
				Properties: kevProperties(v.KEV, v.KEVDateAdded),
			})
		}
	}

	for _, iss := range r.Issues {
		if _, ok := rules[iss.RuleID]; !ok {
			rules[iss.RuleID] = sarifIssueRule(iss)
		}
		var region *sarifRegion
		if iss.Line > 0 {
			region = &sarifRegion{StartLine: iss.Line}
		}
		results = append(results, sarifResult{
			RuleID:     iss.RuleID,
			Level:      sarifLevel(iss.Severity),
			Message:    sarifMessage{Text: iss.Message},
			Properties: cweProperties(iss.CWEs),
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: sarifPath(root, iss.File)},
				Region:           region,
			}}},
		})
	}

	for _, sf := range r.SuppressedFindings {
		v := sf.Vuln
		if _, ok := rules[v.ID]; !ok {
			rules[v.ID] = sarifRule{ID: v.ID, ShortDescription: sarifMessage{Text: v.Summary}, HelpURI: v.URL}
		}
		results = append(results, sarifResult{
			RuleID:  v.ID,
			Level:   sarifLevel(v.Severity),
			Message: sarifMessage{Text: fmt.Sprintf("%s@%s: %s", sf.Package.Name, sf.Package.Version, v.Summary)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: sarifPath(root, sf.Package.Source)},
			}}},
			Suppressions: []sarifSuppression{{Kind: "external", Justification: sf.Reason}},
			Properties:   kevProperties(v.KEV, v.KEVDateAdded),
		})
	}

	for _, si := range r.SuppressedIssues {
		iss := si.Issue
		if _, ok := rules[iss.RuleID]; !ok {
			rules[iss.RuleID] = sarifIssueRule(iss)
		}
		var region *sarifRegion
		if iss.Line > 0 {
			region = &sarifRegion{StartLine: iss.Line}
		}
		results = append(results, sarifResult{
			RuleID:     iss.RuleID,
			Level:      sarifLevel(iss.Severity),
			Message:    sarifMessage{Text: iss.Message},
			Properties: cweProperties(iss.CWEs),
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: sarifPath(root, iss.File)},
				Region:           region,
			}}},
			Suppressions: []sarifSuppression{{Kind: "external", Justification: si.Reason}},
		})
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "ojo",
				InformationURI: "https://colibrisec.dev/docs",
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifLevel(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM", "MODERATE":
		return "warning"
	case "LOW", "INFO":
		return "note"
	default:
		return "warning"
	}
}

func sarifPath(root, path string) string {
	return filepath.ToSlash(relPath(root, path))
}
