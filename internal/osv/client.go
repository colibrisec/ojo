// Package osv queries the OSV.dev vulnerability database (https://osv.dev)
// for known advisories affecting a set of packages.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/colibrisec/ojo/internal/model"
)

const (
	detailConcurrency = 10 // ponytail: fixed worker count, tune if OSV rate-limits large scans
	// OSV doesn't publish a hard limit on queries per querybatch request, but
	// keeping individual requests to a bounded size avoids ever finding a
	// real one the hard way (a large monorepo can easily have 1000s of
	// resolved npm packages).
	maxBatchSize = 1000
)

// apiBase is a var (not const) so tests can point it at a local httptest server.
var apiBase = "https://api.osv.dev/v1"

var httpClient = &http.Client{}

type batchQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type batchRequest struct {
	Queries []batchQuery `json:"queries"`
}

type batchResultEntry struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
}

type batchResult struct {
	Results []batchResultEntry `json:"results"`
}

// Scan queries OSV for every package and returns one Finding per vulnerable package.
func Scan(ctx context.Context, pkgs []model.Package) ([]model.Finding, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}

	var results []batchResultEntry
	for start := 0; start < len(pkgs); start += maxBatchSize {
		end := min(start+maxBatchSize, len(pkgs))
		chunk := pkgs[start:end]

		req := batchRequest{Queries: make([]batchQuery, len(chunk))}
		for i, p := range chunk {
			req.Queries[i].Package.Name = p.Name
			req.Queries[i].Package.Ecosystem = string(p.Ecosystem)
			req.Queries[i].Version = p.Version
		}

		var result batchResult
		if err := post(ctx, apiBase+"/querybatch", req, &result); err != nil {
			return nil, fmt.Errorf("osv querybatch: %w", err)
		}
		results = append(results, result.Results...)
	}

	// Collect the unique vuln IDs we need full details for.
	idSet := map[string]struct{}{}
	for _, r := range results {
		for _, v := range r.Vulns {
			idSet[v.ID] = struct{}{}
		}
	}
	details := fetchDetails(ctx, idSet)

	var findings []model.Finding
	for i, r := range results {
		if len(r.Vulns) == 0 {
			continue
		}
		f := model.Finding{Package: pkgs[i]}
		for _, v := range r.Vulns {
			if d, ok := details[v.ID]; ok {
				f.Vulns = append(f.Vulns, toVulnerability(d, pkgs[i]))
			}
		}
		f.Vulns = dedupeVulns(f.Vulns)
		findings = append(findings, f)
	}
	return findings, nil
}

type vulnDetail struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"` // short one-liner; populated on GHSA entries
	Details  string   `json:"details"` // longer description; the only text field Debian/Alpine entries populate
	Aliases  []string `json:"aliases"`
	Upstream []string `json:"upstream"` // Debian/Alpine put their CVE ID here instead of aliases
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"` // e.g. CRITICAL/HIGH/MODERATE/LOW, present on GHSA-sourced advisories
	} `json:"database_specific"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func normalizeSeverity(s string) string {
	if s == "MODERATE" {
		return "MEDIUM" // align with the Issue.Severity vocabulary used by secret/misconfig/sast
	}
	return s
}

// preferredID prefers a CVE alias over a source-specific ID (e.g. OSV's
// "DEBIAN-CVE-2005-2541" displays as "CVE-2005-2541"), matching how Trivy
// normalizes Debian/Alpine advisory IDs for display. Debian/Alpine entries
// carry their CVE under "upstream" rather than "aliases".
func preferredID(d vulnDetail) string {
	for _, a := range append(d.Aliases, d.Upstream...) {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return d.ID
}

// summary returns d.Summary, falling back to a truncated d.Details for
// sources like Debian/Alpine that only populate the longer field.
func summary(d vulnDetail) string {
	if d.Summary != "" {
		return d.Summary
	}
	const maxLen = 120
	s := d.Details
	if len(s) > maxLen {
		s = strings.TrimSpace(s[:maxLen]) + "..."
	}
	return s
}

func toVulnerability(d vulnDetail, pkg model.Package) model.Vulnerability {
	v := model.Vulnerability{ID: preferredID(d), Summary: summary(d), Aliases: d.Aliases, Severity: "UNKNOWN"}
	if len(d.Severity) > 0 {
		v.CVSSVector = d.Severity[0].Score
	}
	switch {
	case d.DatabaseSpecific.Severity != "":
		// GHSA-style human-reviewed label; prefer it when present.
		v.Severity = normalizeSeverity(d.DatabaseSpecific.Severity)
	default:
		// Sources like Debian/Alpine only give a CVSS vector; derive
		// a label from it ourselves rather than reporting UNKNOWN.
		if label, ok := cvss3SeverityLabel(v.CVSSVector); ok {
			v.Severity = label
		}
	}
	if len(d.References) > 0 {
		v.URL = d.References[0].URL
	}
	v.FixedVersion = resolveFixedVersion(d, pkg)
	return v
}

func fetchDetails(ctx context.Context, ids map[string]struct{}) map[string]vulnDetail {
	out := make(map[string]vulnDetail, len(ids))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, detailConcurrency)

	for id := range ids {
		id := id
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			var d vulnDetail
			if err := get(ctx, apiBase+"/vulns/"+id, &d); err != nil {
				return // ponytail: drop vulns whose detail lookup fails, don't fail the scan
			}
			mu.Lock()
			out[id] = d
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

func post(ctx context.Context, url string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return do(req, out)
}

func get(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	return do(req, out)
}

func do(req *http.Request, out any) error {
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
