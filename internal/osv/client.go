// Package osv queries the OSV.dev vulnerability database (https://osv.dev)
// for known advisories affecting a set of packages.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/colibrisec/ojo/internal/model"
)

const (
	apiBase           = "https://api.osv.dev/v1"
	detailConcurrency = 10 // ponytail: fixed worker count, tune if OSV rate-limits large scans
)

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

type batchResult struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// Scan queries OSV for every package and returns one Finding per vulnerable package.
func Scan(ctx context.Context, pkgs []model.Package) ([]model.Finding, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}

	req := batchRequest{Queries: make([]batchQuery, len(pkgs))}
	for i, p := range pkgs {
		req.Queries[i].Package.Name = p.Name
		req.Queries[i].Package.Ecosystem = string(p.Ecosystem)
		req.Queries[i].Version = p.Version
	}

	var result batchResult
	if err := post(ctx, apiBase+"/querybatch", req, &result); err != nil {
		return nil, fmt.Errorf("osv querybatch: %w", err)
	}

	// Collect the unique vuln IDs we need full details for.
	idSet := map[string]struct{}{}
	for _, r := range result.Results {
		for _, v := range r.Vulns {
			idSet[v.ID] = struct{}{}
		}
	}
	details := fetchDetails(ctx, idSet)

	var findings []model.Finding
	for i, r := range result.Results {
		if len(r.Vulns) == 0 {
			continue
		}
		f := model.Finding{Package: pkgs[i]}
		for _, v := range r.Vulns {
			if d, ok := details[v.ID]; ok {
				f.Vulns = append(f.Vulns, d)
			}
		}
		f.Vulns = dedupeVulns(f.Vulns)
		findings = append(findings, f)
	}
	return findings, nil
}

type vulnDetail struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
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
}

func normalizeSeverity(s string) string {
	if s == "MODERATE" {
		return "MEDIUM" // align with the Issue.Severity vocabulary used by secret/misconfig/sast
	}
	return s
}

func fetchDetails(ctx context.Context, ids map[string]struct{}) map[string]model.Vulnerability {
	out := make(map[string]model.Vulnerability, len(ids))
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
			v := model.Vulnerability{ID: d.ID, Summary: d.Summary, Aliases: d.Aliases, Severity: "UNKNOWN"}
			if d.DatabaseSpecific.Severity != "" {
				v.Severity = normalizeSeverity(d.DatabaseSpecific.Severity)
			}
			if len(d.Severity) > 0 {
				v.CVSSVector = d.Severity[0].Score
			}
			if len(d.References) > 0 {
				v.URL = d.References[0].URL
			}
			mu.Lock()
			out[id] = v
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
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
