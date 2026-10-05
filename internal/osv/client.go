package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/colibrisec/ojo/internal/model"
)

const (
	detailConcurrency = 10
	maxBatchSize      = 1000
)

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

// target is one (name, ecosystem) pair to ask OSV about. Most packages have
// exactly one; see queryTargets for the ones that don't.
type target struct {
	name, ecosystem string
}

// rhelRepos are the OSV ecosystem suffixes a RHEL major version's advisories
// are filed under. An installed rpm doesn't record which repository it came
// from, so each package is checked against all of them.
var rhelRepos = map[string][]string{
	"7": {"::server"},
	"8": {"::baseos", "::appstream"},
	"9": {"::baseos", "::appstream"},
}

const rhelEcosystemPrefix = "Red Hat:enterprise_linux:"

// queryTargets returns what to query OSV for to cover p.
func queryTargets(p model.Package) []target {
	eco := string(p.Ecosystem)
	switch {
	case p.Ecosystem == model.EcosystemCocoaPods:
		// OSV has no CocoaPods ecosystem; Swift advisories are filed against
		// the git repository, which internal/cocoapods resolves into Origin.
		if p.Origin == "" {
			return nil
		}
		return []target{{p.Origin, string(model.EcosystemSwiftURL)}}
	case strings.HasPrefix(eco, rhelEcosystemPrefix):
		if repos, ok := rhelRepos[strings.TrimPrefix(eco, rhelEcosystemPrefix)]; ok {
			targets := make([]target, len(repos))
			for i, repo := range repos {
				targets[i] = target{p.QueryName(), eco + repo}
			}
			return targets
		}
	}
	return []target{{p.QueryName(), eco}}
}

func Scan(ctx context.Context, pkgs []model.Package) ([]model.Finding, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}

	// A package found in several files is asked about once; every copy
	// gets the answer.
	var queries []batchQuery
	var owners [][]int // queries[i] was asked on behalf of each pkgs[owners[i][...]]
	asked := map[batchQuery]int{}
	for i, p := range pkgs {
		for _, t := range queryTargets(p) {
			var q batchQuery
			q.Package.Name = t.name
			q.Package.Ecosystem = t.ecosystem
			q.Version = p.Version
			qi, ok := asked[q]
			if !ok {
				qi = len(queries)
				asked[q] = qi
				queries = append(queries, q)
				owners = append(owners, nil)
			}
			owners[qi] = append(owners[qi], i)
		}
	}

	vulnIDs := make([][]string, len(pkgs))
	for start := 0; start < len(queries); start += maxBatchSize {
		end := min(start+maxBatchSize, len(queries))

		var result batchResult
		if err := post(ctx, apiBase+"/querybatch", batchRequest{Queries: queries[start:end]}, &result); err != nil {
			return nil, fmt.Errorf("osv querybatch: %w", err)
		}
		for i, r := range result.Results {
			if start+i >= len(owners) {
				break
			}
			for _, pkg := range owners[start+i] {
				for _, v := range r.Vulns {
					if !slices.Contains(vulnIDs[pkg], v.ID) {
						vulnIDs[pkg] = append(vulnIDs[pkg], v.ID)
					}
				}
			}
		}
	}

	idSet := map[string]struct{}{}
	for _, ids := range vulnIDs {
		for _, id := range ids {
			idSet[id] = struct{}{}
		}
	}
	details := fetchDetails(ctx, idSet)

	var findings []model.Finding
	for i, ids := range vulnIDs {
		if len(ids) == 0 {
			continue
		}
		f := model.Finding{Package: pkgs[i]}
		for _, id := range ids {
			if d, ok := details[id]; ok {
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
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Upstream []string `json:"upstream"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
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
		return "MEDIUM"
	}
	return s
}

func preferredID(d vulnDetail) string {
	for _, a := range append(d.Aliases, d.Upstream...) {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return d.ID
}

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
				return
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
