// Package kev cross-references vulnerability findings against CISA's Known
// Exploited Vulnerabilities catalog. A CVE having a KEV entry means it has
// confirmed real-world exploitation -- a stronger, more concrete signal
// than CVSS severity alone, which only estimates how bad exploitation
// would be, not whether it's actually happening.
package kev

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/colibrisec/ojo/internal/model"
)

var feedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// cacheTTL: KEV entries are added a few times a week at most, not
// continuously -- a day-old cache is never meaningfully stale for this
// data. ponytail: fixed TTL, not configurable; add a flag if a shorter
// window turns out to matter.
const cacheTTL = 24 * time.Hour

var httpClient = &http.Client{Timeout: 30 * time.Second}

type Entry struct {
	DateAdded  string
	Ransomware bool
}

// Set is the KEV catalog keyed by CVE ID for O(1) lookup.
type Set map[string]Entry

type catalogEntry struct {
	CVEID                      string `json:"cveID"`
	DateAdded                  string `json:"dateAdded"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

type catalog struct {
	Vulnerabilities []catalogEntry `json:"vulnerabilities"`
}

// DefaultCachePath returns where Load caches the catalog between runs
// (~/.cache/ojo/kev.json, following XDG on Linux via os.UserCacheDir). ""
// means caching is unavailable on this system -- Load still works, it just
// fetches fresh every call.
func DefaultCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "ojo", "kev.json")
}

// Load returns the KEV catalog, from cachePath if it's younger than
// cacheTTL, otherwise freshly fetched (and, if cachePath != "", cached for
// next time). If the fetch fails, a still-present-but-stale cache is used
// instead of failing outright -- stale > nothing for enrichment data that
// doesn't gate the scan's exit code, and CISA's feed being briefly
// unreachable shouldn't fail an otherwise-successful vulnerability scan.
// stale reports whether the returned catalog came from an expired cache
// after a failed refetch, so the caller can warn about it.
func Load(cachePath string) (set Set, stale bool, err error) {
	if cachePath != "" {
		if data, fresh, ok := readCache(cachePath); ok && fresh {
			return toSet(data), false, nil
		}
	}

	data, fetchErr := fetch()
	if fetchErr == nil {
		if cachePath != "" {
			_ = writeCache(cachePath, data) // ponytail: cache-write failure isn't fatal, just means no caching this run
		}
		return toSet(data), false, nil
	}

	if cachePath != "" {
		if data, _, ok := readCache(cachePath); ok {
			return toSet(data), true, nil
		}
	}
	return nil, false, fmt.Errorf("fetching KEV catalog: %w", fetchErr)
}

func fetch() (catalog, error) {
	resp, err := httpClient.Get(feedURL)
	if err != nil {
		return catalog{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return catalog{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var c catalog
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return catalog{}, err
	}
	return c, nil
}

func readCache(path string) (c catalog, fresh bool, ok bool) {
	info, err := os.Stat(path)
	if err != nil {
		return catalog{}, false, false
	}
	f, err := os.Open(path)
	if err != nil {
		return catalog{}, false, false
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return catalog{}, false, false
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return catalog{}, false, false
	}
	return c, time.Since(info.ModTime()) < cacheTTL, true
}

func writeCache(path string, c catalog) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func toSet(c catalog) Set {
	set := make(Set, len(c.Vulnerabilities))
	for _, e := range c.Vulnerabilities {
		set[e.CVEID] = Entry{DateAdded: e.DateAdded, Ransomware: e.KnownRansomwareCampaignUse == "Known"}
	}
	return set
}

// Annotate sets Vulnerability.KEV/KEVDateAdded on every finding whose ID or
// any alias is in set. Matching by alias too matters because OSV's
// preferred ID for a vulnerability isn't always its CVE ID -- the KEV
// catalog only speaks CVE.
func Annotate(findings []model.Finding, set Set) {
	for i := range findings {
		for j := range findings[i].Vulns {
			v := &findings[i].Vulns[j]
			if e, ok := set[v.ID]; ok {
				v.KEV, v.KEVDateAdded = true, e.DateAdded
				continue
			}
			for _, alias := range v.Aliases {
				if e, ok := set[alias]; ok {
					v.KEV, v.KEVDateAdded = true, e.DateAdded
					break
				}
			}
		}
	}
}
