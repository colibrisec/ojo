// Package license fills in package licenses for SBOM output.
//
// Lockfiles mostly don't record licenses, so for the ecosystems it covers
// this asks deps.dev (Google's Open Source Insights, the same operator as
// OSV.dev) -- live, like every other lookup in ojo, with no local database.
package license

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/colibrisec/ojo/internal/model"
)

// maxBatchSize is deps.dev's documented limit for one versionbatch request.
const maxBatchSize = 5000

var apiBase = "https://api.deps.dev/v3alpha"

var httpClient = &http.Client{Timeout: 60 * time.Second}

// systems maps an ecosystem to deps.dev's name for it. Ecosystems missing
// here (Packagist, Pub, SwiftURL, OS packages) aren't covered by deps.dev.
var systems = map[model.Ecosystem]string{
	model.EcosystemGo:       "GO",
	model.EcosystemNpm:      "NPM",
	model.EcosystemPyPI:     "PYPI",
	model.EcosystemMaven:    "MAVEN",
	model.EcosystemNuGet:    "NUGET",
	model.EcosystemCratesIO: "CARGO",
	model.EcosystemRubyGems: "RUBYGEMS",
}

type versionKey struct {
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type batchRequest struct {
	Requests  []versionRequest `json:"requests"`
	PageToken string           `json:"pageToken,omitempty"`
}

type versionRequest struct {
	VersionKey versionKey `json:"versionKey"`
}

type batchResponse struct {
	Responses     []versionResponse `json:"responses"`
	NextPageToken string            `json:"nextPageToken"`
}

type versionResponse struct {
	// Request echoes the key as it was sent; deps.dev's own spelling of
	// the name in its answer is normalized and can differ.
	Request versionRequest `json:"request"`
	Version *versionInfo   `json:"version"` // nil: unknown package version
}

type versionInfo struct {
	Licenses []string `json:"licenses"`
}

// Lookup returns pkgs with License filled in wherever it was empty and
// deps.dev knows the package version. A package that already has a license
// (read from a lockfile or an image) is left alone, and so is one deps.dev
// doesn't cover or doesn't know. On error the packages are returned as far
// as they were filled in, so a caller can still emit an SBOM.
func Lookup(ctx context.Context, pkgs []model.Package) ([]model.Package, error) {
	out := make([]model.Package, len(pkgs))
	copy(out, pkgs)

	var keys []versionKey
	seen := map[versionKey]bool{}
	for _, p := range out {
		if key, ok := keyFor(p); ok && !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}

	found := map[versionKey]string{}
	var firstErr error
	for start := 0; start < len(keys); start += maxBatchSize {
		end := min(start+maxBatchSize, len(keys))
		if err := lookupBatch(ctx, keys[start:end], found); err != nil {
			firstErr = fmt.Errorf("deps.dev versionbatch: %w", err)
			break
		}
	}

	for i, p := range out {
		if key, ok := keyFor(p); ok {
			out[i].License = found[key]
		}
	}
	return out, firstErr
}

// keyFor returns the deps.dev key to look p up under, or false if p already
// has a license or deps.dev doesn't cover its ecosystem.
func keyFor(p model.Package) (versionKey, bool) {
	system, ok := systems[p.Ecosystem]
	if !ok || p.License != "" || p.Name == "" || p.Version == "" {
		return versionKey{}, false
	}
	return versionKey{System: system, Name: p.Name, Version: p.Version}, true
}

func lookupBatch(ctx context.Context, keys []versionKey, found map[versionKey]string) error {
	body := batchRequest{Requests: make([]versionRequest, len(keys))}
	for i, k := range keys {
		body.Requests[i].VersionKey = k
	}
	for {
		var resp batchResponse
		if err := post(ctx, apiBase+"/versionbatch", body, &resp); err != nil {
			return err
		}
		for _, r := range resp.Responses {
			if r.Version == nil {
				continue
			}
			if l := join(r.Version.Licenses); l != "" {
				found[r.Request.VersionKey] = l
			}
		}
		if resp.NextPageToken == "" {
			return nil
		}
		body.PageToken = resp.NextPageToken
	}
}

// join combines deps.dev's license list into one SPDX expression. Entries
// deps.dev couldn't map to SPDX come back as "non-standard" and are dropped
// rather than reported as if they were a license name.
func join(licenses []string) string {
	var parts []string
	for _, l := range licenses {
		if l == "" || l == "non-standard" {
			continue
		}
		if len(licenses) > 1 && strings.ContainsAny(l, " ") {
			l = "(" + l + ")"
		}
		parts = append(parts, l)
	}
	return strings.Join(parts, " AND ")
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
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
