// Package cocoapods resolves pods from a Podfile.lock to the things the
// lockfile doesn't record: the git repository a pod is built from and its
// declared license.
//
// OSV has no CocoaPods ecosystem. Advisories for Swift/Objective-C libraries
// are filed under SwiftURL, keyed by repository ("github.com/owner/repo"),
// so matching a pod against them needs the repository its podspec points
// at. That comes from the public CocoaPods spec CDN, one small JSON file per
// pod version.
package cocoapods

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/colibrisec/ojo/internal/model"
)

const concurrency = 10

var cdnBase = "https://cdn.cocoapods.org/Specs"

var httpClient = &http.Client{Timeout: 30 * time.Second}

type podspec struct {
	License any `json:"license"` // "MIT", or {"type": "MIT", "file": "LICENSE"}
	Source  struct {
		Git string `json:"git"`
	} `json:"source"`
}

// Resolve returns pkgs with Origin (the pod's repository, in OSV's SwiftURL
// form) and License filled in for every CocoaPods package whose podspec
// could be fetched. Other packages pass through untouched. unresolved counts
// the pods left without a repository -- private pods, pods distributed as a
// plain archive, or a CDN that couldn't be reached -- which therefore can't
// be checked for vulnerabilities.
func Resolve(ctx context.Context, pkgs []model.Package) (out []model.Package, unresolved int) {
	out = make([]model.Package, len(pkgs))
	copy(out, pkgs)

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	for i := range out {
		if out[i].Ecosystem != model.EcosystemCocoaPods {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p *model.Package) {
			defer wg.Done()
			defer func() { <-sem }()

			spec, err := fetch(ctx, p.Name, p.Version)
			if err == nil {
				p.Origin = repository(spec.Source.Git)
				if p.License == "" {
					p.License = licenseName(spec.License)
				}
			}
			if p.Origin == "" {
				mu.Lock()
				unresolved++
				mu.Unlock()
			}
		}(&out[i])
	}
	wg.Wait()
	return out, unresolved
}

// specURL is where the CDN serves a pod version's spec: sharded by the
// first three hex digits of the pod name's MD5.
func specURL(name, version string) string {
	sum := md5.Sum([]byte(name))
	h := hex.EncodeToString(sum[:])
	return fmt.Sprintf("%s/%c/%c/%c/%s/%s/%s.podspec.json",
		cdnBase, h[0], h[1], h[2], url.PathEscape(name), url.PathEscape(version), url.PathEscape(name))
}

func fetch(ctx context.Context, name, version string) (podspec, error) {
	var spec podspec
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, specURL(name, version), nil)
	if err != nil {
		return spec, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return spec, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return spec, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(&spec)
	return spec, err
}

// repository normalizes a podspec's git URL the way Package.resolved
// locations are (internal/manifest): scheme and ".git" stripped.
func repository(git string) string {
	git = strings.TrimSpace(git)
	if rest, ok := strings.CutPrefix(git, "git@"); ok {
		git = strings.Replace(rest, ":", "/", 1) // scp-style git@host:owner/repo
	}
	for _, prefix := range []string{"https://", "http://", "ssh://git@", "ssh://", "git://"} {
		git = strings.TrimPrefix(git, prefix)
	}
	return strings.TrimSuffix(strings.TrimSuffix(git, "/"), ".git")
}

func licenseName(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case map[string]any:
		if t, ok := v["type"].(string); ok {
			return t
		}
	}
	return ""
}
