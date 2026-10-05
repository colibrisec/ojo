// Package alas checks Amazon Linux packages against Amazon's own security
// advisories (ALAS, https://alas.aws.amazon.com).
//
// OSV publishes nothing for Amazon Linux, so its packages can't go through
// internal/osv. Amazon ships the advisories with the distribution instead,
// as the updateinfo.xml of each release's core repository -- the same file
// `dnf updateinfo` reads. It is fetched live on every scan, like every other
// lookup in ojo, with no local database.
package alas

import (
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/colibrisec/ojo/internal/model"
)

const ecosystemPrefix = "Amazon Linux:"

// maxFeedSize bounds how much of a decompressed advisory feed is read: far
// above the real ones (~16MB), low enough that a bad response can't exhaust
// memory.
const maxFeedSize = 512 << 20

type release struct {
	// mirrorList names the current snapshot of the core repository. The
	// x86_64 repository's advisories list the aarch64 packages too, so one
	// feed covers both architectures.
	mirrorList string
	site       string // path of the release on alas.aws.amazon.com
}

// releases are the Amazon Linux releases with a live advisory feed, keyed
// by os-release VERSION_ID. Amazon Linux 1 (2018.03) is end of life and
// isn't covered.
var releases = map[string]release{
	"2":    {"https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list", "AL2"},
	"2023": {"https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list", "AL2023"},
}

var httpClient = &http.Client{Timeout: 2 * time.Minute}

// Ecosystem returns the ecosystem for packages of the Amazon Linux release
// with the given os-release VERSION_ID, or false if ojo has no advisories
// for that release.
func Ecosystem(versionID string) (model.Ecosystem, bool) {
	if _, ok := releases[versionID]; !ok {
		return "", false
	}
	return model.Ecosystem(ecosystemPrefix + versionID), true
}

// Covers reports whether p is an Amazon Linux package, checked by Scan
// rather than against OSV.
func Covers(p model.Package) bool {
	return strings.HasPrefix(string(p.Ecosystem), ecosystemPrefix)
}

// Scan returns a finding for every package in pkgs that an advisory fixes
// in a later version than the one installed. Packages Covers doesn't accept
// are ignored. A feed that can't be fetched is an error, never an empty
// result: no findings must mean no known vulnerabilities.
func Scan(ctx context.Context, pkgs []model.Package) ([]model.Finding, error) {
	feeds := map[string]map[string][]fix{}
	var findings []model.Finding
	for _, p := range pkgs {
		if !Covers(p) {
			continue
		}
		versionID := strings.TrimPrefix(string(p.Ecosystem), ecosystemPrefix)
		feed, ok := feeds[versionID]
		if !ok {
			rel, known := releases[versionID]
			if !known {
				return nil, fmt.Errorf("no advisory feed for Amazon Linux %s", versionID)
			}
			var err error
			if feed, err = fetchFeed(ctx, rel); err != nil {
				return nil, fmt.Errorf("fetching Amazon Linux %s advisories: %w", versionID, err)
			}
			feeds[versionID] = feed
		}
		if vulns := match(p, feed[p.Name]); len(vulns) > 0 {
			findings = append(findings, model.Finding{Package: p, Vulns: vulns})
		}
	}
	return findings, nil
}

// fix is one advisory's fixed version of one package.
type fix struct {
	version  evr
	advisory *advisory
}

type advisory struct {
	id, severity, url string
	cves              []string
	summaries         map[string]string // CVE -> its paragraph of the description
	title             string
}

// match returns the vulnerabilities the advisories in fixes report for p:
// one per CVE, with the closest fixed version above the installed one.
func match(p model.Package, fixes []fix) []model.Vulnerability {
	installed := parseEVR(p.Version)
	byID := map[string]model.Vulnerability{}
	fixedIn := map[string]evr{}
	for _, f := range fixes {
		if compareEVR(installed, f.version) >= 0 {
			continue
		}
		a := f.advisory
		ids := a.cves
		if len(ids) == 0 {
			ids = []string{a.id} // a few advisories carry no CVE
		}
		for _, id := range ids {
			if prev, ok := fixedIn[id]; ok && compareEVR(prev, f.version) <= 0 {
				continue
			}
			fixedIn[id] = f.version
			v := model.Vulnerability{
				ID:           id,
				Summary:      a.summaries[id],
				Severity:     a.severity,
				FixedVersion: f.version.String(),
				URL:          a.url,
			}
			if v.Summary == "" {
				v.Summary = a.title
			}
			if id != a.id {
				v.Aliases = []string{a.id}
			}
			byID[id] = v
		}
	}

	vulns := make([]model.Vulnerability, 0, len(byID))
	for _, v := range byID {
		vulns = append(vulns, v)
	}
	sort.Slice(vulns, func(i, j int) bool { return vulns[i].ID < vulns[j].ID })
	return vulns
}

// fetchFeed downloads a release's advisories, indexed by package name.
func fetchFeed(ctx context.Context, rel release) (map[string][]fix, error) {
	list, err := get(ctx, rel.mirrorList)
	if err != nil {
		return nil, err
	}
	mirror, err := io.ReadAll(io.LimitReader(list, 1<<16))
	list.Close()
	if err != nil {
		return nil, err
	}
	base, _, _ := strings.Cut(strings.TrimSpace(string(mirror)), "\n")
	base = strings.TrimSuffix(strings.TrimSpace(base), "/")
	if base == "" {
		return nil, fmt.Errorf("%s lists no mirror", rel.mirrorList)
	}

	href, err := updateinfoLocation(ctx, base+"/repodata/repomd.xml")
	if err != nil {
		return nil, err
	}
	body, err := get(ctx, base+"/"+href)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	var r io.Reader = body
	if strings.HasSuffix(href, ".gz") {
		gz, err := gzip.NewReader(body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", href, err)
		}
		defer gz.Close()
		r = gz
	} else if !strings.HasSuffix(href, ".xml") {
		return nil, fmt.Errorf("%s: unsupported compression", href)
	}
	return parseFeed(io.LimitReader(r, maxFeedSize), rel.site)
}

// updateinfoLocation reads a repository's index for where its advisories
// are; the file name carries a checksum and changes with every update.
func updateinfoLocation(ctx context.Context, repomdURL string) (string, error) {
	body, err := get(ctx, repomdURL)
	if err != nil {
		return "", err
	}
	defer body.Close()
	var repomd struct {
		Data []struct {
			Type     string `xml:"type,attr"`
			Location struct {
				Href string `xml:"href,attr"`
			} `xml:"location"`
		} `xml:"data"`
	}
	if err := xml.NewDecoder(io.LimitReader(body, 1<<20)).Decode(&repomd); err != nil {
		return "", fmt.Errorf("%s: %w", repomdURL, err)
	}
	for _, d := range repomd.Data {
		if d.Type == "updateinfo" && d.Location.Href != "" {
			return d.Location.Href, nil
		}
	}
	return "", fmt.Errorf("%s lists no updateinfo", repomdURL)
}

type xmlUpdate struct {
	Type        string `xml:"type,attr"`
	ID          string `xml:"id"`
	Title       string `xml:"title"`
	Severity    string `xml:"severity"`
	Description string `xml:"description"`
	References  []struct {
		ID   string `xml:"id,attr"`
		Type string `xml:"type,attr"`
	} `xml:"references>reference"`
	Packages []struct {
		Name    string `xml:"name,attr"`
		Version string `xml:"version,attr"`
		Release string `xml:"release,attr"`
		Epoch   string `xml:"epoch,attr"`
	} `xml:"pkglist>collection>package"`
}

func parseFeed(r io.Reader, site string) (map[string][]fix, error) {
	feed := map[string][]fix{}
	dec := xml.NewDecoder(r)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return feed, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parsing advisories: %w", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "update" {
			continue
		}
		var u xmlUpdate
		if err := dec.DecodeElement(&u, &start); err != nil {
			return nil, fmt.Errorf("parsing advisories: %w", err)
		}
		if u.Type != "security" || u.ID == "" {
			continue
		}

		a := &advisory{
			id:        u.ID,
			severity:  severity(u.Severity),
			url:       fmt.Sprintf("https://alas.aws.amazon.com/%s/%s.html", site, u.ID),
			title:     title(u.Title),
			summaries: summaries(u.Description),
		}
		for _, ref := range u.References {
			if ref.Type == "cve" && ref.ID != "" {
				a.cves = append(a.cves, ref.ID)
			}
		}
		// The same package is listed once per architecture, at one version.
		seen := map[string]bool{}
		for _, p := range u.Packages {
			v := evr{epoch: p.Epoch, version: p.Version, release: p.Release}
			if key := p.Name + " " + v.String(); p.Name != "" && !seen[key] {
				seen[key] = true
				feed[p.Name] = append(feed[p.Name], fix{version: v, advisory: a})
			}
		}
	}
}

// severity maps Amazon's advisory priority onto ojo's severity labels.
func severity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "CRITICAL"
	case "important":
		return "HIGH"
	case "medium", "moderate":
		return "MEDIUM"
	case "low":
		return "LOW"
	}
	return "UNKNOWN"
}

// title drops the release and advisory ID an advisory title starts with
// ("Amazon Linux 2023 - ALAS2023-2023-001: Important priority ...").
func title(s string) string {
	if _, rest, ok := strings.Cut(s, ": "); ok {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(s)
}

const maxSummaryLen = 120

// summaries splits an advisory description into its per-CVE paragraphs: a
// line holding "CVE-...:" followed by that CVE's text.
func summaries(description string) map[string]string {
	out := map[string]string{}
	var id string
	for _, line := range strings.Split(description, "\n") {
		line = strings.TrimSpace(line)
		if cve, ok := strings.CutSuffix(line, ":"); ok && strings.HasPrefix(cve, "CVE-") && !strings.Contains(cve, " ") {
			id = cve
			continue
		}
		if id == "" || line == "" {
			id = ""
			continue
		}
		if out[id] == "" {
			if len(line) > maxSummaryLen {
				line = strings.TrimSpace(line[:maxSummaryLen]) + "..."
			}
			out[id] = line
		}
		id = ""
	}
	return out
}

func get(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: unexpected status %d", url, resp.StatusCode)
	}
	return resp.Body, nil
}
