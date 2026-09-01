package kev

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/colibrisec/ojo/internal/model"
)

const sampleCatalog = `{"vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10","knownRansomwareCampaignUse":"Known"}]}`

func withFeedServer(t *testing.T, body string, status int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	old := feedURL
	feedURL = srv.URL
	t.Cleanup(func() { feedURL = old })
}

func TestLoad_FetchesAndCaches(t *testing.T) {
	withFeedServer(t, sampleCatalog, http.StatusOK)
	cachePath := filepath.Join(t.TempDir(), "kev.json")

	set, stale, err := Load(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if stale {
		t.Error("expected a fresh fetch to not be reported stale")
	}
	if _, ok := set["CVE-2021-44228"]; !ok {
		t.Errorf("expected CVE-2021-44228 in the set, got %+v", set)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Errorf("expected the fetch to be cached at %s: %v", cachePath, err)
	}
}

func TestLoad_UsesFreshCacheWithoutFetching(t *testing.T) {
	var fetched bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetched = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	old := feedURL
	feedURL = srv.URL
	defer func() { feedURL = old }()

	cachePath := filepath.Join(t.TempDir(), "kev.json")
	if err := os.WriteFile(cachePath, []byte(sampleCatalog), 0o644); err != nil {
		t.Fatal(err)
	}

	set, stale, err := Load(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if fetched {
		t.Error("expected a fresh cache to be used without hitting the feed")
	}
	if stale {
		t.Error("expected a fresh cache to not be reported stale")
	}
	if _, ok := set["CVE-2021-44228"]; !ok {
		t.Errorf("expected CVE-2021-44228 in the set, got %+v", set)
	}
}

func TestLoad_FallsBackToStaleCacheOnFetchFailure(t *testing.T) {
	withFeedServer(t, "", http.StatusInternalServerError)

	cachePath := filepath.Join(t.TempDir(), "kev.json")
	if err := os.WriteFile(cachePath, []byte(sampleCatalog), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(cachePath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	set, stale, err := Load(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if !stale {
		t.Error("expected the stale cache fallback to be reported")
	}
	if _, ok := set["CVE-2021-44228"]; !ok {
		t.Errorf("expected CVE-2021-44228 from the stale cache, got %+v", set)
	}
}

func TestLoad_ErrorsWithNoCacheAndFetchFailure(t *testing.T) {
	withFeedServer(t, "", http.StatusInternalServerError)
	if _, _, err := Load(filepath.Join(t.TempDir(), "kev.json")); err == nil {
		t.Error("expected an error when there's neither a cache nor a successful fetch")
	}
}

func TestAnnotate_MatchesByIDAndAlias(t *testing.T) {
	set := Set{"CVE-2021-44228": Entry{DateAdded: "2021-12-10"}}
	findings := []model.Finding{{
		Vulns: []model.Vulnerability{
			{ID: "CVE-2021-44228"},
			{ID: "OSV-2", Aliases: []string{"CVE-2021-44228"}},
			{ID: "CVE-9999-99999"},
		},
	}}

	Annotate(findings, set)

	if !findings[0].Vulns[0].KEV || findings[0].Vulns[0].KEVDateAdded != "2021-12-10" {
		t.Errorf("expected direct ID match to be KEV-annotated, got %+v", findings[0].Vulns[0])
	}
	if !findings[0].Vulns[1].KEV {
		t.Errorf("expected alias match to be KEV-annotated, got %+v", findings[0].Vulns[1])
	}
	if findings[0].Vulns[2].KEV {
		t.Errorf("expected the non-KEV CVE to be untouched, got %+v", findings[0].Vulns[2])
	}
}

func TestToSet_ParsesRansomwareFlag(t *testing.T) {
	var c catalog
	if err := json.Unmarshal([]byte(sampleCatalog), &c); err != nil {
		t.Fatal(err)
	}
	set := toSet(c)
	if !set["CVE-2021-44228"].Ransomware {
		t.Errorf("expected knownRansomwareCampaignUse=Known to set Ransomware=true, got %+v", set["CVE-2021-44228"])
	}
}
