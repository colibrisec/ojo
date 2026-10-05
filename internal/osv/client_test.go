package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

func TestScanSurfacesOSVErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"code": 3, "message": "invalid ecosystem"}`))
	}))
	defer srv.Close()

	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	_, err := Scan(context.Background(), []model.Package{{Name: "x", Version: "1.0.0", Ecosystem: model.EcosystemNpm}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "invalid ecosystem") {
		t.Errorf("expected the OSV response body to be surfaced in the error, got: %v", err)
	}
}

func TestScanChunksLargeBatches(t *testing.T) {
	var requestCount int32
	var maxQueriesSeen int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if int32(len(req.Queries)) > atomic.LoadInt32(&maxQueriesSeen) {
			atomic.StoreInt32(&maxQueriesSeen, int32(len(req.Queries)))
		}
		if len(req.Queries) > maxBatchSize {
			t.Errorf("request had %d queries, want <= %d", len(req.Queries), maxBatchSize)
		}
		result := batchResult{Results: make([]batchResultEntry, len(req.Queries))}
		json.NewEncoder(w).Encode(result)
	}))
	defer srv.Close()

	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	var pkgs []model.Package
	for i := 0; i < maxBatchSize+1; i++ {
		pkgs = append(pkgs, model.Package{Name: "pkg", Version: "1.0.0", Ecosystem: model.EcosystemNpm})
	}

	if _, err := Scan(context.Background(), pkgs); err != nil {
		t.Fatal(err)
	}
	if requestCount != 2 {
		t.Errorf("expected maxBatchSize+1 packages to be split across 2 requests, got %d", requestCount)
	}
}

func TestScanQueriesBySourcePackageName(t *testing.T) {
	var got batchRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		json.NewEncoder(w).Encode(batchResult{Results: make([]batchResultEntry, len(got.Queries))})
	}))
	defer srv.Close()

	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	pkgs := []model.Package{
		{Name: "libcrypto3", Origin: "openssl", Version: "3.5.6-r0", Ecosystem: "Alpine:v3.23"},
		{Name: "busybox", Version: "1.37.0-r0", Ecosystem: "Alpine:v3.23"},
	}
	if _, err := Scan(context.Background(), pkgs); err != nil {
		t.Fatal(err)
	}
	if len(got.Queries) != 2 {
		t.Fatalf("expected 2 queries, got %d", len(got.Queries))
	}
	if n := got.Queries[0].Package.Name; n != "openssl" {
		t.Errorf("binary package with an origin must be queried by source name, got %q", n)
	}
	if n := got.Queries[1].Package.Name; n != "busybox" {
		t.Errorf("package without an origin must be queried by its own name, got %q", n)
	}
}

// captureQueries points Scan at a server that records every query it is
// sent and reports no vulnerabilities.
func captureQueries(t *testing.T) *[]batchQuery {
	t.Helper()
	var got []batchQuery
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		got = append(got, req.Queries...)
		json.NewEncoder(w).Encode(batchResult{Results: make([]batchResultEntry, len(req.Queries))})
	}))
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
	return &got
}

func TestScanQueriesRHELPerRepository(t *testing.T) {
	got := captureQueries(t)
	pkgs := []model.Package{
		{Name: "openssl-libs", Origin: "openssl", Version: "1:3.0.7-27.el9", Ecosystem: "Red Hat:enterprise_linux:9"},
		{Name: "openssl-libs", Origin: "openssl", Version: "1:3.2.2-16.el10", Ecosystem: "Red Hat:enterprise_linux:10.0"},
		{Name: "openssl-libs", Origin: "openssl", Version: "1:3.0.7-27.el9", Ecosystem: "Rocky Linux:9"},
	}
	if _, err := Scan(context.Background(), pkgs); err != nil {
		t.Fatal(err)
	}

	var ecosystems []string
	for _, q := range *got {
		if q.Package.Name != "openssl" {
			t.Errorf("queried %q, want the source package openssl", q.Package.Name)
		}
		ecosystems = append(ecosystems, q.Package.Ecosystem)
	}
	want := []string{
		"Red Hat:enterprise_linux:9::baseos", "Red Hat:enterprise_linux:9::appstream",
		"Red Hat:enterprise_linux:10.0",
		"Rocky Linux:9",
	}
	if strings.Join(ecosystems, "|") != strings.Join(want, "|") {
		t.Errorf("queried ecosystems %v, want %v", ecosystems, want)
	}
}

func TestScanQueriesPodsAsSwiftURL(t *testing.T) {
	got := captureQueries(t)
	pkgs := []model.Package{
		{Name: "Alamofire", Origin: "github.com/Alamofire/Alamofire", Version: "5.9.1", Ecosystem: model.EcosystemCocoaPods},
		{Name: "PrivatePod", Version: "1.0.0", Ecosystem: model.EcosystemCocoaPods}, // unresolved: nothing to ask about
	}
	if _, err := Scan(context.Background(), pkgs); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 || (*got)[0].Package.Name != "github.com/Alamofire/Alamofire" || (*got)[0].Package.Ecosystem != "SwiftURL" {
		t.Errorf("unexpected queries: %+v", *got)
	}
}

// A package with two query targets gets the findings of both, each
// vulnerability once, attributed to the right package.
func TestScanMergesResultsAcrossTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/vulns/") {
			id := strings.TrimPrefix(r.URL.Path, "/vulns/")
			json.NewEncoder(w).Encode(map[string]any{
				"id": id,
				"affected": []map[string]any{{
					"package": map[string]string{"name": "openssl", "ecosystem": "Red Hat:enterprise_linux:9::appstream"},
					"ranges":  []map[string]any{{"events": []map[string]string{{"introduced": "0"}, {"fixed": "1:3.0.7-28.el9"}}}},
				}},
			})
			return
		}
		var req batchRequest
		json.NewDecoder(r.Body).Decode(&req)
		var res batchResult
		for _, q := range req.Queries {
			var entry batchResultEntry
			switch q.Package.Ecosystem {
			case "Red Hat:enterprise_linux:9::baseos":
				entry.Vulns = []struct {
					ID string `json:"id"`
				}{{ID: "RHSA-1"}}
			case "Red Hat:enterprise_linux:9::appstream":
				entry.Vulns = []struct {
					ID string `json:"id"`
				}{{ID: "RHSA-1"}, {ID: "RHSA-2"}}
			}
			res.Results = append(res.Results, entry)
		}
		json.NewEncoder(w).Encode(res)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	findings, err := Scan(context.Background(), []model.Package{
		{Name: "bash", Version: "5.1.8-9.el9", Ecosystem: "Rocky Linux:9"},
		{Name: "openssl-libs", Origin: "openssl", Version: "1:3.0.7-27.el9", Ecosystem: "Red Hat:enterprise_linux:9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Package.Name != "openssl-libs" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	if len(findings[0].Vulns) != 2 {
		t.Fatalf("expected RHSA-1 and RHSA-2 once each, got %+v", findings[0].Vulns)
	}
	if got := findings[0].Vulns[0].FixedVersion; got != "1:3.0.7-28.el9" {
		t.Errorf("FixedVersion = %q", got)
	}
}
