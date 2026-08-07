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
