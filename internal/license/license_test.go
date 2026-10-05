package license

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

// stubDepsDev serves versionbatch from a fixed "SYSTEM/name/version" ->
// licenses table, recording every key it was asked about.
func stubDepsDev(t *testing.T, table map[string][]string) *[]versionKey {
	t.Helper()
	var asked []versionKey
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		var resp batchResponse
		for _, q := range req.Requests {
			asked = append(asked, q.VersionKey)
			k := q.VersionKey
			item := versionResponse{Request: q}
			if l, ok := table[k.System+"/"+k.Name+"/"+k.Version]; ok {
				item.Version = &versionInfo{Licenses: l}
			}
			resp.Responses = append(resp.Responses, item)
		}
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
	return &asked
}

func TestLookup(t *testing.T) {
	asked := stubDepsDev(t, map[string][]string{
		"PYPI/requests/2.31.0":       {"Apache-2.0"},
		"CARGO/dual/1.0.0":           {"MIT", "Apache-2.0"},
		"NPM/odd/1.0.0":              {"non-standard"},
		"GO/example.com/mod/v1.0.0":  {"BSD-3-Clause"},
		"NPM/already-known/1.0.0":    {"GPL-3.0-only"},
		"PACKAGIST/vendor/pkg/1.0.0": {"MIT"},
	})

	pkgs := []model.Package{
		{Name: "requests", Version: "2.31.0", Ecosystem: model.EcosystemPyPI},
		{Name: "dual", Version: "1.0.0", Ecosystem: model.EcosystemCratesIO},
		{Name: "odd", Version: "1.0.0", Ecosystem: model.EcosystemNpm},
		{Name: "unknown", Version: "9.9.9", Ecosystem: model.EcosystemNpm},
		{Name: "already-known", Version: "1.0.0", Ecosystem: model.EcosystemNpm, License: "MIT"},
		{Name: "vendor/pkg", Version: "1.0.0", Ecosystem: model.EcosystemPackagist},
		{Name: "example.com/mod", Version: "v1.0.0", Ecosystem: model.EcosystemGo},
		{Name: "requests", Version: "2.31.0", Ecosystem: model.EcosystemPyPI, Source: "other/requirements.txt"},
	}
	out, err := Lookup(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"Apache-2.0", "MIT AND Apache-2.0", "", "", "MIT", "", "BSD-3-Clause", "Apache-2.0"}
	for i, w := range want {
		if out[i].License != w {
			t.Errorf("%s: license %q, want %q", out[i].Name, out[i].License, w)
		}
	}
	// Not asked about: the package that already had a license, the one in
	// an ecosystem deps.dev doesn't cover, and the duplicate.
	if len(*asked) != 5 {
		t.Errorf("asked deps.dev about %d keys, want 5: %+v", len(*asked), *asked)
	}
	if pkgs[0].License != "" {
		t.Error("Lookup modified its input slice")
	}
}

func TestLookupReturnsPackagesOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	pkgs := []model.Package{{Name: "requests", Version: "2.31.0", Ecosystem: model.EcosystemPyPI}}
	out, err := Lookup(context.Background(), pkgs)
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(out) != 1 || out[0].Name != "requests" {
		t.Errorf("expected the packages back regardless, got %+v", out)
	}
}

func TestSPDXClassification(t *testing.T) {
	for _, s := range []string{"MIT", "Apache-2.0", "GPL-2.0-or-later"} {
		if !IsSPDXID(s) {
			t.Errorf("IsSPDXID(%q) = false", s)
		}
	}
	for _, s := range []string{"GPLv2+", "MIT License", "", "MIT OR Apache-2.0"} {
		if IsSPDXID(s) {
			t.Errorf("IsSPDXID(%q) = true", s)
		}
	}
	for _, s := range []string{"MIT OR Apache-2.0", "(MIT OR Apache-2.0) AND BSD-3-Clause", "GPL-2.0-only WITH Classpath-exception-2.0", "GPL-2.0+ AND MIT"} {
		if !IsSPDXExpression(s) {
			t.Errorf("IsSPDXExpression(%q) = false", s)
		}
	}
	for _, s := range []string{"MIT", "MIT OR", "GPLv2+ and MIT", "MIT AND Custom", "MIT WITH Apache-2.0", "(MIT OR Apache-2.0", "Public Domain"} {
		if IsSPDXExpression(s) {
			t.Errorf("IsSPDXExpression(%q) = true", s)
		}
	}
}
