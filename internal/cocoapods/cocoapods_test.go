package cocoapods

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

func stubCDN(t *testing.T, specs map[string]string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := specs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	old := cdnBase
	cdnBase = srv.URL
	t.Cleanup(func() { cdnBase = old })
}

func TestSpecURLShardsByNameHash(t *testing.T) {
	// md5("Alamofire") starts with da2 -- the layout the real CDN serves.
	got := specURL("Alamofire", "5.9.1")
	want := cdnBase + "/d/a/2/Alamofire/5.9.1/Alamofire.podspec.json"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestResolve(t *testing.T) {
	stubCDN(t, map[string]string{
		"/d/a/2/Alamofire/5.9.1/Alamofire.podspec.json": `{"license": "MIT", "source": {"git": "https://github.com/Alamofire/Alamofire.git", "tag": "5.9.1"}}`,
		"/f/e/5/Zipped/1.0.0/Zipped.podspec.json":       `{"license": {"type": "Apache-2.0", "file": "LICENSE"}, "source": {"http": "https://example.com/zipped.zip"}}`,
	})

	pkgs := []model.Package{
		{Name: "Alamofire", Version: "5.9.1", Ecosystem: model.EcosystemCocoaPods},
		{Name: "Zipped", Version: "1.0.0", Ecosystem: model.EcosystemCocoaPods},
		{Name: "PrivatePod", Version: "2.0.0", Ecosystem: model.EcosystemCocoaPods},
		{Name: "lodash", Version: "4.17.21", Ecosystem: model.EcosystemNpm},
	}
	out, unresolved := Resolve(context.Background(), pkgs)

	if out[0].Origin != "github.com/Alamofire/Alamofire" || out[0].License != "MIT" {
		t.Errorf("Alamofire: %+v", out[0])
	}
	// No git source: nothing to match advisories against, but the license
	// is still known.
	if out[1].Origin != "" || out[1].License != "Apache-2.0" {
		t.Errorf("Zipped: %+v", out[1])
	}
	if out[2].Origin != "" {
		t.Errorf("PrivatePod: %+v", out[2])
	}
	if out[3] != pkgs[3] {
		t.Errorf("non-pod package was modified: %+v", out[3])
	}
	if unresolved != 2 {
		t.Errorf("unresolved = %d, want 2", unresolved)
	}
	if pkgs[0].Origin != "" {
		t.Error("Resolve modified its input slice")
	}
}

func TestRepository(t *testing.T) {
	cases := map[string]string{
		"https://github.com/Alamofire/Alamofire.git": "github.com/Alamofire/Alamofire",
		"git@github.com:owner/repo.git":              "github.com/owner/repo",
		"https://gitlab.com/owner/repo/":             "gitlab.com/owner/repo",
		"":                                           "",
	}
	for in, want := range cases {
		if got := repository(in); got != want {
			t.Errorf("repository(%q) = %q, want %q", in, got, want)
		}
	}
}
