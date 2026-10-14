package osv

import (
	"encoding/json"
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

func TestResolveFixedVersion(t *testing.T) {
	d := vulnDetail{}
	d.Affected = []struct {
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
	}{
		{
			Package: struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			}{Name: "django", Ecosystem: "PyPI"},
			Ranges: []struct {
				Events []struct {
					Introduced string `json:"introduced"`
					Fixed      string `json:"fixed"`
				} `json:"events"`
			}{
				{Events: []struct {
					Introduced string `json:"introduced"`
					Fixed      string `json:"fixed"`
				}{
					{Introduced: "2.2"}, {Fixed: "2.2.28"},
				}},
				{Events: []struct {
					Introduced string `json:"introduced"`
					Fixed      string `json:"fixed"`
				}{
					{Introduced: "3.2"}, {Fixed: "3.2.13"},
				}},
			},
		},
	}

	got := resolveFixedVersion(d, model.Package{Name: "django", Version: "3.2.0", Ecosystem: "PyPI"})
	if got != "3.2.13" {
		t.Errorf("resolveFixedVersion for 3.2.0 = %q, want 3.2.13", got)
	}

	got = resolveFixedVersion(d, model.Package{Name: "requests", Version: "2.6.0", Ecosystem: "PyPI"})
	if got != "" {
		t.Errorf("resolveFixedVersion for unrelated package = %q, want empty", got)
	}
}

func TestResolveFixedVersionMatchesSourcePackage(t *testing.T) {
	var d vulnDetail
	err := json.Unmarshal([]byte(`{"affected":[{"package":{"name":"openssl","ecosystem":"Alpine:v3.23"},
		"ranges":[{"events":[{"introduced":"0"},{"fixed":"3.5.8-r0"}]}]}]}`), &d)
	if err != nil {
		t.Fatal(err)
	}

	pkg := model.Package{Name: "libcrypto3", Origin: "openssl", Version: "3.5.6-r0", Ecosystem: "Alpine:v3.23"}
	if got := resolveFixedVersion(d, pkg); got != "3.5.8-r0" {
		t.Errorf("fixed version for binary package must be resolved via its source package, got %q", got)
	}
}

func TestResolveFixedVersionUsesEcosystemOrdering(t *testing.T) {
	cases := []struct {
		ecosystem, installed, events, want string
	}{
		{"PyPI", "2.0.0rc1", `{"introduced":"0"},{"fixed":"2.0.0"}`, "2.0.0"},
		{"Maven", "1.0-SNAPSHOT", `{"introduced":"0"},{"fixed":"1.0"}`, "1.0"},
		{"Debian:12", "1.2~rc1-1", `{"introduced":"0"},{"fixed":"1.2-1"}`, "1.2-1"},
		{"npm", "1.0.0", `{"introduced":"0"},{"fixed":"1.0.0-rc.1"}`, ""},
	}
	for _, c := range cases {
		var d vulnDetail
		doc := `{"affected":[{"package":{"name":"p","ecosystem":"` + c.ecosystem + `"},"ranges":[{"events":[` + c.events + `]}]}]}`
		if err := json.Unmarshal([]byte(doc), &d); err != nil {
			t.Fatal(err)
		}
		pkg := model.Package{Name: "p", Version: c.installed, Ecosystem: model.Ecosystem(c.ecosystem)}
		if got := resolveFixedVersion(d, pkg); got != c.want {
			t.Errorf("%s %s: got fixed version %q, want %q", c.ecosystem, c.installed, got, c.want)
		}
	}
}
