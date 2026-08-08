package osv

import (
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int // sign only
	}{
		{"1.35+dfsg-3.1", "1.35+dfsg-4", -1},
		{"2.2.28", "2.2.9", 1}, // numeric compare, not lexical ("28" > "9")
		{"3.2.13", "3.2.13", 0},
		{"1.0.0", "1.0.1", -1},
	}
	for _, c := range cases {
		got := versionCompare(c.a, c.b)
		gotSign := 0
		switch {
		case got < 0:
			gotSign = -1
		case got > 0:
			gotSign = 1
		}
		if gotSign != c.want {
			t.Errorf("versionCompare(%q, %q) sign = %d, want %d", c.a, c.b, gotSign, c.want)
		}
	}
}

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
