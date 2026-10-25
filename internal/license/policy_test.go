package license

import (
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

func pkg(name, lic string) model.Package {
	return model.Package{Name: name, Version: "1.0.0", Ecosystem: model.EcosystemNpm, Source: "package-lock.json", License: lic}
}

func rules(issues []model.Issue) map[string]string {
	m := map[string]string{}
	for _, iss := range issues {
		m[iss.Match] = iss.RuleID
	}
	return m
}

func TestPolicyDeny(t *testing.T) {
	p := Policy{Deny: []string{"GPL-3.0-only", "AGPL-*"}}
	issues, _ := p.Check([]model.Package{
		pkg("mit", "MIT"),
		pkg("gpl", "GPL-3.0-only"),
		pkg("gpl-deprecated", "GPL-3.0"),
		pkg("agpl", "AGPL-3.0-or-later"),
		pkg("dual-ok", "MIT OR GPL-3.0-only"),
		pkg("both-bad", "MIT AND GPL-3.0-only"),
		pkg("nested", "(Apache-2.0 OR GPL-3.0-only) AND AGPL-3.0-only"),
		pkg("later", "GPL-3.0-or-later"),
	})
	got := rules(issues)
	want := map[string]string{
		"gpl@1.0.0":            "license-denied",
		"gpl-deprecated@1.0.0": "license-denied",
		"agpl@1.0.0":           "license-denied",
		"both-bad@1.0.0":       "license-denied",
		"nested@1.0.0":         "license-denied",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
}

func TestPolicyAllow(t *testing.T) {
	p := Policy{Allow: []string{"MIT", "apache-2.0", "BSD-*", "Custom License"}}
	issues, _ := p.Check([]model.Package{
		pkg("mit", "MIT"),
		pkg("apache", "Apache-2.0"),
		pkg("bsd", "BSD-3-Clause"),
		pkg("free-form", "Custom License"),
		pkg("dual", "GPL-2.0-only OR MIT"),
		pkg("with", "Apache-2.0 WITH LLVM-exception"),
		pkg("gpl", "GPL-2.0-only"),
		pkg("and", "MIT AND GPL-2.0-only"),
		pkg("broken", "MIT AND ("),
	})
	got := rules(issues)
	for _, name := range []string{"gpl@1.0.0", "and@1.0.0", "broken@1.0.0"} {
		if got[name] != "license-not-allowed" {
			t.Errorf("%s: got %q, want license-not-allowed", name, got[name])
		}
	}
	if len(got) != 3 {
		t.Errorf("got %v, want exactly 3 issues", got)
	}
}

func TestPolicyUnknown(t *testing.T) {
	pkgs := []model.Package{pkg("none", ""), pkg("noassert", "NOASSERTION"), pkg("mit", "MIT")}

	issues, unknown := Policy{Deny: []string{"GPL-3.0-only"}}.Check(pkgs)
	if len(issues) != 0 || len(unknown) != 2 {
		t.Errorf("warn mode: got %d issues, %d unknown; want 0, 2", len(issues), len(unknown))
	}

	issues, _ = Policy{Deny: []string{"GPL-3.0-only"}, FailUnknown: true}.Check(pkgs)
	if got := rules(issues); len(got) != 2 || got["none@1.0.0"] != "license-unknown" {
		t.Errorf("fail mode: got %v", got)
	}
}

func TestPolicyExceptionsAndDedup(t *testing.T) {
	p := Policy{Deny: []string{"GPL-3.0-only"}, Exceptions: []string{"internal", "pinned@1.0.0", "other@2.0.0"}}
	issues, _ := p.Check([]model.Package{
		pkg("internal", "GPL-3.0-only"),
		pkg("pinned", "GPL-3.0-only"),
		pkg("other", "GPL-3.0-only"),
		pkg("other", "GPL-3.0-only"),
	})
	if len(issues) != 1 || issues[0].Match != "other@1.0.0" {
		t.Errorf("got %+v, want one issue for other@1.0.0", issues)
	}
}
