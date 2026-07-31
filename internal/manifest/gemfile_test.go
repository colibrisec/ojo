package manifest

import "testing"

func TestGemfileLockParser(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Gemfile.lock", `GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      actionview (= 7.0.4)
      activesupport (= 7.0.4)
    nokogiri (1.10.0-x86_64-linux)
      mini_portile2 (~> 2.4.0)
    rails (7.0.4)
      actionpack (= 7.0.4)

PLATFORMS
  ruby

DEPENDENCIES
  rails

BUNDLED WITH
   2.3.7
`)

	pkgs, err := gemfileLockParser{}.Parse(dir + "/Gemfile.lock")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{"actionpack@7.0.4": false, "nokogiri@1.10.0-x86_64-linux": false, "rails@7.0.4": false}
	for _, p := range pkgs {
		if p.Ecosystem != "RubyGems" {
			t.Errorf("expected RubyGems ecosystem, got %q", p.Ecosystem)
		}
		if p.Name == "actionview" || p.Name == "activesupport" || p.Name == "mini_portile2" {
			t.Errorf("nested sub-dependency line should not be parsed as its own package, got %+v", p)
		}
		key := p.Name + "@" + p.Version
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for k, found := range want {
		if !found {
			t.Errorf("expected package %s not found in %+v", k, pkgs)
		}
	}
}
