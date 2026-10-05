package manifest

import "testing"

func TestComposerLockParser(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "composer.lock", `{
		"packages": [
			{"name": "symfony/symfony", "version": "v4.4.0"}
		],
		"packages-dev": [
			{"name": "phpunit/phpunit", "version": "9.5.0"}
		]
	}`)

	pkgs, err := composerLockParser{}.Parse(dir + "/composer.lock")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{"symfony/symfony@4.4.0": false, "phpunit/phpunit@9.5.0": false}
	for _, p := range pkgs {
		if p.Ecosystem != "Packagist" {
			t.Errorf("expected Packagist ecosystem, got %q", p.Ecosystem)
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

func TestComposerLockParserReadsLicenses(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "composer.lock", `{
		"packages": [
			{"name": "monolog/monolog", "version": "3.5.0", "license": ["MIT"]},
			{"name": "dual/licensed", "version": "1.0.0", "license": ["LGPL-2.1-only", "GPL-3.0-or-later"]},
			{"name": "no/license", "version": "1.0.0"}
		]
	}`)

	pkgs, err := composerLockParser{}.Parse(dir + "/composer.lock")
	if err != nil {
		t.Fatal(err)
	}
	// Several licenses in a composer.lock are a choice between them.
	want := map[string]string{
		"monolog/monolog": "MIT",
		"dual/licensed":   "LGPL-2.1-only OR GPL-3.0-or-later",
		"no/license":      "",
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %d packages, want %d", len(pkgs), len(want))
	}
	for _, p := range pkgs {
		if p.License != want[p.Name] {
			t.Errorf("%s: license = %q, want %q", p.Name, p.License, want[p.Name])
		}
	}
}
