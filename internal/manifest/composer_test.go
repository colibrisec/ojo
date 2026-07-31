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
