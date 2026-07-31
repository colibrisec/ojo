package manifest

import "testing"

func TestGradleLockParser(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "gradle.lockfile", `# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
org.springframework:spring-core:5.3.20=compileClasspath,runtimeClasspath
empty=annotationProcessor,testAnnotationProcessor
`)

	pkgs, err := gradleLockParser{}.Parse(dir + "/gradle.lockfile")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"com.google.guava:guava@31.1-jre": false, "org.springframework:spring-core@5.3.20": false}
	for _, p := range pkgs {
		if p.Ecosystem != "Maven" {
			t.Errorf("expected Maven ecosystem, got %q", p.Ecosystem)
		}
		want[p.Name+"@"+p.Version] = true
	}
	for k, found := range want {
		if !found {
			t.Errorf("expected package %s not found in %+v", k, pkgs)
		}
	}
	if len(pkgs) != 2 {
		t.Errorf("expected the \"empty=...\" marker line to be skipped, got %d packages: %+v", len(pkgs), pkgs)
	}
}
