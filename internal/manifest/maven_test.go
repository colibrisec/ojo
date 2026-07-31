package manifest

import "testing"

func TestMavenPomParser(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pom.xml", `<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0</version>
  <properties>
    <spring.version>5.3.20</spring.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>inherited-from-parent</artifactId>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>unresolvable-property</artifactId>
      <version>${some.property.only.the.parent.pom.knows}</version>
    </dependency>
  </dependencies>
</project>
`)

	pkgs, err := mavenPomParser{}.Parse(dir + "/pom.xml")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{"org.springframework:spring-core@5.3.20": false, "com.google.guava:guava@31.1-jre": false}
	for _, p := range pkgs {
		if p.Ecosystem != "Maven" {
			t.Errorf("expected Maven ecosystem, got %q", p.Ecosystem)
		}
		if p.Name == "org.example:inherited-from-parent" || p.Name == "org.example:unresolvable-property" {
			t.Errorf("dependency with no resolvable version should have been skipped, got %+v", p)
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
	if len(pkgs) != 2 {
		t.Errorf("expected exactly 2 resolvable dependencies, got %d: %+v", len(pkgs), pkgs)
	}
}
