package misconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScan(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Dockerfile", "FROM ubuntu\nENV DB_PASSWORD=hunter2\nADD ./app.tar.gz /app\n")
	write(t, dir, "pod.yaml", "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n    - name: web\n      securityContext:\n        privileged: true\n")
	write(t, dir, "main.tf", `resource "aws_s3_bucket" "data" {
  acl = "public-read"
}
`)

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"dockerfile-root-user":     false,
		"dockerfile-latest-tag":    false,
		"dockerfile-secret-env":    false,
		"k8s-host-network":         false,
		"k8s-privileged-container": false,
		"tf-s3-public-acl":         false,
	}
	for _, i := range issues {
		if _, ok := want[i.RuleID]; ok {
			want[i.RuleID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected rule %s to fire, got issues: %+v", id, issues)
		}
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
