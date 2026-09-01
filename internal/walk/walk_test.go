package walk

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWalk_VisitsRegularFilesOnly(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "a")
	writeFile(t, filepath.Join(dir, "sub", "b.txt"), "b")

	var visited []string
	err := Walk(dir, func(path string, d fs.DirEntry) error {
		rel, _ := filepath.Rel(dir, path)
		visited = append(visited, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(visited)
	want := []string{"a.txt", "sub/b.txt"}
	if len(visited) != len(want) || visited[0] != want[0] || visited[1] != want[1] {
		t.Errorf("visited = %v, want %v", visited, want)
	}
}

func TestWalk_SkipsVendorDirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "app.go"), "package main")
	writeFile(t, filepath.Join(dir, "node_modules", "pkg", "index.js"), "")
	writeFile(t, filepath.Join(dir, ".git", "HEAD"), "")
	writeFile(t, filepath.Join(dir, "vendor", "lib", "x.go"), "")

	var visited []string
	err := Walk(dir, func(path string, d fs.DirEntry) error {
		visited = append(visited, d.Name())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(visited) != 1 || visited[0] != "app.go" {
		t.Errorf("expected only app.go to be visited (skipping node_modules/.git/vendor), got %v", visited)
	}
}

func TestWalk_PropagatesCallbackError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "a")

	wantErr := errors.New("boom")
	err := Walk(dir, func(path string, d fs.DirEntry) error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Errorf("expected the callback's error to propagate, got %v", err)
	}
}

func TestWalk_NonexistentRootIsAnError(t *testing.T) {
	err := Walk(filepath.Join(t.TempDir(), "nope"), func(path string, d fs.DirEntry) error {
		return nil
	})
	if err == nil {
		t.Error("expected an error for a nonexistent root")
	}
}
