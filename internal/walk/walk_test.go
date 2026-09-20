package walk

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
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

func gitInit(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
}

func walked(t *testing.T, dir string) []string {
	t.Helper()
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
	return visited
}

func TestRespectGitignore_SkipsIgnoredFilesAndDirs(t *testing.T) {
	dir := t.TempDir()
	gitInit(t, dir)
	writeFile(t, filepath.Join(dir, ".gitignore"), "dist/\n*.log\n")
	writeFile(t, filepath.Join(dir, "src", "main.go"), "package main")
	writeFile(t, filepath.Join(dir, "dist", "bundle.js"), "x")
	writeFile(t, filepath.Join(dir, "app.log"), "x")
	t.Cleanup(func() { RespectGitignore("") })

	if err := RespectGitignore(dir); err != nil {
		t.Fatal(err)
	}
	got := walked(t, dir)
	want := []string{".gitignore", "src/main.go"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("visited = %v, want %v", got, want)
	}
}

func TestRespectGitignore_KeepsTrackedFilesThatMatchIgnorePatterns(t *testing.T) {
	dir := t.TempDir()
	gitInit(t, dir)
	writeFile(t, filepath.Join(dir, "keep.log"), "x")
	if out, err := exec.Command("git", "-C", dir, "add", "keep.log").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	writeFile(t, filepath.Join(dir, ".gitignore"), "*.log\n")
	t.Cleanup(func() { RespectGitignore("") })

	if err := RespectGitignore(dir); err != nil {
		t.Fatal(err)
	}
	got := walked(t, dir)
	found := false
	for _, p := range got {
		if p == "keep.log" {
			found = true
		}
	}
	if !found {
		t.Errorf("tracked file keep.log must still be scanned, visited = %v", got)
	}
}

func TestRespectGitignore_OutsideGitRepoIsNoop(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "a")
	t.Cleanup(func() { RespectGitignore("") })

	if err := RespectGitignore(dir); err != nil {
		t.Fatal(err)
	}
	if got := walked(t, dir); len(got) != 1 || got[0] != "a.txt" {
		t.Errorf("visited = %v, want [a.txt]", got)
	}
}
