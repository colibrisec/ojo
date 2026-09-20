package walk

import (
	"bytes"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
)

var defaultSkipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	"vendor":       true,
}

var gitIgnored map[string]bool

// RespectGitignore makes Walk skip untracked files that git ignores under
// root. Outside a git repository, or without git, it has no effect. An empty
// root clears the setting.
func RespectGitignore(root string) error {
	gitIgnored = nil
	if root == "" {
		return nil
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	out, err := exec.Command("git", "-C", abs, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z").Output()
	if err != nil {
		return nil
	}
	ignored := map[string]bool{}
	for _, p := range bytes.Split(out, []byte{0}) {
		if len(p) == 0 {
			continue
		}
		ignored[filepath.Join(abs, filepath.FromSlash(strings.TrimSuffix(string(p), "/")))] = true
	}
	gitIgnored = ignored
	return nil
}

func isGitIgnored(path string) bool {
	if gitIgnored == nil {
		return false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	return gitIgnored[abs]
}

// Walk visits every regular file under root, skipping common vendor/VCS directories.
func Walk(root string, fn func(path string, d fs.DirEntry) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if isGitIgnored(path) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if defaultSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		return fn(path, d)
	})
}
