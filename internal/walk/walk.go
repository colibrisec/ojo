// Package walk provides the directory traversal shared by every filesystem-based scanner.
package walk

import (
	"io/fs"
	"path/filepath"
)

var defaultSkipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	"vendor":       true,
}

// Walk visits every regular file under root, skipping common vendor/VCS directories.
func Walk(root string, fn func(path string, d fs.DirEntry) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
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
