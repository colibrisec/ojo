package cli

import (
	"bytes"
	"path/filepath"
	"testing"
)

// runImage mirrors fs_test.go's run helper. Every case here deliberately
// errors before image.Scan (a real registry pull) is ever reached -- this
// package has no way to stub that out, unlike internal/image's own
// httptest-backed tests.
func runImage(t *testing.T, args ...string) error {
	t.Helper()
	cmd := imageCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestImageCmd_RequiresExactlyOneArg(t *testing.T) {
	if err := runImage(t); err == nil {
		t.Error("expected an error with no image ref given")
	}
	if err := runImage(t, "ref1", "ref2"); err == nil {
		t.Error("expected an error with more than one image ref given")
	}
}

func TestImageCmd_BadConfigPathIsAnError(t *testing.T) {
	dir := t.TempDir()
	err := runImage(t, "--config", filepath.Join(dir, "nope.yaml"), "alpine:latest")
	if err == nil {
		t.Error("expected an error for a missing explicit --config path")
	}
}

func TestImageCmd_BadCycloneDXVersionIsAnError(t *testing.T) {
	err := runImage(t, "--cyclonedx-version", "9.9", "alpine:latest")
	if err == nil {
		t.Error("expected an error for an unsupported CycloneDX version")
	}
}
