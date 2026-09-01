package secret

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func initTestRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=ojo-test", "GIT_AUTHOR_EMAIL=ojo-test@example.com",
			"GIT_COMMITTER_NAME=ojo-test", "GIT_COMMITTER_EMAIL=ojo-test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "commit.gpgsign", "false")
	return dir
}

func TestScanGitHistory_FindsSecretRemovedInALaterCommit(t *testing.T) {
	dir := initTestRepo(t)
	path := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(path, []byte("aws_key = \"AKIAABCDEFGHIJKLMNOP\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCommit(t, dir, "add secret")

	if err := os.WriteFile(path, []byte("aws_key = \"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCommit(t, dir, "remove secret")

	// The working tree no longer has the secret.
	working, err := Scan(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(working) != 0 {
		t.Fatalf("expected the working tree to be clean, got %+v", working)
	}

	history, err := ScanGitHistory(context.Background(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, i := range history {
		if i.RuleID == "aws-access-key-id" && i.File == "config.yaml" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the removed secret to still be found in git history, got %+v", history)
	}
}

func TestScanGitHistory_NotAGitRepoIsAnError(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	if _, err := ScanGitHistory(context.Background(), t.TempDir(), nil); err == nil {
		t.Error("expected an error for a non-git directory")
	}
}

func gitCommit(t *testing.T, dir, msg string) {
	t.Helper()
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-q", "-m", msg}} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=ojo-test", "GIT_AUTHOR_EMAIL=ojo-test@example.com",
			"GIT_COMMITTER_NAME=ojo-test", "GIT_COMMITTER_EMAIL=ojo-test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}
