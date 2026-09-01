package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/colibrisec/ojo/internal/kev"
	"github.com/colibrisec/ojo/internal/model"
)

// run executes fsCmd() with args against dir, returning combined
// stdout+stderr and the RunE error. --scanners vuln/--kev need
// stubOSVScan/stubKevLoad (deps_test.go) rather than a real OSV.dev/CISA
// call.
func run(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := fsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(append(args, dir))
	err := cmd.Execute()
	return buf.String(), err
}

func TestFsCmd_NoFindingsExitsClean(t *testing.T) {
	dir := t.TempDir()
	out, err := run(t, dir, "--scanners", "secret")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(out, "No issues found") {
		t.Errorf("expected a clean-scan message, got %q", out)
	}
}

func TestFsCmd_FindingsReturnErrFindingsFound(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")

	out, err := run(t, dir, "--scanners", "secret")
	if !errors.Is(err, ErrFindingsFound) {
		t.Errorf("expected ErrFindingsFound, got %v", err)
	}
	if !strings.Contains(out, "aws-access-key-id") {
		t.Errorf("expected the finding in output, got %q", out)
	}
}

func TestFsCmd_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")

	out, err := run(t, dir, "--scanners", "secret", "-f", "json")
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v", err)
	}
	if !strings.Contains(out, `"ruleId": "aws-access-key-id"`) && !strings.Contains(out, `"RuleID": "aws-access-key-id"`) {
		t.Errorf("expected JSON output to contain the finding, got %q", out)
	}
}

func TestFsCmd_SARIFFormat(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")

	out, err := run(t, dir, "--scanners", "secret", "-f", "sarif")
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v", err)
	}
	if !strings.Contains(out, `"aws-access-key-id"`) || !strings.Contains(out, `"$schema"`) {
		t.Errorf("expected valid-looking SARIF output, got %q", out)
	}
}

func TestFsCmd_VEXFormat(t *testing.T) {
	dir := t.TempDir()
	out, err := run(t, dir, "--scanners", "secret", "-f", "vex")
	if err != nil {
		t.Fatalf("expected no error (secret scanner produces no Findings), got %v", err)
	}
	if !strings.Contains(out, `"@context": "https://openvex.dev/ns/v0.2.0"`) {
		t.Errorf("expected an OpenVEX document, got %q", out)
	}
}

func TestFsCmd_SBOMFormat(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "requirements.txt", "django==3.2.0\n")

	out, err := run(t, dir, "-f", "sbom")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(out, "pkg:pypi/django@3.2.0") {
		t.Errorf("expected the django component in the SBOM, got %q", out)
	}
}

func TestFsCmd_VulnScannerStub(t *testing.T) {
	dir := t.TempDir()
	stubOSVScan(t, []model.Finding{{
		Package: model.Package{Name: "x", Version: "1"},
		Vulns:   []model.Vulnerability{{ID: "CVE-2024-1", Severity: "HIGH"}},
	}}, nil)

	out, err := run(t, dir, "--scanners", "vuln")
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v", err)
	}
	if !strings.Contains(out, "CVE-2024-1") {
		t.Errorf("got %q", out)
	}
}

func TestFsCmd_VulnScannerOSVErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	stubOSVScan(t, nil, errors.New("osv down"))

	_, err := run(t, dir, "--scanners", "vuln")
	if err == nil || !strings.Contains(err.Error(), "osv down") {
		t.Errorf("expected the osv.Scan error to propagate, got %v", err)
	}
}

func TestFsCmd_VulnScannerKevFlag(t *testing.T) {
	dir := t.TempDir()
	stubOSVScan(t, []model.Finding{{
		Package: model.Package{Name: "x", Version: "1"},
		Vulns:   []model.Vulnerability{{ID: "CVE-2024-1"}},
	}}, nil)
	stubKevLoad(t, kev.Set{"CVE-2024-1": kev.Entry{DateAdded: "2024-01-01"}}, false, nil)

	out, err := run(t, dir, "--scanners", "vuln", "--kev")
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v", err)
	}
	if !strings.Contains(out, "KEV") {
		t.Errorf("expected a KEV marker in output, got %q", out)
	}
}

func TestFsCmd_VulnScannerKevLoadErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	stubOSVScan(t, []model.Finding{{Package: model.Package{Name: "x", Version: "1"}, Vulns: []model.Vulnerability{{ID: "CVE-2024-1"}}}}, nil)
	stubKevLoad(t, nil, false, errors.New("feed unreachable"))

	_, err := run(t, dir, "--scanners", "vuln", "--kev")
	if err == nil || !strings.Contains(err.Error(), "feed unreachable") {
		t.Errorf("expected the KEV load error to propagate, got %v", err)
	}
}

func TestFsCmd_VexFileSuppresses(t *testing.T) {
	dir := t.TempDir()
	vexDoc := `{"@context":"https://openvex.dev/ns/v0.2.0","author":"t","timestamp":"2026-01-01T00:00:00Z","version":1,` +
		`"statements":[{"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:generic/x@1"}],"status":"not_affected"}]}`
	write(t, dir, "accept.vex.json", vexDoc)
	stubOSVScan(t, []model.Finding{{
		Package: model.Package{Name: "x", Version: "1"},
		Vulns:   []model.Vulnerability{{ID: "CVE-2024-1"}},
	}}, nil)

	out, err := run(t, dir, "--scanners", "vuln", "--vex-file", filepath.Join(dir, "accept.vex.json"))
	if err != nil {
		t.Fatalf("expected the finding to be suppressed (no error), got %v", err)
	}
	if !strings.Contains(out, "No issues found") {
		t.Errorf("got %q", out)
	}
}

func TestFsCmd_ConfigFileSetsFormatAndScanners(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")
	cfgPath := filepath.Join(dir, ".ojo.yaml")
	write(t, dir, ".ojo.yaml", "scanners: secret\nformat: json\n")

	out, err := run(t, dir, "--config", cfgPath)
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v", err)
	}
	if !strings.Contains(out, `"RuleID": "aws-access-key-id"`) {
		t.Errorf("expected the config file's scanners/format to take effect (JSON output with the secret finding), got %q", out)
	}
}

func TestFsCmd_CustomRulesDirBadPathIsAnError(t *testing.T) {
	dir := t.TempDir()
	if _, err := run(t, dir, "--rules-dir", filepath.Join(dir, "nope")); err == nil {
		t.Error("expected an error for a missing explicit --rules-dir path")
	}
}

func TestFsCmd_SecretRulesFileBadRegexIsAnError(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	write(t, dir, "rules.yaml", "rules:\n  - id: bad\n    regex: \"[unclosed\"\n    severity: HIGH\n")

	if _, err := run(t, dir, "--scanners", "secret", "--secret-rules-file", rulesPath); err == nil {
		t.Error("expected an error for an invalid regex in --secret-rules-file")
	}
}

func TestFsCmd_CycloneDXVersionRejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "requirements.txt", "django==3.2.0\n")

	_, err := run(t, dir, "-f", "sbom", "--cyclonedx-version", "9.9")
	if err == nil {
		t.Error("expected an error for an unsupported CycloneDX version")
	}
}

func TestFsCmd_IgnoreFileSuppresses(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")
	write(t, dir, ".ojoignore", "aws-access-key-id  .env  # accepted risk\n")

	out, err := run(t, dir, "--scanners", "secret", "--ignore-file", filepath.Join(dir, ".ojoignore"))
	if err != nil {
		t.Fatalf("expected the finding to be suppressed (no error), got %v", err)
	}
	if !strings.Contains(out, "No issues found") {
		t.Errorf("expected a clean-scan message, got %q", out)
	}
}

func TestFsCmd_SecretRulesFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "config.yaml", `token = "itok_ABCDEFGHIJ0123456789"`+"\n")
	rulesPath := filepath.Join(dir, "rules.yaml")
	write(t, dir, "rules.yaml", "rules:\n  - id: internal-token\n    description: Internal token\n    regex: \"itok_[A-Za-z0-9]{20}\"\n    severity: HIGH\n")

	out, err := run(t, dir, "--scanners", "secret", "--secret-rules-file", rulesPath)
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v", err)
	}
	if !strings.Contains(out, "internal-token") {
		t.Errorf("expected the custom rule to fire, got %q", out)
	}
}

func TestFsCmd_SecretGitHistory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitInit(t, dir)
	write(t, dir, "config.yaml", "aws_key = \"AKIAABCDEFGHIJKLMNOP\"\n")
	gitCommitAll(t, dir, "add secret")
	write(t, dir, "config.yaml", "aws_key = \"\"\n")
	gitCommitAll(t, dir, "remove secret")

	out, err := run(t, dir, "--scanners", "secret", "--secret-git-history")
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound (secret still in history), got %v", err)
	}
	if !strings.Contains(out, "git history") {
		t.Errorf("expected the history finding's message to say so, got %q", out)
	}
}

func TestFsCmd_RulesDirCustomSASTRule(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.py", "eval(x)\n")
	rulesDir := filepath.Join(dir, ".ojo", "rules")
	write(t, rulesDir, "custom.yaml", "id: custom-eval\nlanguage: python\nseverity: HIGH\ntitle: custom eval\nmessage: custom eval detected\nquery: |\n  (call function: (identifier) @fn (#eq? @fn \"eval\")) @match\n")

	out, err := run(t, dir, "--scanners", "sast")
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v", err)
	}
	if !strings.Contains(out, "custom-eval") {
		t.Errorf("expected the custom SAST rule to fire, got %q", out)
	}
}

func TestFsCmd_BadConfigPathIsAnError(t *testing.T) {
	dir := t.TempDir()
	if _, err := run(t, dir, "--config", filepath.Join(dir, "nope.yaml")); err == nil {
		t.Error("expected an error for a missing explicit --config path")
	}
}

func TestFsCmd_BadIgnoreFilePathIsAnError(t *testing.T) {
	dir := t.TempDir()
	if _, err := run(t, dir, "--ignore-file", filepath.Join(dir, "nope")); err == nil {
		t.Error("expected an error for a missing explicit --ignore-file path")
	}
}

func TestFsCmd_UnknownScannerIsAnError(t *testing.T) {
	dir := t.TempDir()
	if _, err := run(t, dir, "--scanners", "nope"); err == nil {
		t.Error("expected an error for an unknown scanner")
	}
}

func TestFsCmd_GitlabWritesReports(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")
	t.Chdir(dir) // -g writes report files relative to cwd

	_, err := run(t, dir, "-g")
	if !errors.Is(err, ErrFindingsFound) {
		t.Fatalf("expected ErrFindingsFound, got %v", err)
	}
	for _, name := range []string{
		"gl-dependency-scanning-report.json",
		"gl-sast-report.json",
		"gl-secret-detection-report.json",
		"gl-sbom-report.cdx.json",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to be written: %v", name, err)
		}
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func gitInit(t *testing.T, dir string) {
	t.Helper()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "commit.gpgsign", "false")
	runGit(t, dir, "config", "user.email", "ojo-test@example.com")
	runGit(t, dir, "config", "user.name", "ojo-test")
}

func gitCommitAll(t *testing.T, dir, msg string) {
	t.Helper()
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-q", "-m", msg)
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}
