package sast

import (
	"os"
	"path/filepath"
	"testing"
)

const pyAgentToolFixture = `from langchain_experimental.tools import PythonREPLTool
from langchain_community.tools import ShellTool

def handle_inline(request):
    PythonREPLTool().run(request.args.get("code"))

def handle_via_variable(request):
    tool = ShellTool()
    cmd = request.args.get("cmd")
    tool.run(cmd)

def safe_literal():
    tool = ShellTool()
    tool.run("echo fixed-and-safe")

def safe_unrelated_object():
    logger.run(request.args.get("x"))
`

func TestPythonAgentUnsandboxedExec(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent.py"), []byte(pyAgentToolFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "py-agent-unsandboxed-exec" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 py-agent-unsandboxed-exec issues (inline constructor + tracked variable, not the literal or unrelated-object cases), got %d: %+v", count, issues)
	}
}
