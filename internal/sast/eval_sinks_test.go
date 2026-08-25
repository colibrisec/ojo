package sast

import (
	"os"
	"path/filepath"
	"testing"
)

// Extra code-execution sinks: Ruby's instance_eval/class_eval/module_eval
// string form (the block form must NOT fire — it's ordinary metaprogramming
// used throughout idiomatic Ruby), JS's vm module, and Java's ScriptEngine
// eval() gated on a non-literal argument.

const rubyMetaEvalFixture = `class Widget
  # safe: block-form class_eval, ordinary metaprogramming
  class_eval do
    def dynamic_method; end
  end

  def unsafe(code)
    instance_eval(code)
  end

  def also_unsafe
    self.class.class_eval("def generated; end")
  end
end
`

func TestRubyMetaEvalStringOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "widget.rb"), []byte(rubyMetaEvalFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "ruby-eval-detected" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 ruby-eval-detected issues (instance_eval + class_eval string form, NOT the block-form class_eval), got %d: %+v", count, issues)
	}
}

const jsVMFixture = `const vm = require('vm');

function unsafe(code) {
	vm.runInNewContext(code);
}

function alsoUnsafe(code) {
	vm.runInThisContext(code);
}
`

func TestJSVMEvalDetected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(jsVMFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "js-eval-detected" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 js-eval-detected issues (vm.runInNewContext + vm.runInThisContext), got %d: %+v", count, issues)
	}
}

const javaScriptEvalFixture = `import javax.script.ScriptEngine;
import javax.servlet.http.HttpServletRequest;

class C {
	void unsafe(ScriptEngine engine, HttpServletRequest request) throws Exception {
		String code = request.getParameter("code");
		engine.eval(code);
	}

	void safe(ScriptEngine engine) throws Exception {
		engine.eval("print('hello')");
	}
}
`

func TestJavaScriptEvalDetected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "C.java"), []byte(javaScriptEvalFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range issues {
		if i.RuleID == "java-eval-detected" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 java-eval-detected issue (tainted arg, not the literal script), got %d: %+v", count, issues)
	}
}
