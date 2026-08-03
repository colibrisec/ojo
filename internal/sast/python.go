// Python rules, using gotreesitter (pure-Go tree-sitter runtime, no cgo —
// see scanner.go's package doc for why that constraint matters) and its
// query engine. Each rule is a compiled tree-sitter query plus a small Go
// predicate for the checks a query alone can't express (e.g. "is this
// argument a literal or built dynamically").
//
// Curated against github.com/semgrep/semgrep-rules' python ruleset: same
// threat coverage, hand-ported rather than executing semgrep's rule engine.
package sast

import (
	"strings"

	gts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"

	"github.com/colibrisec/ojo/internal/model"
)

var pyLang = grammars.PythonLanguage()

func mustPyQuery(src string) *gts.Query {
	q, err := gts.NewQuery(src, pyLang)
	if err != nil {
		panic("sast: invalid python query: " + err.Error())
	}
	return q
}

type pyRule struct {
	id       string
	severity string
	check    func(root *gts.Node, src []byte, path string) []model.Issue
}

var pyRules = []pyRule{
	{"py-hardcoded-secret", "MEDIUM", checkPyHardcodedSecret},
	{"py-eval-exec", "HIGH", checkPyEvalExec},
	{"py-command-injection", "HIGH", checkPyCommandInjection},
	{"py-sql-injection", "HIGH", checkPySQLInjection},
	{"py-weak-hash", "LOW", checkPyWeakHash},
	{"py-pickle-deserialization", "HIGH", checkPyPickle},
	{"py-yaml-unsafe-load", "MEDIUM", checkPyYAMLUnsafeLoad},
	{"py-insecure-random-for-secrets", "INFO", checkPyInsecureRandom},
	{"py-tls-verify-disabled", "HIGH", checkPyTLSVerifyDisabled},
	{"py-flask-debug-enabled", "MEDIUM", checkPyFlaskDebug},
	{"py-jinja2-autoescape-disabled", "MEDIUM", checkPyJinja2Autoescape},
}

func pyIssueAt(id, severity, path, title, message string, n *gts.Node) model.Issue {
	return model.Issue{
		Scanner:  "sast",
		RuleID:   id,
		Title:    title,
		Severity: severity,
		File:     path,
		Line:     int(n.StartPoint().Row) + 1,
		Message:  message,
	}
}

// fileImports reports whether the source imports modName, via either
// `import modName` or `from modName import ...`.
func fileImports(root *gts.Node, src []byte, modName string) bool {
	q := fileImportsQuery
	for _, m := range q.ExecuteNode(root, pyLang, src) {
		for _, c := range m.Captures {
			if c.Name == "mod" && string(c.Node.Text(src)) == modName {
				return true
			}
		}
	}
	return false
}

var fileImportsQuery = mustPyQuery(`[
	(import_statement name: (dotted_name (identifier) @mod))
	(import_statement name: (aliased_import name: (dotted_name (identifier) @mod)))
	(import_from_statement module_name: (dotted_name (identifier) @mod))
]`)

// pyIsDynamicString reports whether n (an argument expression) is built at
// runtime — an f-string with interpolation, %-formatting, concatenation, or
// .format(...) — rather than a plain string literal.
func pyIsDynamicString(n *gts.Node, src []byte) bool {
	switch n.Type(pyLang) {
	case "string":
		for _, c := range n.Children() {
			if c.Type(pyLang) == "interpolation" {
				return true
			}
		}
		return false
	case "binary_operator":
		return true // covers both "%s" % x and "a" + x
	case "call":
		fn := n.ChildByFieldName("function", pyLang)
		return fn != nil && fn.Type(pyLang) == "attribute" &&
			string(fn.ChildByFieldName("attribute", pyLang).Text(src)) == "format"
	default:
		return false
	}
}

var secretAssignQuery = mustPyQuery(`(assignment left: (identifier) @name right: (string) @val) @assign`)

func checkPyHardcodedSecret(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range secretAssignQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		name := string(caps["name"].Text(src))
		val := caps["val"]
		if !nameLooksSecret(name) || pyIsDynamicString(val, src) {
			continue
		}
		if len(strings.Trim(string(val.Text(src)), `"'`)) <= 4 {
			continue
		}
		issues = append(issues, pyIssueAt("py-hardcoded-secret", "MEDIUM", path,
			"Hardcoded secret-looking value", "variable "+name+" is assigned a literal string",
			caps["assign"]))
	}
	return issues
}

var evalExecQuery = mustPyQuery(`(call function: (identifier) @fname (#any-of? @fname "eval" "exec")) @call`)

func checkPyEvalExec(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range evalExecQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		fname := string(caps["fname"].Text(src))
		issues = append(issues, pyIssueAt("py-eval-exec", "HIGH", path,
			fname+"() used", fname+"() executes arbitrary code; avoid it on any input that isn't fully trusted",
			caps["call"]))
	}
	return issues
}

var osSystemQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) (#eq? @mod "os") (#eq? @fn "system")) @call`)
var subprocessShellQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) arguments: (argument_list (keyword_argument name: (identifier) @kwname value: (true))) (#eq? @mod "subprocess") (#any-of? @fn "run" "call" "Popen" "check_call" "check_output") (#eq? @kwname "shell")) @call`)

func checkPyCommandInjection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range osSystemQuery.ExecuteNode(root, pyLang, src) {
		issues = append(issues, pyIssueAt("py-command-injection", "HIGH", path,
			"os.system() runs a shell command", "os.system() always invokes a shell; build the command with subprocess and a literal argument list instead",
			capMap(m)["call"]))
	}
	for _, m := range subprocessShellQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		issues = append(issues, pyIssueAt("py-command-injection", "HIGH", path,
			"subprocess call with shell=True", "subprocess."+string(caps["fn"].Text(src))+"(shell=True) invokes a shell; pass the command as an argument list with shell=False (the default) instead",
			caps["call"]))
	}
	return issues
}

var sqlExecuteQuery = mustPyQuery(`(call function: (attribute attribute: (identifier) @meth) arguments: (argument_list . (_) @arg) (#any-of? @meth "execute" "executemany")) @call`)

func checkPySQLInjection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range sqlExecuteQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		if !pyIsDynamicString(caps["arg"], src) {
			continue
		}
		issues = append(issues, pyIssueAt("py-sql-injection", "HIGH", path,
			"SQL query built from a non-literal string",
			string(caps["meth"].Text(src))+" query argument is built via f-string/%/concatenation/.format instead of parameter placeholders",
			caps["call"]))
	}
	return issues
}

var weakHashQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) (#eq? @mod "hashlib") (#any-of? @fn "md5" "sha1")) @call`)

func checkPyWeakHash(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range weakHashQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		fn := string(caps["fn"].Text(src))
		issues = append(issues, pyIssueAt("py-weak-hash", "LOW", path,
			"Weak hash algorithm", "hashlib."+fn+" is cryptographically broken; use hashlib.sha256 or stronger",
			caps["call"]))
	}
	return issues
}

var pickleQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) (#eq? @mod "pickle") (#any-of? @fn "load" "loads")) @call`)

func checkPyPickle(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range pickleQuery.ExecuteNode(root, pyLang, src) {
		issues = append(issues, pyIssueAt("py-pickle-deserialization", "HIGH", path,
			"Insecure deserialization via pickle", "pickle.load(s) can execute arbitrary code when deserializing untrusted data",
			capMap(m)["call"]))
	}
	return issues
}

var yamlLoadQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) arguments: (argument_list) @args (#eq? @mod "yaml") (#eq? @fn "load")) @call`)

var safeYAMLLoaders = map[string]bool{"SafeLoader": true, "CSafeLoader": true}

func checkPyYAMLUnsafeLoad(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range yamlLoadQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		safe := false
		for _, c := range caps["args"].Children() {
			if c.Type(pyLang) != "keyword_argument" {
				continue
			}
			if string(c.ChildByFieldName("name", pyLang).Text(src)) != "Loader" {
				continue
			}
			val := c.ChildByFieldName("value", pyLang)
			name := string(val.Text(src))
			name = name[strings.LastIndex(name, ".")+1:]
			safe = safeYAMLLoaders[name]
		}
		if safe {
			continue
		}
		issues = append(issues, pyIssueAt("py-yaml-unsafe-load", "MEDIUM", path,
			"yaml.load without a safe Loader", "yaml.load(...) without Loader=yaml.SafeLoader can construct arbitrary Python objects from untrusted YAML",
			caps["call"]))
	}
	return issues
}

var randomCallQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod)  (#eq? @mod "random")) @call`)
var funcDefQuery = mustPyQuery(`(function_definition name: (identifier) @fname body: (block) @body) @def`)

func checkPyInsecureRandom(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range funcDefQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		fname := string(caps["fname"].Text(src))
		if !nameLooksSecret(fname) && !strings.Contains(strings.ToLower(fname), "session") {
			continue
		}
		for _, rm := range randomCallQuery.ExecuteNode(caps["body"], pyLang, src) {
			issues = append(issues, pyIssueAt("py-insecure-random-for-secrets", "INFO", path,
				"random module used in a security-sounding function",
				"function "+fname+" uses the random module, which is not cryptographically secure; consider the secrets module",
				capMap(rm)["call"]))
		}
	}
	return issues
}

var requestsVerifyQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod) arguments: (argument_list (keyword_argument name: (identifier) @kwname value: (false))) (#eq? @mod "requests") (#eq? @kwname "verify")) @call`)
var sslUnverifiedQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) (#eq? @mod "ssl") (#eq? @fn "_create_unverified_context")) @call`)

func checkPyTLSVerifyDisabled(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range requestsVerifyQuery.ExecuteNode(root, pyLang, src) {
		issues = append(issues, pyIssueAt("py-tls-verify-disabled", "HIGH", path,
			"TLS certificate verification disabled", "requests call with verify=False disables certificate validation",
			capMap(m)["call"]))
	}
	for _, m := range sslUnverifiedQuery.ExecuteNode(root, pyLang, src) {
		issues = append(issues, pyIssueAt("py-tls-verify-disabled", "HIGH", path,
			"TLS certificate verification disabled", "ssl._create_unverified_context() disables certificate validation",
			capMap(m)["call"]))
	}
	return issues
}

var flaskRunDebugQuery = mustPyQuery(`(call function: (attribute attribute: (identifier) @meth) arguments: (argument_list (keyword_argument name: (identifier) @kwname value: (true))) (#eq? @meth "run") (#eq? @kwname "debug")) @call`)

func checkPyFlaskDebug(root *gts.Node, src []byte, path string) []model.Issue {
	if !fileImports(root, src, "flask") {
		return nil
	}
	var issues []model.Issue
	for _, m := range flaskRunDebugQuery.ExecuteNode(root, pyLang, src) {
		issues = append(issues, pyIssueAt("py-flask-debug-enabled", "MEDIUM", path,
			"Flask debug mode enabled", "app.run(debug=True) exposes the Werkzeug interactive debugger, which allows remote code execution if reachable",
			capMap(m)["call"]))
	}
	return issues
}

var jinja2EnvQuery = mustPyQuery(`(call function: (identifier) @fname arguments: (argument_list (keyword_argument name: (identifier) @kwname value: (false))) (#eq? @fname "Environment") (#eq? @kwname "autoescape")) @call`)

func checkPyJinja2Autoescape(root *gts.Node, src []byte, path string) []model.Issue {
	if !fileImports(root, src, "jinja2") {
		return nil
	}
	var issues []model.Issue
	for _, m := range jinja2EnvQuery.ExecuteNode(root, pyLang, src) {
		issues = append(issues, pyIssueAt("py-jinja2-autoescape-disabled", "MEDIUM", path,
			"Jinja2 autoescape disabled", "Environment(autoescape=False) disables automatic HTML escaping, opening the door to XSS",
			capMap(m)["call"]))
	}
	return issues
}

func capMap(m gts.QueryMatch) map[string]*gts.Node {
	out := make(map[string]*gts.Node, len(m.Captures))
	for _, c := range m.Captures {
		out[c.Name] = c.Node
	}
	return out
}
