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
	{"py-weak-cipher", "MEDIUM", checkPyWeakCipher},
	{"py-pickle-deserialization", "HIGH", checkPyPickle},
	{"py-yaml-unsafe-load", "MEDIUM", checkPyYAMLUnsafeLoad},
	{"py-insecure-random-for-secrets", "INFO", checkPyInsecureRandom},
	{"py-tls-verify-disabled", "HIGH", checkPyTLSVerifyDisabled},
	{"py-flask-debug-enabled", "MEDIUM", checkPyFlaskDebug},
	{"py-jinja2-autoescape-disabled", "MEDIUM", checkPyJinja2Autoescape},
	{"py-open-redirect", "MEDIUM", checkPyOpenRedirect},
	{"py-jwt-verify-disabled", "HIGH", checkPyJWTVerifyDisabled},
	{"py-cors-wildcard", "MEDIUM", checkPyCORSWildcard},
	{"py-insecure-cookie", "MEDIUM", checkPyInsecureCookie},
	{"py-path-traversal", "HIGH", checkPyPathTraversal},
	{"py-cookie-missing-flags", "LOW", checkPyCookieMissingFlags},
	{"py-ssrf", "HIGH", checkPySSRF},
	{"py-xxe", "HIGH", checkPyXXE},
	{"py-ssti", "HIGH", checkPySSTI},
	{"py-nosqli", "HIGH", checkPyNoSQLi},
	{"py-insecure-tempfile", "MEDIUM", checkPyInsecureTempfile},
	{"py-unsafe-reflection", "HIGH", checkPyUnsafeReflection},
	{"py-predictable-prng-seed", "MEDIUM", checkPyPredictablePRNGSeed},
	{"py-agent-unsandboxed-exec", "HIGH", checkPyAgentUnsandboxedExec},
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

var (
	osSystemQuery        = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) (#eq? @mod "os") (#any-of? @fn "system" "popen")) @call`)
	subprocessShellQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) arguments: (argument_list (keyword_argument name: (identifier) @kwname value: (true))) (#eq? @mod "subprocess") (#any-of? @fn "run" "call" "Popen" "check_call" "check_output") (#eq? @kwname "shell")) @call`)
)

func checkPyCommandInjection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range osSystemQuery.ExecuteNode(root, pyLang, src) {
		fn := string(capMap(m)["fn"].Text(src))
		issues = append(issues, pyIssueAt("py-command-injection", "HIGH", path,
			"os."+fn+"() runs a shell command", "os."+fn+"() always invokes a shell; build the command with subprocess and a literal argument list instead",
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
		if !pyIsDynamicString(caps["arg"], src) && !pyTaintedArg(caps["arg"], src) {
			continue
		}
		issues = append(issues, pyIssueAt("py-sql-injection", "HIGH", path,
			"SQL query built from a non-literal string",
			string(caps["meth"].Text(src))+" query argument is built via f-string/%/concatenation/.format instead of parameter placeholders, or is a local variable derived from request/env input",
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

var (
	weakCipherClassQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) (#any-of? @mod "DES" "DES3" "ARC4" "Blowfish") (#eq? @fn "new")) @call`)
	weakCipherModeQuery  = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) arguments: (argument_list . (_) . (attribute attribute: (identifier) @mode)) (#eq? @fn "new") (#eq? @mode "MODE_ECB")) @call`)
)

// checkPyWeakCipher covers pycryptodome/PyCrypto's two independent ways to
// end up with a broken cipher: constructing an inherently weak cipher class
// (DES/DES3/ARC4/Blowfish — same name-list signal as go/java-weak-cipher),
// or constructing any cipher (including AES) in ECB mode, which leaks
// plaintext structure regardless of key strength. A call already flagged by
// the class check is skipped by the mode check so DES.new(key, DES.MODE_ECB)
// reports once, not twice.
func checkPyWeakCipher(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	weakClasses := map[string]bool{}
	for _, m := range weakCipherClassQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		mod := string(caps["mod"].Text(src))
		weakClasses[string(caps["call"].Text(src))] = true
		issues = append(issues, pyIssueAt("py-weak-cipher", "MEDIUM", path,
			"Weak cipher algorithm", mod+".new(...) is a broken cipher; use AES in GCM mode instead",
			caps["call"]))
	}
	for _, m := range weakCipherModeQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		call := string(caps["call"].Text(src))
		if weakClasses[call] {
			continue // already reported above for the cipher class itself
		}
		issues = append(issues, pyIssueAt("py-weak-cipher", "MEDIUM", path,
			"Insecure cipher mode (ECB)", string(caps["mod"].Text(src))+".new(..., "+string(caps["mod"].Text(src))+".MODE_ECB) leaks plaintext structure; use MODE_GCM instead",
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

var (
	randomCallQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod)  (#eq? @mod "random")) @call`)
	funcDefQuery    = mustPyQuery(`(function_definition name: (identifier) @fname body: (block) @body) @def`)
)

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

var (
	requestsVerifyQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod) arguments: (argument_list (keyword_argument name: (identifier) @kwname value: (false))) (#eq? @mod "requests") (#eq? @kwname "verify")) @call`)
	sslUnverifiedQuery  = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) (#eq? @mod "ssl") (#eq? @fn "_create_unverified_context")) @call`)
)

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

var pyFuncBoundary = map[string]bool{"function_definition": true, "lambda": true}

func pyAssignInfo(n *gts.Node, lang *gts.Language, src []byte) (string, *gts.Node, bool) {
	if n.Type(pyLang) != "assignment" {
		return "", nil, false
	}
	left := n.ChildByFieldName("left", pyLang)
	right := n.ChildByFieldName("right", pyLang)
	if left == nil || right == nil || left.Type(pyLang) != "identifier" {
		return "", nil, false
	}
	return string(left.Text(src)), right, true
}

// pyIsEnvSource matches os.getenv(...)/os.environ.get(...)/os.environ[...]
// by raw text rather than decomposing the call shape — cheap and good
// enough for a single-node source check.
func pyIsEnvSource(n *gts.Node, src []byte) bool {
	text := string(n.Text(src))
	return strings.HasPrefix(text, "os.getenv(") || strings.HasPrefix(text, "os.environ.get(") || strings.HasPrefix(text, "os.environ[")
}

// pyExprTainted reports whether n evaluates from tainted input: rooted at
// request (pyRootedAtRequest), an env-var read, a variable already
// known-tainted in env, or built from any of those via binary_operator
// (%/+ formatting) or a call's arguments.
func pyExprTainted(n *gts.Node, lang *gts.Language, src []byte, env map[string]bool) bool {
	if n == nil {
		return false
	}
	if pyRootedAtRequest(n, src) || pyIsEnvSource(n, src) {
		return true
	}
	switch n.Type(pyLang) {
	case "identifier":
		return env[string(n.Text(src))]
	case "binary_operator":
		return pyExprTainted(n.ChildByFieldName("left", pyLang), lang, src, env) || pyExprTainted(n.ChildByFieldName("right", pyLang), lang, src, env)
	case "call":
		args := n.ChildByFieldName("arguments", pyLang)
		if args == nil {
			return false
		}
		for _, a := range args.Children() {
			if pyExprTainted(a, lang, src, env) {
				return true
			}
		}
		return false
	case "parenthesized_expression":
		if n.NamedChildCount() > 0 {
			return pyExprTainted(n.NamedChild(0), lang, src, env)
		}
		return false
	default:
		return false
	}
}

// pyTaintedArg reports whether arg evaluates from tainted input, tracking
// through local variable assignments within its enclosing function/lambda
// (intraprocedural taint tracking — see taint_ts.go).
func pyTaintedArg(arg *gts.Node, src []byte) bool {
	body := tsEnclosingBody(arg, pyLang, pyFuncBoundary)
	env := tsTaintEnv(body, pyLang, src, pyFuncBoundary, pyAssignInfo, pyExprTainted)
	return pyExprTainted(arg, pyLang, src, env)
}

func pyRootedAtRequest(n *gts.Node, src []byte) bool {
	for {
		switch n.Type(pyLang) {
		case "attribute":
			n = n.ChildByFieldName("object", pyLang)
		case "call":
			n = n.ChildByFieldName("function", pyLang)
		case "subscript":
			n = n.ChildByFieldName("value", pyLang)
		case "identifier":
			return string(n.Text(src)) == "request"
		default:
			return false
		}
		if n == nil {
			return false
		}
	}
}

var pyRedirectCallQuery = mustPyQuery(`(call function: (identifier) @fname arguments: (argument_list . (_) @arg) (#eq? @fname "redirect")) @call`)

func checkPyOpenRedirect(root *gts.Node, src []byte, path string) []model.Issue {
	if !fileImports(root, src, "flask") {
		return nil
	}
	var issues []model.Issue
	for _, m := range pyRedirectCallQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		arg := caps["arg"]
		if !pyIsDynamicString(arg, src) && !pyTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, pyIssueAt("py-open-redirect", "MEDIUM", path,
			"Redirect target built from request data", "redirect(...) argument is derived from request input (directly, or through a local variable) rather than a literal/allowlisted URL",
			caps["call"]))
	}
	return issues
}

var pyJWTVerifyFalseQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) arguments: (argument_list (keyword_argument name: (identifier) @kwname value: (false))) (#eq? @mod "jwt") (#eq? @fn "decode") (#eq? @kwname "verify")) @call`)

func checkPyJWTVerifyDisabled(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range pyJWTVerifyFalseQuery.ExecuteNode(root, pyLang, src) {
		issues = append(issues, pyIssueAt("py-jwt-verify-disabled", "HIGH", path,
			"JWT signature verification disabled", "jwt.decode(..., verify=False) accepts tokens with any/no signature, allowing forgery",
			capMap(m)["call"]))
	}
	return issues
}

var pySubscriptAssignQuery = mustPyQuery(`(assignment left: (subscript subscript: (string) @key) right: (string) @val) @assign`)

func checkPyCORSWildcard(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range pySubscriptAssignQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		key := strings.Trim(string(caps["key"].Text(src)), `"'`)
		val := strings.Trim(string(caps["val"].Text(src)), `"'`)
		if !strings.EqualFold(key, "Access-Control-Allow-Origin") || val != "*" {
			continue
		}
		issues = append(issues, pyIssueAt("py-cors-wildcard", "MEDIUM", path,
			"CORS allow-origin set to wildcard", "headers['Access-Control-Allow-Origin'] = '*' allows any origin to make credentialed cross-origin requests",
			caps["assign"]))
	}
	return issues
}

var pyCookieFalseQuery = mustPyQuery(`(call function: (attribute attribute: (identifier) @meth) arguments: (argument_list (keyword_argument name: (identifier) @kwname value: (false))) (#eq? @meth "set_cookie") (#any-of? @kwname "secure" "httponly")) @call`)

func checkPyInsecureCookie(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range pyCookieFalseQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		kw := string(caps["kwname"].Text(src))
		issues = append(issues, pyIssueAt("py-insecure-cookie", "MEDIUM", path,
			"Cookie flag explicitly disabled", "set_cookie(..., "+kw+"=False) weakens cookie protection",
			caps["call"]))
	}
	return issues
}

var pyOpenCallQuery = mustPyQuery(`(call function: (identifier) @fname arguments: (argument_list . (_) @arg) (#eq? @fname "open")) @call`)

func checkPyPathTraversal(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range pyOpenCallQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		arg := caps["arg"]
		if !pyIsDynamicString(arg, src) && !pyTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, pyIssueAt("py-path-traversal", "HIGH", path,
			"File path built from request data", "open(...) path is derived from request input (directly, or through a local variable) or built via f-string/%/concatenation/.format rather than a validated literal; sanitize/allowlist before use",
			caps["call"]))
	}
	return issues
}

var requestsSSRFQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) arguments: (argument_list . (_) @arg) (#eq? @mod "requests") (#any-of? @fn "get" "post" "put" "delete" "head" "patch")) @call`)

func checkPySSRF(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range requestsSSRFQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		arg := caps["arg"]
		if !pyIsDynamicString(arg, src) && !pyTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, pyIssueAt("py-ssrf", "HIGH", path,
			"Outbound request URL built from request data",
			"requests."+string(caps["fn"].Text(src))+"(...) URL argument is derived from request/env input (directly, or through a local variable) or built via f-string/%/concatenation/.format rather than a validated/allowlisted URL",
			caps["call"]))
	}
	return issues
}

var lxmlResolveEntitiesQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) arguments: (argument_list (keyword_argument name: (identifier) @kwname value: (true))) (#eq? @mod "etree") (#eq? @fn "XMLParser") (#eq? @kwname "resolve_entities")) @call`)

func checkPyXXE(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range lxmlResolveEntitiesQuery.ExecuteNode(root, pyLang, src) {
		issues = append(issues, pyIssueAt("py-xxe", "HIGH", path,
			"XML entity resolution explicitly enabled", "lxml.etree.XMLParser(resolve_entities=True) allows external/internal entity expansion, enabling XXE and entity-expansion DoS when parsing untrusted XML",
			capMap(m)["call"]))
	}
	return issues
}

var pyRenderTemplateStringQuery = mustPyQuery(`(call function: (identifier) @fname arguments: (argument_list . (_) @arg) (#eq? @fname "render_template_string")) @call`)

func checkPySSTI(root *gts.Node, src []byte, path string) []model.Issue {
	if !fileImports(root, src, "flask") {
		return nil
	}
	var issues []model.Issue
	for _, m := range pyRenderTemplateStringQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		arg := caps["arg"]
		if !pyIsDynamicString(arg, src) && !pyTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, pyIssueAt("py-ssti", "HIGH", path,
			"Template source built from request data",
			"render_template_string(...) argument is derived from request/env input (directly, or through a local variable) or built via f-string/%/concatenation/.format — the template source itself is attacker-controlled, which is server-side template injection, not just a data-substitution issue",
			caps["call"]))
	}
	return issues
}

var pyMongoQueryCallQuery = mustPyQuery(`(call function: (attribute attribute: (identifier) @meth) arguments: (argument_list . (_) @arg) (#any-of? @meth "find" "find_one" "find_one_and_update" "find_one_and_delete" "update_one" "update_many" "delete_one" "delete_many")) @call`)

// checkPyNoSQLi flags a pymongo query/update/delete call whose filter
// argument is entirely request/env-derived, not a literal filter with
// individually-typed fields — a different shape from SQL injection
// (there's no string concatenation to point at; the whole filter object
// being attacker-controlled is what lets operators like $ne/$gt through).
func checkPyNoSQLi(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range pyMongoQueryCallQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		arg := caps["arg"]
		if !pyTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, pyIssueAt("py-nosqli", "HIGH", path,
			"MongoDB query filter built entirely from request data",
			string(caps["meth"].Text(src))+"(...) filter argument is derived from request/env input rather than a literal filter with individually-typed fields — passing the whole request payload as a MongoDB filter lets an attacker inject query operators (e.g. $ne, $gt) to bypass intended matching",
			caps["call"]))
	}
	return issues
}

var pyMktempQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) (#eq? @mod "tempfile") (#eq? @fn "mktemp")) @call`)

// checkPyInsecureTempfile flags tempfile.mktemp() unconditionally: it
// returns a predictable, not-yet-created filename with no safe usage —
// that's exactly why Python's own docs deprecate it in favor of
// NamedTemporaryFile()/mkstemp(), which atomically create the file.
func checkPyInsecureTempfile(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range pyMktempQuery.ExecuteNode(root, pyLang, src) {
		issues = append(issues, pyIssueAt("py-insecure-tempfile", "MEDIUM", path,
			"Insecure temporary file name", "tempfile.mktemp() returns a predictable, not-yet-created filename — a race condition (TOCTOU) lets another process create/symlink the same path first; use tempfile.NamedTemporaryFile()/mkstemp() instead",
			capMap(m)["call"]))
	}
	return issues
}

var pyImportModuleQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) arguments: (argument_list . (_) @arg) (#eq? @mod "importlib") (#eq? @fn "import_module")) @call`)

// checkPyUnsafeReflection flags importlib.import_module(...) when the
// module-name argument is itself tainted (request/env-derived, directly or
// through a local variable) — not gated on pyIsDynamicString: dynamic
// (but non-attacker-controlled) module names are a normal plugin-loading
// idiom, same reasoning as the other *-unsafe-reflection rules.
func checkPyUnsafeReflection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range pyImportModuleQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		arg := caps["arg"]
		if !pyTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, pyIssueAt("py-unsafe-reflection", "HIGH", path,
			"Module imported by an attacker-controlled name",
			"importlib.import_module(...) argument is derived from request/env input (directly, or through a local variable) — this imports whatever module name an attacker supplies, executing that module's top-level code",
			caps["call"]))
	}
	return issues
}

var pyRandomSeedQuery = mustPyQuery(`(call function: (attribute object: (identifier) @mod attribute: (identifier) @fn) arguments: (argument_list . (integer)) (#eq? @mod "random") (#eq? @fn "seed")) @call`)

// checkPyPredictablePRNGSeed flags random.seed(<literal>) — a fixed seed
// makes every subsequent "random" value fully predictable, regardless of
// what the generator is later used for (distinct from
// py-insecure-random-for-secrets, which flags the module choice, not the
// seed). random.seed() with no args, or seeded from os.urandom()/similar,
// is unaffected — only a literal integer argument matches.
func checkPyPredictablePRNGSeed(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range pyRandomSeedQuery.ExecuteNode(root, pyLang, src) {
		issues = append(issues, pyIssueAt("py-predictable-prng-seed", "MEDIUM", path,
			"PRNG seeded with a hardcoded literal",
			"random.seed(...) is called with a compile-time integer literal; every run produces the same sequence, making all subsequent output predictable",
			capMap(m)["call"]))
	}
	return issues
}

var pySetCookieCallQuery = mustPyQuery(`(call function: (attribute attribute: (identifier) @meth) arguments: (argument_list) @args (#eq? @meth "set_cookie")) @call`)

func checkPyCookieMissingFlags(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range pySetCookieCallQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		has := map[string]bool{}
		for _, c := range caps["args"].Children() {
			if c.Type(pyLang) != "keyword_argument" {
				continue
			}
			name := c.ChildByFieldName("name", pyLang)
			if name != nil {
				has[strings.ToLower(string(name.Text(src)))] = true
			}
		}
		for _, flag := range []string{"secure", "httponly"} {
			if has[flag] {
				continue
			}
			issues = append(issues, pyIssueAt("py-cookie-missing-flags", "LOW", path,
				flag+" not set on set_cookie", "set_cookie(...) doesn't pass "+flag+"=...; it defaults to False, weakening cookie protection unless set elsewhere",
				caps["call"]))
		}
	}
	return issues
}

// pyAgentToolClasses are LangChain/AutoGen/CrewAI-style tools whose .run()
// executes their argument as code or a shell command with no sandbox --
// LangChain's own docs call several of these "unsafe" for exactly this
// reason. Curated by name since there's no import to gate on that would be
// reliable across langchain/langchain_community/langchain_experimental's
// churn between releases.
var pyAgentToolClasses = map[string]bool{
	"PythonREPLTool": true, "PythonAstREPLTool": true, "ShellTool": true,
	"BashProcess": true, "CodeInterpreterTool": true, "LocalCommandLineCodeExecutor": true,
}

// pyIsAgentToolConstructor matches both `PythonREPLTool().run(...)` directly
// and a variable previously assigned from one of pyAgentToolClasses'
// constructors -- same env-threading shape as pyExprTainted, just tracking
// "constructed from a dangerous class" instead of "tainted".
func pyIsAgentToolConstructor(n *gts.Node, lang *gts.Language, src []byte, env map[string]bool) bool {
	if n == nil {
		return false
	}
	switch n.Type(pyLang) {
	case "identifier":
		return env[string(n.Text(src))]
	case "call":
		fn := n.ChildByFieldName("function", pyLang)
		if fn == nil {
			return false
		}
		if fn.Type(pyLang) == "attribute" {
			fn = fn.ChildByFieldName("attribute", pyLang)
		}
		return pyAgentToolClasses[string(fn.Text(src))]
	default:
		return false
	}
}

var agentToolRunQuery = mustPyQuery(`(call function: (attribute object: (_) @obj attribute: (identifier) @meth) arguments: (argument_list . (_) @arg) (#any-of? @meth "run" "arun")) @call`)

func checkPyAgentUnsandboxedExec(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range agentToolRunQuery.ExecuteNode(root, pyLang, src) {
		caps := capMap(m)
		obj, arg := caps["obj"], caps["arg"]

		body := tsEnclosingBody(obj, pyLang, pyFuncBoundary)
		toolEnv := tsTaintEnv(body, pyLang, src, pyFuncBoundary, pyAssignInfo, pyIsAgentToolConstructor)
		if !pyIsAgentToolConstructor(obj, pyLang, src, toolEnv) {
			continue
		}
		if !pyIsDynamicString(arg, src) && !pyTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, pyIssueAt("py-agent-unsandboxed-exec", "HIGH", path,
			"Agent tool executes untrusted input with no sandbox",
			string(obj.Text(src))+"."+string(caps["meth"].Text(src))+"(...) runs the argument as code/a shell command; it traces back to request/env input with no sandboxing or allowlist in between",
			caps["call"]))
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
