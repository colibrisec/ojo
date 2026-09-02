package sast

import (
	"strings"

	gts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"

	"github.com/colibrisec/ojo/internal/model"
)

var javaLang = grammars.JavaLanguage()

func mustJavaQuery(src string) *gts.Query {
	q, err := gts.NewQuery(src, javaLang)
	if err != nil {
		panic("sast: invalid java query: " + err.Error())
	}
	return q
}

type javaRule struct {
	id       string
	severity string
	check    func(root *gts.Node, src []byte, path string) []model.Issue
}

var javaRules = []javaRule{
	{"java-hardcoded-secret", "MEDIUM", checkJavaHardcodedSecret},
	{"java-command-injection", "HIGH", checkJavaCommandInjection},
	{"java-sql-injection", "HIGH", checkJavaSQLInjection},
	{"java-weak-hash", "LOW", checkJavaWeakHash},
	{"java-weak-cipher", "MEDIUM", checkJavaWeakCipher},
	{"java-insecure-deserialization", "HIGH", checkJavaInsecureDeserialization},
	{"java-insecure-random-for-secrets", "INFO", checkJavaInsecureRandom},
	{"java-tls-trust-manager-bypass", "HIGH", checkJavaTLSTrustManagerBypass},
	{"java-xxe", "HIGH", checkJavaXXE},
	{"java-open-redirect", "MEDIUM", checkJavaOpenRedirect},
	{"java-cors-wildcard", "MEDIUM", checkJavaCORSWildcard},
	{"java-insecure-cookie", "MEDIUM", checkJavaInsecureCookie},
	{"java-path-traversal", "HIGH", checkJavaPathTraversal},
	{"java-cookie-missing-flags", "LOW", checkJavaCookieMissingFlags},
	{"java-ssrf", "HIGH", checkJavaSSRF},
	{"java-yaml-unsafe-load", "HIGH", checkJavaYAMLUnsafeLoad},
	{"java-eval-detected", "HIGH", checkJavaEvalDetected},
	{"java-unsafe-reflection", "HIGH", checkJavaUnsafeReflection},
	{"java-predictable-prng-seed", "MEDIUM", checkJavaPredictablePRNGSeed},
	{"java-jwt-none-algorithm", "HIGH", checkJavaJWTNoneAlgorithm},
}

func javaIssueAt(id, severity, path, title, message string, n *gts.Node) model.Issue {
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

func javaIsDynamicString(n *gts.Node, src []byte) bool {
	if n.Type(javaLang) != "binary_expression" {
		return false
	}
	op := n.ChildByFieldName("operator", javaLang)
	return op != nil && string(op.Text(src)) == "+"
}

func trimJavaQuotes(s string) string {
	if len(s) >= 2 {
		return s[1 : len(s)-1]
	}
	return s
}

var javaSecretAssignQuery = mustJavaQuery(`(variable_declarator name: (identifier) @name value: (string_literal) @val) @decl`)

func checkJavaHardcodedSecret(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaSecretAssignQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		name := string(caps["name"].Text(src))
		val := caps["val"]
		if !nameLooksSecret(name) {
			continue
		}
		if len(trimJavaQuotes(string(val.Text(src)))) <= 4 {
			continue
		}
		issues = append(issues, javaIssueAt("java-hardcoded-secret", "MEDIUM", path,
			"Hardcoded secret-looking value", "variable "+name+" is assigned a literal string",
			caps["decl"]))
	}
	return issues
}

var (
	javaRuntimeExecQuery    = mustJavaQuery(`(method_invocation object: (method_invocation object: (identifier) @cls name: (identifier) @m1) name: (identifier) @m2 arguments: (argument_list . (_) @arg) (#eq? @cls "Runtime") (#eq? @m1 "getRuntime") (#eq? @m2 "exec")) @call`)
	javaProcessBuilderQuery = mustJavaQuery(`(object_creation_expression type: (type_identifier) @cls arguments: (argument_list . (_) @arg) (#eq? @cls "ProcessBuilder")) @call`)
)

func checkJavaCommandInjection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaRuntimeExecQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		if !javaIsDynamicString(caps["arg"], src) && !javaTaintedArg(caps["arg"], src) {
			continue
		}
		issues = append(issues, javaIssueAt("java-command-injection", "HIGH", path,
			"Command built from a non-literal argument",
			"Runtime.getRuntime().exec(...) argument is built via `+` concatenation instead of a literal/argument array, or is a local variable derived from request/env input",
			caps["call"]))
	}
	for _, m := range javaProcessBuilderQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		if !javaIsDynamicString(caps["arg"], src) && !javaTaintedArg(caps["arg"], src) {
			continue
		}
		issues = append(issues, javaIssueAt("java-command-injection", "HIGH", path,
			"Command built from a non-literal argument",
			"new ProcessBuilder(...) argument is built via `+` concatenation instead of a literal/argument array, or is a local variable derived from request/env input",
			caps["call"]))
	}
	return issues
}

var javaStatementExecuteQuery = mustJavaQuery(`(method_invocation name: (identifier) @m arguments: (argument_list . (_) @arg) (#any-of? @m "execute" "executeQuery" "executeUpdate")) @call`)

func checkJavaSQLInjection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaStatementExecuteQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		if !javaIsDynamicString(caps["arg"], src) && !javaTaintedArg(caps["arg"], src) {
			continue
		}
		issues = append(issues, javaIssueAt("java-sql-injection", "HIGH", path,
			"SQL query built from a non-literal string",
			string(caps["m"].Text(src))+"(...) query argument is built via `+` concatenation instead of a PreparedStatement placeholder, or is a local variable derived from request/env input",
			caps["call"]))
	}
	return issues
}

var javaMessageDigestQuery = mustJavaQuery(`(method_invocation object: (identifier) @cls name: (identifier) @m arguments: (argument_list (string_literal (string_fragment) @alg)) (#eq? @cls "MessageDigest") (#eq? @m "getInstance")) @call`)

func checkJavaWeakHash(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaMessageDigestQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		alg := string(caps["alg"].Text(src))
		if alg != "MD5" && alg != "SHA1" && alg != "SHA-1" {
			continue
		}
		issues = append(issues, javaIssueAt("java-weak-hash", "LOW", path,
			"Weak hash algorithm", "MessageDigest.getInstance(\""+alg+"\") is cryptographically broken; use \"SHA-256\" or stronger",
			caps["call"]))
	}
	return issues
}

var javaCipherQuery = mustJavaQuery(`(method_invocation object: (identifier) @cls name: (identifier) @m arguments: (argument_list (string_literal (string_fragment) @alg)) (#eq? @cls "Cipher") (#eq? @m "getInstance")) @call`)

func checkJavaWeakCipher(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaCipherQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		alg := string(caps["alg"].Text(src))
		upper := strings.ToUpper(alg)
		if !strings.Contains(upper, "DES") && !strings.Contains(upper, "RC4") && !strings.Contains(upper, "ECB") {
			continue
		}
		issues = append(issues, javaIssueAt("java-weak-cipher", "MEDIUM", path,
			"Weak cipher or insecure mode", "Cipher.getInstance(\""+alg+"\") uses a broken cipher or an insecure mode (ECB); use AES/GCM/NoPadding",
			caps["call"]))
	}
	return issues
}

var javaReadObjectQuery = mustJavaQuery(`(method_invocation name: (identifier) @m (#eq? @m "readObject")) @call`)

func checkJavaInsecureDeserialization(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaReadObjectQuery.ExecuteNode(root, javaLang, src) {
		issues = append(issues, javaIssueAt("java-insecure-deserialization", "HIGH", path,
			"Insecure deserialization via readObject", "ObjectInputStream#readObject can instantiate arbitrary classes and execute code when given untrusted data",
			javaCapMap(m)["call"]))
	}
	return issues
}

var (
	javaRandomNewQuery = mustJavaQuery(`(object_creation_expression type: (type_identifier) @t (#eq? @t "Random")) @call`)
	javaMethodDefQuery = mustJavaQuery(`(method_declaration name: (identifier) @fname body: (block) @body) @def`)
)

func checkJavaInsecureRandom(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaMethodDefQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		fname := string(caps["fname"].Text(src))
		if !nameLooksSecret(fname) && !strings.Contains(strings.ToLower(fname), "session") {
			continue
		}
		for _, rm := range javaRandomNewQuery.ExecuteNode(caps["body"], javaLang, src) {
			issues = append(issues, javaIssueAt("java-insecure-random-for-secrets", "INFO", path,
				"java.util.Random used in a security-sounding method",
				"method "+fname+" uses java.util.Random, which is not cryptographically secure; consider java.security.SecureRandom",
				javaCapMap(rm)["call"]))
		}
	}
	return issues
}

var javaTrustManagerQuery = mustJavaQuery(`(object_creation_expression type: (type_identifier) @t (#any-of? @t "X509TrustManager" "HostnameVerifier")) @call`)

func checkJavaTLSTrustManagerBypass(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaTrustManagerQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		t := string(caps["t"].Text(src))
		issues = append(issues, javaIssueAt("java-tls-trust-manager-bypass", "HIGH", path,
			"Custom "+t+" implementation", "a custom "+t+" can silently disable TLS certificate/hostname validation; verify it doesn't just return true/accept everything",
			caps["call"]))
	}
	return issues
}

var javaXXEFactoryQuery = mustJavaQuery(`(method_invocation object: (identifier) @cls name: (identifier) @m (#any-of? @cls "DocumentBuilderFactory" "SAXParserFactory" "XMLInputFactory") (#eq? @m "newInstance")) @call`)

func checkJavaXXE(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaXXEFactoryQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		cls := string(caps["cls"].Text(src))
		issues = append(issues, javaIssueAt("java-xxe", "HIGH", path,
			cls+" created without hardening", cls+".newInstance() is vulnerable to XXE by default unless external entity/DTD processing is explicitly disabled",
			caps["call"]))
	}
	return issues
}

var javaFuncBoundary = map[string]bool{"method_declaration": true, "constructor_declaration": true, "lambda_expression": true}

func javaAssignInfo(n *gts.Node, lang *gts.Language, src []byte) (string, *gts.Node, bool) {
	switch n.Type(javaLang) {
	case "variable_declarator":
		name := n.ChildByFieldName("name", javaLang)
		val := n.ChildByFieldName("value", javaLang)
		if name == nil || val == nil || name.Type(javaLang) != "identifier" {
			return "", nil, false
		}
		return string(name.Text(src)), val, true
	case "assignment_expression":
		left := n.ChildByFieldName("left", javaLang)
		right := n.ChildByFieldName("right", javaLang)
		if left == nil || right == nil || left.Type(javaLang) != "identifier" {
			return "", nil, false
		}
		return string(left.Text(src)), right, true
	default:
		return "", nil, false
	}
}

// javaIsEnvSource matches System.getenv(...) by raw text.
func javaIsEnvSource(n *gts.Node, src []byte) bool {
	return strings.HasPrefix(string(n.Text(src)), "System.getenv(")
}

// javaExprTainted reports whether n evaluates from tainted input: rooted
// at request/req (javaRootedAtRequest), an env-var read, a variable
// already known-tainted in env, or built from any of those via `+`
// concatenation or a method call's arguments.
func javaExprTainted(n *gts.Node, lang *gts.Language, src []byte, env map[string]bool) bool {
	if n == nil {
		return false
	}
	if javaRootedAtRequest(n, src) || javaIsEnvSource(n, src) {
		return true
	}
	switch n.Type(javaLang) {
	case "identifier":
		return env[string(n.Text(src))]
	case "binary_expression":
		op := n.ChildByFieldName("operator", javaLang)
		if op == nil || string(op.Text(src)) != "+" {
			return false
		}
		return javaExprTainted(n.ChildByFieldName("left", javaLang), lang, src, env) || javaExprTainted(n.ChildByFieldName("right", javaLang), lang, src, env)
	case "method_invocation":
		args := n.ChildByFieldName("arguments", javaLang)
		if args == nil {
			return false
		}
		for _, a := range args.Children() {
			if javaExprTainted(a, lang, src, env) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// javaTaintedArg reports whether arg evaluates from tainted input, tracking
// through local variable assignments within its enclosing method/
// constructor/lambda (intraprocedural taint tracking — see taint_ts.go).
func javaTaintedArg(arg *gts.Node, src []byte) bool {
	body := tsEnclosingBody(arg, javaLang, javaFuncBoundary)
	env := tsTaintEnv(body, javaLang, src, javaFuncBoundary, javaAssignInfo, javaExprTainted)
	return javaExprTainted(arg, javaLang, src, env)
}

func javaRootedAtRequest(n *gts.Node, src []byte) bool {
	for {
		switch n.Type(javaLang) {
		case "method_invocation", "field_access":
			obj := n.ChildByFieldName("object", javaLang)
			if obj == nil {
				return false
			}
			n = obj
		case "identifier":
			name := strings.ToLower(string(n.Text(src)))
			return name == "request" || name == "req"
		default:
			return false
		}
	}
}

var javaSendRedirectQuery = mustJavaQuery(`(method_invocation name: (identifier) @m arguments: (argument_list . (_) @arg) (#eq? @m "sendRedirect")) @call`)

func checkJavaOpenRedirect(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaSendRedirectQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		arg := caps["arg"]
		if !javaIsDynamicString(arg, src) && !javaTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, javaIssueAt("java-open-redirect", "MEDIUM", path,
			"Redirect target built from request data",
			"sendRedirect(...) argument is derived from request input (directly, or through a local variable) or built via `+` concatenation rather than a literal/allowlisted URL",
			caps["call"]))
	}
	return issues
}

var javaHeaderCallQuery = mustJavaQuery(`(method_invocation name: (identifier) @m arguments: (argument_list . (string_literal) @key . (string_literal) @val) (#any-of? @m "setHeader" "addHeader")) @call`)

func checkJavaCORSWildcard(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaHeaderCallQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		key := trimJavaQuotes(string(caps["key"].Text(src)))
		val := trimJavaQuotes(string(caps["val"].Text(src)))
		if !strings.EqualFold(key, "Access-Control-Allow-Origin") || val != "*" {
			continue
		}
		issues = append(issues, javaIssueAt("java-cors-wildcard", "MEDIUM", path,
			"CORS allow-origin set to wildcard", `setHeader("Access-Control-Allow-Origin", "*") allows any origin to make credentialed cross-origin requests`,
			caps["call"]))
	}
	return issues
}

var javaCookieBoolCallQuery = mustJavaQuery(`(method_invocation name: (identifier) @m arguments: (argument_list (false)) (#any-of? @m "setSecure" "setHttpOnly")) @call`)

func checkJavaInsecureCookie(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaCookieBoolCallQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		issues = append(issues, javaIssueAt("java-insecure-cookie", "MEDIUM", path,
			"Cookie flag explicitly disabled", string(caps["m"].Text(src))+"(false) weakens cookie protection",
			caps["call"]))
	}
	return issues
}

var javaScriptEvalQuery = mustJavaQuery(`(method_invocation name: (identifier) @m arguments: (argument_list . (_) @arg) (#eq? @m "eval")) @call`)

// checkJavaEvalDetected flags a `.eval(...)` call (matched by method name
// only, not a verified javax.script.ScriptEngine/JEXL/MVEL receiver — no
// type resolution available) whose argument is dynamic or tainted.
// Unlike Python's eval()/exec() (unconditionally flagged: essentially no
// legitimate call ever has attacker-reachable input and even literal use is
// rare), script-engine eval() with a literal/hardcoded script is a normal,
// common pattern (loading a bundled rule-engine script, etc.), so this rule
// is gated on the argument being non-literal instead of unconditional.
func checkJavaEvalDetected(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaScriptEvalQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		arg := caps["arg"]
		if !javaIsDynamicString(arg, src) && !javaTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, javaIssueAt("java-eval-detected", "HIGH", path,
			"Script engine eval() with a non-literal argument",
			".eval(...) argument is built via `+` concatenation, or is a local variable derived from request/env input — evaluating untrusted input as script code (javax.script.ScriptEngine or similar) is remote code execution",
			caps["call"]))
	}
	return issues
}

var javaClassForNameQuery = mustJavaQuery(`(method_invocation object: (identifier) @cls name: (identifier) @m arguments: (argument_list . (_) @arg) (#eq? @cls "Class") (#eq? @m "forName")) @call`)

// checkJavaUnsafeReflection flags Class.forName(...) when the class-name
// argument is itself tainted (request/env-derived, directly or through a
// local variable) — not gated on javaIsDynamicString: Class.forName is
// routinely called with a plain (non-literal, non-tainted) variable in
// normal code (e.g. loading a JDBC driver class name from a properties
// file), so only the taint check is used, same reasoning as
// ruby-unsafe-reflection/php-unsafe-reflection.
func checkJavaUnsafeReflection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaClassForNameQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		arg := caps["arg"]
		if !javaTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, javaIssueAt("java-unsafe-reflection", "HIGH", path,
			"Class loaded by an attacker-controlled name",
			"Class.forName(...) argument is derived from request/env input (directly, or through a local variable) — this loads/initializes whatever class name an attacker supplies",
			caps["call"]))
	}
	return issues
}

var javaRandomSeedQuery = mustJavaQuery(`(object_creation_expression type: (type_identifier) @t arguments: (argument_list . (decimal_integer_literal)) (#eq? @t "Random")) @call`)

// checkJavaPredictablePRNGSeed flags new Random(<literal>) — a fixed seed
// makes every subsequent value fully predictable (distinct from
// java-insecure-random-for-secrets, which flags new Random() used in a
// security-sounding method, not the seed). new Random() with no args
// (seeded from system entropy) is unaffected.
func checkJavaPredictablePRNGSeed(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaRandomSeedQuery.ExecuteNode(root, javaLang, src) {
		issues = append(issues, javaIssueAt("java-predictable-prng-seed", "MEDIUM", path,
			"PRNG seeded with a hardcoded literal",
			"new Random(...) is called with a compile-time integer literal; every run produces the same sequence, making all subsequent output predictable",
			javaCapMap(m)["call"]))
	}
	return issues
}

var javaYamlLoadQuery = mustJavaQuery(`(method_invocation object: (object_creation_expression type: (type_identifier) @t) @newExpr name: (identifier) @m arguments: (argument_list . (_) @arg) (#eq? @t "Yaml") (#eq? @m "load")) @call`)

// checkJavaYAMLUnsafeLoad flags SnakeYAML's default (zero-argument)
// Yaml().load(...), which uses an unsafe Constructor that can instantiate
// arbitrary Java classes from untrusted YAML — the source of multiple
// public RCE CVEs (e.g. CVE-2022-1471). `new Yaml(anything).load(...)` is
// not flagged: a non-default constructor argument is at minimum an
// explicit choice (SafeConstructor or otherwise) rather than the silent
// unsafe default, so requiring zero constructor args keeps this rule from
// false-positiving on the hardened form. Matches the direct
// `new Yaml(...).load(...)` chain only, not `Yaml y = new Yaml(); y.load(...)`
// split across two statements — same "flag the candidate" tradeoff as
// java-xxe/java-tls-trust-manager-bypass otherwise.
func checkJavaYAMLUnsafeLoad(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaYamlLoadQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		if args := caps["newExpr"].ChildByFieldName("arguments", javaLang); args != nil && args.NamedChildCount() > 0 {
			continue
		}
		issues = append(issues, javaIssueAt("java-yaml-unsafe-load", "HIGH", path,
			"SnakeYAML unsafe deserialization", "new Yaml().load(...) uses SnakeYAML's default Constructor, which can instantiate arbitrary Java classes from untrusted YAML; use new Yaml(new SafeConstructor()) instead",
			caps["call"]))
	}
	return issues
}

var javaURLNewQuery = mustJavaQuery(`(object_creation_expression type: (type_identifier) @t arguments: (argument_list . (_) @arg) (#eq? @t "URL")) @call`)

func checkJavaSSRF(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaURLNewQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		arg := caps["arg"]
		if !javaIsDynamicString(arg, src) && !javaTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, javaIssueAt("java-ssrf", "HIGH", path,
			"Outbound request URL built from request data",
			"new URL(...) argument is derived from request input (directly, or through a local variable) or built via `+` concatenation rather than a validated/allowlisted URL",
			caps["call"]))
	}
	return issues
}

var javaFileNewQuery = mustJavaQuery(`(object_creation_expression type: (type_identifier) @t arguments: (argument_list . (_) @arg) (#any-of? @t "File" "FileInputStream" "FileReader")) @call`)

func checkJavaPathTraversal(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaFileNewQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		arg := caps["arg"]
		if !javaIsDynamicString(arg, src) && !javaTaintedArg(arg, src) {
			continue
		}
		t := string(caps["t"].Text(src))
		issues = append(issues, javaIssueAt("java-path-traversal", "HIGH", path,
			"File path built from request data", "new "+t+"(...) path is derived from request input (directly, or through a local variable) or built via `+` concatenation rather than a validated literal; sanitize/allowlist before use",
			caps["call"]))
	}
	return issues
}

var (
	javaCookieNewQuery    = mustJavaQuery(`(object_creation_expression type: (type_identifier) @t (#eq? @t "Cookie")) @call`)
	javaCookieSetterQuery = mustJavaQuery(`(method_invocation name: (identifier) @m (#any-of? @m "setSecure" "setHttpOnly")) @call`)
)

// checkJavaCookieMissingFlags is a same-method-body co-occurrence check, not
// real data-flow: it flags a `new Cookie(...)` when setSecure/setHttpOnly
// don't appear anywhere else as a call in the same method body. It can't
// tell which Cookie variable a given setter call was hardening when a method
// juggles more than one — same "flag the candidate, let a human confirm"
// tradeoff as java-tls-trust-manager-bypass/java-xxe.
func checkJavaCookieMissingFlags(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaMethodDefQuery.ExecuteNode(root, javaLang, src) {
		body := javaCapMap(m)["body"]
		newCookies := javaCookieNewQuery.ExecuteNode(body, javaLang, src)
		if len(newCookies) == 0 {
			continue
		}
		setters := map[string]bool{}
		for _, sm := range javaCookieSetterQuery.ExecuteNode(body, javaLang, src) {
			setters[string(javaCapMap(sm)["m"].Text(src))] = true
		}
		for _, cm := range newCookies {
			call := javaCapMap(cm)["call"]
			for _, flag := range []string{"setSecure", "setHttpOnly"} {
				if setters[flag] {
					continue
				}
				issues = append(issues, javaIssueAt("java-cookie-missing-flags", "LOW", path,
					flag+" never called on cookie", "new Cookie(...) is created in this method but "+flag+"(true) is never called; it defaults to false, weakening cookie protection unless set elsewhere",
					call))
			}
		}
	}
	return issues
}

// javaJWTNoneMethodQuery matches auth0 java-jwt's Algorithm.none(), which
// constructs an unsecured-JWT signer/verifier directly.
// javaJWTNoneFieldQuery matches jjwt's SignatureAlgorithm.NONE constant,
// used the same way Go's jwt.SigningMethodNone is: passed wherever the
// library expects a signing algorithm, accepting unsigned tokens.
var (
	javaJWTNoneMethodQuery = mustJavaQuery(`(method_invocation object: (identifier) @cls name: (identifier) @m (#eq? @cls "Algorithm") (#eq? @m "none")) @call`)
	javaJWTNoneFieldQuery  = mustJavaQuery(`(field_access object: (identifier) @cls field: (identifier) @f (#eq? @cls "SignatureAlgorithm") (#eq? @f "NONE")) @call`)
)

func checkJavaJWTNoneAlgorithm(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaJWTNoneMethodQuery.ExecuteNode(root, javaLang, src) {
		issues = append(issues, javaIssueAt("java-jwt-none-algorithm", "HIGH", path,
			"JWT algorithm set to 'none'", "Algorithm.none() accepts unsigned tokens, allowing signature bypass",
			javaCapMap(m)["call"]))
	}
	for _, m := range javaJWTNoneFieldQuery.ExecuteNode(root, javaLang, src) {
		issues = append(issues, javaIssueAt("java-jwt-none-algorithm", "HIGH", path,
			"JWT algorithm set to 'none'", "SignatureAlgorithm.NONE accepts unsigned tokens, allowing signature bypass",
			javaCapMap(m)["call"]))
	}
	return issues
}

func javaCapMap(m gts.QueryMatch) map[string]*gts.Node {
	out := make(map[string]*gts.Node, len(m.Captures))
	for _, c := range m.Captures {
		out[c.Name] = c.Node
	}
	return out
}
