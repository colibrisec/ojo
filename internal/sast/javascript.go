package sast

import (
	"strings"

	gts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"

	"github.com/colibrisec/ojo/internal/model"
)

var (
	jsLang  = grammars.JavascriptLanguage()
	tsLang  = grammars.TypescriptLanguage()
	tsxLang = grammars.TsxLanguage()
)

type triQuery struct {
	js, ts, tsx *gts.Query
}

func (q triQuery) forLang(lang *gts.Language) *gts.Query {
	switch lang {
	case jsLang:
		return q.js
	case tsLang:
		return q.ts
	case tsxLang:
		return q.tsx
	default:
		return nil
	}
}

func mustQueryFor(lang *gts.Language, src string) *gts.Query {
	q, err := gts.NewQuery(src, lang)
	if err != nil {
		panic("sast: invalid js/ts query: " + err.Error())
	}
	return q
}

func mustTriQuery(src string) triQuery {
	return triQuery{js: mustQueryFor(jsLang, src), ts: mustQueryFor(tsLang, src), tsx: mustQueryFor(tsxLang, src)}
}

func mustJSXQuery(src string) triQuery {
	return triQuery{js: mustQueryFor(jsLang, src), tsx: mustQueryFor(tsxLang, src)}
}

type jsRule struct {
	id       string
	severity string
	check    func(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue
}

var jsRules = []jsRule{
	{"js-hardcoded-secret", "MEDIUM", checkJSHardcodedSecret},
	{"js-eval-detected", "HIGH", checkJSEvalDetected},
	{"js-command-injection", "HIGH", checkJSCommandInjection},
	{"js-sql-injection", "HIGH", checkJSSQLInjection},
	{"js-weak-hash", "LOW", checkJSWeakHash},
	{"js-weak-cipher", "MEDIUM", checkJSWeakCipher},
	{"js-insecure-random-for-secrets", "INFO", checkJSInsecureRandom},
	{"js-tls-verify-disabled", "HIGH", checkJSTLSVerifyDisabled},
	{"js-dom-xss-innerhtml", "MEDIUM", checkJSDOMXSSInnerHTML},
	{"js-react-dangerously-set-innerhtml", "MEDIUM", checkJSReactDangerouslySetInnerHTML},
	{"js-open-redirect", "MEDIUM", checkJSOpenRedirect},
	{"js-jwt-none-algorithm", "HIGH", checkJSJWTNoneAlgorithm},
	{"js-yaml-unsafe-load", "MEDIUM", checkJSYAMLUnsafeLoad},
	{"js-cors-wildcard", "MEDIUM", checkJSCORSWildcard},
	{"js-insecure-cookie", "MEDIUM", checkJSInsecureCookie},
	{"js-path-traversal", "HIGH", checkJSPathTraversal},
	{"js-cookie-missing-flags", "LOW", checkJSCookieMissingFlags},
	{"js-ssrf", "HIGH", checkJSSSRF},
	{"js-ssti", "HIGH", checkJSSSTI},
	{"js-nosqli", "HIGH", checkJSNoSQLi},
	{"js-unsafe-reflection", "HIGH", checkJSUnsafeReflection},
}

func jsIssueAt(id, severity, path, title, message string, n *gts.Node) model.Issue {
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

func jsIsDynamicString(n *gts.Node, lang *gts.Language, src []byte) bool {
	switch n.Type(lang) {
	case "template_string":
		for _, c := range n.Children() {
			if c.Type(lang) == "template_substitution" {
				return true
			}
		}
		return false
	case "binary_expression":
		op := n.ChildByFieldName("operator", lang)
		return op != nil && string(op.Text(src)) == "+"
	default:
		return false
	}
}

var secretDeclQuery = mustTriQuery(`(variable_declarator name: (identifier) @name value: (string) @val) @decl`)

func checkJSHardcodedSecret(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range secretDeclQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		name := string(caps["name"].Text(src))
		val := caps["val"]
		if !nameLooksSecret(name) || len(trimQuotes(string(val.Text(src)))) <= 4 {
			continue
		}
		issues = append(issues, jsIssueAt("js-hardcoded-secret", "MEDIUM", path,
			"Hardcoded secret-looking value", "variable "+name+" is assigned a literal string",
			caps["decl"]))
	}
	return issues
}

func trimQuotes(s string) string {
	if len(s) >= 2 {
		return s[1 : len(s)-1]
	}
	return s
}

var evalDetectedQuery = mustTriQuery(`[
	(call_expression function: (identifier) @fname (#eq? @fname "eval"))
	(new_expression constructor: (identifier) @fname (#eq? @fname "Function"))
] @call`)

// vmRunQuery matches node:vm's runInNewContext/runInThisContext/runInContext.
// Node's own docs are explicit that the vm module is "not a security
// mechanism" and code run through it can escape the sandbox — same
// "executes arbitrary code" tradeoff as eval()/new Function(), just via a
// different API.
var vmRunQuery = mustTriQuery(`(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @meth) (#eq? @obj "vm") (#any-of? @meth "runInNewContext" "runInThisContext" "runInContext")) @call`)

func checkJSEvalDetected(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range evalDetectedQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		fname := string(caps["fname"].Text(src))
		issues = append(issues, jsIssueAt("js-eval-detected", "HIGH", path,
			fname+"() used", fname+"() executes arbitrary code; avoid it on any input that isn't fully trusted",
			caps["call"]))
	}
	for _, m := range vmRunQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		issues = append(issues, jsIssueAt("js-eval-detected", "HIGH", path,
			"vm."+string(caps["meth"].Text(src))+"() used", "vm."+string(caps["meth"].Text(src))+"() executes arbitrary code; Node's docs explicitly state the vm module is not a security sandbox — avoid it on any input that isn't fully trusted",
			caps["call"]))
	}
	return issues
}

var (
	childProcessExecQuery       = mustTriQuery(`(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @meth) arguments: (arguments . (_) @arg) (#any-of? @obj "child_process" "cp") (#any-of? @meth "exec" "execSync")) @call`)
	childProcessSpawnShellQuery = mustTriQuery(`(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @meth) arguments: (arguments (object (pair key: (property_identifier) @key value: (true)))) (#any-of? @obj "child_process" "cp") (#any-of? @meth "spawn" "execFile") (#eq? @key "shell")) @call`)
)

func checkJSCommandInjection(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range childProcessExecQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		if !jsIsDynamicString(caps["arg"], lang, src) && !jsTaintedArg(caps["arg"], lang, src) {
			continue
		}
		issues = append(issues, jsIssueAt("js-command-injection", "HIGH", path,
			"Command built from a non-literal argument",
			string(caps["obj"].Text(src))+"."+string(caps["meth"].Text(src))+" argument is built via template-literal interpolation or concatenation instead of a literal, or is a local variable derived from request/env input; prefer execFile/spawn with an argument array",
			caps["call"]))
	}
	for _, m := range childProcessSpawnShellQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		issues = append(issues, jsIssueAt("js-command-injection", "HIGH", path,
			"spawn/execFile called with shell: true",
			string(caps["obj"].Text(src))+"."+string(caps["meth"].Text(src))+"(..., { shell: true }) invokes a shell, reintroducing the same injection risk execFile/spawn's argument-array form exists to avoid",
			caps["call"]))
	}
	return issues
}

var sqlQueryCallQuery = mustTriQuery(`(call_expression function: (member_expression property: (property_identifier) @meth) arguments: (arguments . (_) @arg) (#any-of? @meth "query" "execute")) @call`)

func checkJSSQLInjection(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range sqlQueryCallQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		if !jsIsDynamicString(caps["arg"], lang, src) && !jsTaintedArg(caps["arg"], lang, src) {
			continue
		}
		issues = append(issues, jsIssueAt("js-sql-injection", "HIGH", path,
			"SQL query built from a non-literal string",
			string(caps["meth"].Text(src))+" query argument is built via template-literal interpolation or concatenation instead of parameterized placeholders, or is a local variable derived from request/env input",
			caps["call"]))
	}
	return issues
}

var createHashQuery = mustTriQuery(`(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @fn) arguments: (arguments (string) @alg) (#eq? @obj "crypto") (#eq? @fn "createHash")) @call`)

func checkJSWeakHash(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range createHashQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		alg := trimQuotes(string(caps["alg"].Text(src)))
		if alg != "md5" && alg != "sha1" {
			continue
		}
		issues = append(issues, jsIssueAt("js-weak-hash", "LOW", path,
			"Weak hash algorithm", "crypto.createHash('"+alg+"') is cryptographically broken; use 'sha256' or stronger",
			caps["call"]))
	}
	return issues
}

var createCipherQuery = mustTriQuery(`(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @fn) arguments: (arguments . (string) @alg) (#eq? @obj "crypto") (#any-of? @fn "createCipheriv" "createCipher" "createDecipheriv" "createDecipher")) @call`)

// checkJSWeakCipher flags crypto.createCipher(iv)/createDecipher(iv) called
// with a broken cipher (DES/RC4) or an insecure mode (ECB) — same
// name-in-algorithm-string signal as java-weak-cipher, just against Node's
// OpenSSL-style algorithm identifiers ("des-ede3-cbc", "rc4", "aes-128-ecb")
// instead of Java's.
func checkJSWeakCipher(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range createCipherQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		alg := trimQuotes(string(caps["alg"].Text(src)))
		upper := strings.ToUpper(alg)
		if !strings.Contains(upper, "DES") && !strings.Contains(upper, "RC4") && !strings.Contains(upper, "ECB") {
			continue
		}
		issues = append(issues, jsIssueAt("js-weak-cipher", "MEDIUM", path,
			"Weak cipher or insecure mode", "crypto."+string(caps["fn"].Text(src))+"('"+alg+"', ...) uses a broken cipher or an insecure mode (ECB); use AES-GCM instead",
			caps["call"]))
	}
	return issues
}

var (
	mathRandomQuery = mustTriQuery(`(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @fn) (#eq? @obj "Math") (#eq? @fn "random")) @call`)
	jsFuncDeclQuery = mustTriQuery(`(function_declaration name: (identifier) @fname body: (statement_block) @body) @def`)
)

func checkJSInsecureRandom(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range jsFuncDeclQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		fname := string(caps["fname"].Text(src))
		if !nameLooksSecret(fname) && !strings.Contains(strings.ToLower(fname), "session") {
			continue
		}
		for _, rm := range mathRandomQuery.forLang(lang).ExecuteNode(caps["body"], lang, src) {
			issues = append(issues, jsIssueAt("js-insecure-random-for-secrets", "INFO", path,
				"Math.random used in a security-sounding function",
				"function "+fname+" uses Math.random, which is not cryptographically secure; consider the crypto module's randomBytes/randomUUID",
				jsCapMap(rm)["call"]))
		}
	}
	return issues
}

var rejectUnauthorizedQuery = mustTriQuery(`(pair key: (property_identifier) @key value: (false) (#eq? @key "rejectUnauthorized")) @pair`)

func checkJSTLSVerifyDisabled(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rejectUnauthorizedQuery.forLang(lang).ExecuteNode(root, lang, src) {
		issues = append(issues, jsIssueAt("js-tls-verify-disabled", "HIGH", path,
			"TLS certificate verification disabled", "rejectUnauthorized: false disables certificate validation",
			jsCapMap(m)["pair"]))
	}
	return issues
}

var innerHTMLAssignQuery = mustTriQuery(`(assignment_expression left: (member_expression property: (property_identifier) @prop) right: (_) @val (#eq? @prop "innerHTML")) @assign`)

func checkJSDOMXSSInnerHTML(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range innerHTMLAssignQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		if caps["val"].Type(lang) == "string" {
			continue // literal HTML, not attacker-influenced
		}
		issues = append(issues, jsIssueAt("js-dom-xss-innerhtml", "MEDIUM", path,
			"innerHTML assigned a non-literal value", ".innerHTML = ... with a non-literal right-hand side can lead to DOM-based XSS; prefer .textContent or a sanitizer",
			caps["assign"]))
	}
	return issues
}

var dangerouslySetInnerHTMLQuery = mustJSXQuery(`(jsx_attribute (property_identifier) @attr (#eq? @attr "dangerouslySetInnerHTML")) @jsxattr`)

func checkJSReactDangerouslySetInnerHTML(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	q := dangerouslySetInnerHTMLQuery.forLang(lang)
	if q == nil {
		return nil
	}
	var issues []model.Issue
	for _, m := range q.ExecuteNode(root, lang, src) {
		issues = append(issues, jsIssueAt("js-react-dangerously-set-innerhtml", "MEDIUM", path,
			"dangerouslySetInnerHTML used", "dangerouslySetInnerHTML bypasses React's escaping; ensure the __html value is sanitized",
			jsCapMap(m)["jsxattr"]))
	}
	return issues
}

var redirectCallQuery = mustTriQuery(`(call_expression function: (member_expression property: (property_identifier) @meth) arguments: (arguments . (_) @arg) (#eq? @meth "redirect")) @call`)

func checkJSOpenRedirect(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range redirectCallQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		arg := caps["arg"]
		if !jsIsDynamicString(arg, lang, src) && !jsTaintedArg(arg, lang, src) {
			continue
		}
		issues = append(issues, jsIssueAt("js-open-redirect", "MEDIUM", path,
			"Redirect target built from request data", "redirect(...) argument is derived from request input (directly, or through a local variable) rather than a literal/allowlisted URL",
			caps["call"]))
	}
	return issues
}

var jsFuncBoundary = map[string]bool{
	"function_declaration": true, "function_expression": true, "arrow_function": true,
	"method_definition": true, "generator_function_declaration": true, "generator_function": true,
}

func jsAssignInfo(n *gts.Node, lang *gts.Language, src []byte) (string, *gts.Node, bool) {
	switch n.Type(lang) {
	case "variable_declarator":
		name := n.ChildByFieldName("name", lang)
		val := n.ChildByFieldName("value", lang)
		if name == nil || val == nil || name.Type(lang) != "identifier" {
			return "", nil, false
		}
		return string(name.Text(src)), val, true
	case "assignment_expression":
		left := n.ChildByFieldName("left", lang)
		right := n.ChildByFieldName("right", lang)
		if left == nil || right == nil || left.Type(lang) != "identifier" {
			return "", nil, false
		}
		return string(left.Text(src)), right, true
	default:
		return "", nil, false
	}
}

// jsIsEnvSource matches process.env.X/process.env['X'] by raw text rather
// than decomposing the member/subscript-expression shape.
func jsIsEnvSource(n *gts.Node, _ *gts.Language, src []byte) bool {
	text := string(n.Text(src))
	return strings.HasPrefix(text, "process.env.") || strings.HasPrefix(text, "process.env[")
}

// jsExprTainted reports whether n evaluates from tainted input: rooted at
// req/request (rootedAtRequest), an env-var read, a variable already
// known-tainted in env, or built from any of those via `+` concatenation,
// template-literal interpolation, or a call's arguments.
func jsExprTainted(n *gts.Node, lang *gts.Language, src []byte, env map[string]bool) bool {
	if n == nil {
		return false
	}
	if rootedAtRequest(n, lang, src) || jsIsEnvSource(n, lang, src) {
		return true
	}
	switch n.Type(lang) {
	case "identifier":
		return env[string(n.Text(src))]
	case "binary_expression":
		op := n.ChildByFieldName("operator", lang)
		if op == nil || string(op.Text(src)) != "+" {
			return false
		}
		return jsExprTainted(n.ChildByFieldName("left", lang), lang, src, env) || jsExprTainted(n.ChildByFieldName("right", lang), lang, src, env)
	case "template_string":
		for _, c := range n.Children() {
			if c.Type(lang) != "template_substitution" || c.NamedChildCount() == 0 {
				continue
			}
			if jsExprTainted(c.NamedChild(0), lang, src, env) {
				return true
			}
		}
		return false
	case "call_expression":
		args := n.ChildByFieldName("arguments", lang)
		if args == nil {
			return false
		}
		for _, a := range args.Children() {
			if jsExprTainted(a, lang, src, env) {
				return true
			}
		}
		return false
	case "parenthesized_expression":
		if n.NamedChildCount() > 0 {
			return jsExprTainted(n.NamedChild(0), lang, src, env)
		}
		return false
	default:
		return false
	}
}

// jsTaintedArg reports whether arg evaluates from tainted input, tracking
// through local variable assignments within its enclosing function/arrow/
// method (intraprocedural taint tracking — see taint_ts.go).
func jsTaintedArg(arg *gts.Node, lang *gts.Language, src []byte) bool {
	body := tsEnclosingBody(arg, lang, jsFuncBoundary)
	env := tsTaintEnv(body, lang, src, jsFuncBoundary, jsAssignInfo, jsExprTainted)
	return jsExprTainted(arg, lang, src, env)
}

func rootedAtRequest(n *gts.Node, lang *gts.Language, src []byte) bool {
	for n.Type(lang) == "member_expression" {
		obj := n.ChildByFieldName("object", lang)
		if obj == nil {
			return false
		}
		n = obj
	}
	if n.Type(lang) != "identifier" {
		return false
	}
	name := string(n.Text(src))
	return name == "req" || name == "request"
}

var jwtAlgorithmNoneQuery = mustTriQuery(`(pair key: (property_identifier) @key value: (string) @val (#eq? @key "algorithm")) @pair`)

func checkJSJWTNoneAlgorithm(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range jwtAlgorithmNoneQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		if trimQuotes(string(caps["val"].Text(src))) != "none" {
			continue
		}
		issues = append(issues, jsIssueAt("js-jwt-none-algorithm", "HIGH", path,
			"JWT algorithm set to 'none'", "algorithm: 'none' accepts unsigned tokens, allowing signature bypass",
			caps["pair"]))
	}
	return issues
}

var jsYamlLoadQuery = mustTriQuery(`(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @fn) arguments: (arguments . (_) @arg) @args (#any-of? @obj "yaml" "YAML") (#eq? @fn "load")) @call`)

// checkJSYAMLUnsafeLoad flags js-yaml's load() with no options argument (or
// one with no "schema" key) — versions before js-yaml v4 default to a schema
// that can construct arbitrary JS types from untrusted YAML. An explicit
// `schema:` option is treated as a deliberate choice (hardened or not) and
// skipped, same false-positive-avoidance tradeoff as java-yaml-unsafe-load's
// zero-constructor-arg check.
func checkJSYAMLUnsafeLoad(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range jsYamlLoadQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		if jsArgsHaveSchemaOption(caps["args"], lang, src) {
			continue
		}
		issues = append(issues, jsIssueAt("js-yaml-unsafe-load", "MEDIUM", path,
			"yaml.load without an explicit schema", string(caps["obj"].Text(src))+".load(...) without a restrictive `schema` option can construct arbitrary types from untrusted YAML on js-yaml versions before v4",
			caps["call"]))
	}
	return issues
}

// jsArgsHaveSchemaOption reports whether an arguments node's second argument
// is an object literal containing a "schema" key.
func jsArgsHaveSchemaOption(args *gts.Node, lang *gts.Language, src []byte) bool {
	if args == nil || args.NamedChildCount() < 2 {
		return false
	}
	opts := args.NamedChild(1)
	if opts.Type(lang) != "object" {
		return false
	}
	for _, c := range opts.Children() {
		if c.Type(lang) != "pair" {
			continue
		}
		key := c.ChildByFieldName("key", lang)
		if key != nil && string(key.Text(src)) == "schema" {
			return true
		}
	}
	return false
}

var corsHeaderCallQuery = mustTriQuery(`(call_expression function: (member_expression property: (property_identifier) @meth) arguments: (arguments . (string) @key . (string) @val) (#any-of? @meth "setHeader" "header")) @call`)

func checkJSCORSWildcard(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range corsHeaderCallQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		key := trimQuotes(string(caps["key"].Text(src)))
		val := trimQuotes(string(caps["val"].Text(src)))
		if !strings.EqualFold(key, "Access-Control-Allow-Origin") || val != "*" {
			continue
		}
		issues = append(issues, jsIssueAt("js-cors-wildcard", "MEDIUM", path,
			"CORS allow-origin set to wildcard", `setHeader("Access-Control-Allow-Origin", "*") allows any origin to make credentialed cross-origin requests`,
			caps["call"]))
	}
	return issues
}

var (
	cookieFlagFalseQuery = mustTriQuery(`(pair key: (property_identifier) @key value: (false)) @pair`)
	sameSiteValueQuery   = mustTriQuery(`(pair key: (property_identifier) @key value: (string) @val (#eq? @key "sameSite")) @pair`)
)

func checkJSInsecureCookie(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range cookieFlagFalseQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		key := string(caps["key"].Text(src))
		if key != "httpOnly" && key != "secure" {
			continue
		}
		issues = append(issues, jsIssueAt("js-insecure-cookie", "MEDIUM", path,
			"Cookie flag explicitly disabled", key+": false in a cookie options object weakens cookie protection",
			caps["pair"]))
	}
	for _, m := range sameSiteValueQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		val := strings.Trim(strings.ToLower(string(caps["val"].Text(src))), `'"`)
		if val != "none" {
			continue
		}
		obj := caps["pair"].Parent()
		if obj == nil || jsObjectHasSecureTrue(obj, lang, src) {
			continue
		}
		issues = append(issues, jsIssueAt("js-insecure-cookie", "MEDIUM", path,
			"SameSite=None cookie without Secure",
			"sameSite: 'none' is set without secure: true in the same options object — SameSite=None requires Secure or modern browsers reject the cookie outright, and without Secure the cookie is also sent over plain HTTP",
			caps["pair"]))
	}
	return issues
}

// jsObjectHasSecureTrue reports whether obj (an object-literal node) has a
// sibling `secure: true` pair.
func jsObjectHasSecureTrue(obj *gts.Node, lang *gts.Language, src []byte) bool {
	for _, c := range obj.Children() {
		if c.Type(lang) != "pair" {
			continue
		}
		key := c.ChildByFieldName("key", lang)
		val := c.ChildByFieldName("value", lang)
		if key == nil || val == nil {
			continue
		}
		if string(key.Text(src)) == "secure" && val.Type(lang) == "true" {
			return true
		}
	}
	return false
}

var fsReadCallQuery = mustTriQuery(`(call_expression function: (member_expression property: (property_identifier) @meth) arguments: (arguments . (_) @arg) (#any-of? @meth "readFile" "readFileSync" "createReadStream")) @call`)

func checkJSPathTraversal(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range fsReadCallQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		arg := caps["arg"]
		if !jsIsDynamicString(arg, lang, src) && !jsTaintedArg(arg, lang, src) {
			continue
		}
		issues = append(issues, jsIssueAt("js-path-traversal", "HIGH", path,
			"File path built from request data", "fs read call path is derived from request input (directly, or through a local variable) or built via template-literal interpolation/concatenation rather than a validated literal; sanitize/allowlist before use",
			caps["call"]))
	}
	return issues
}

var (
	fetchCallQuery = mustTriQuery(`(call_expression function: (identifier) @fname arguments: (arguments . (_) @arg) (#eq? @fname "fetch")) @call`)
	axiosCallQuery = mustTriQuery(`(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @meth) arguments: (arguments . (_) @arg) (#eq? @obj "axios") (#any-of? @meth "get" "post" "put" "delete")) @call`)
)

func checkJSSSRF(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range fetchCallQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		arg := caps["arg"]
		if !jsIsDynamicString(arg, lang, src) && !jsTaintedArg(arg, lang, src) {
			continue
		}
		issues = append(issues, jsIssueAt("js-ssrf", "HIGH", path,
			"Outbound request URL built from request data",
			"fetch(...) URL argument is derived from request/env input (directly, or through a local variable) or built via template-literal interpolation/concatenation rather than a validated/allowlisted URL",
			caps["call"]))
	}
	for _, m := range axiosCallQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		arg := caps["arg"]
		if !jsIsDynamicString(arg, lang, src) && !jsTaintedArg(arg, lang, src) {
			continue
		}
		issues = append(issues, jsIssueAt("js-ssrf", "HIGH", path,
			"Outbound request URL built from request data",
			"axios."+string(caps["meth"].Text(src))+"(...) URL argument is derived from request/env input (directly, or through a local variable) or built via template-literal interpolation/concatenation rather than a validated/allowlisted URL",
			caps["call"]))
	}
	return issues
}

var ejsCallQuery = mustTriQuery(`(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @meth) arguments: (arguments . (_) @arg) (#eq? @obj "ejs") (#any-of? @meth "render" "compile")) @call`)

func checkJSSSTI(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range ejsCallQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		arg := caps["arg"]
		if !jsIsDynamicString(arg, lang, src) && !jsTaintedArg(arg, lang, src) {
			continue
		}
		issues = append(issues, jsIssueAt("js-ssti", "HIGH", path,
			"Template source built from request data",
			"ejs."+string(caps["meth"].Text(src))+"(...) argument is derived from request/env input (directly, or through a local variable) or built via template-literal interpolation/concatenation — the template source itself is attacker-controlled, which is server-side template injection, not just a data-substitution issue",
			caps["call"]))
	}
	return issues
}

var jsMongoQueryCallQuery = mustTriQuery(`(call_expression function: (member_expression property: (property_identifier) @meth) arguments: (arguments . (_) @arg) (#any-of? @meth "find" "findOne" "findOneAndUpdate" "findOneAndDelete" "updateOne" "updateMany" "deleteOne" "deleteMany")) @call`)

// checkJSNoSQLi flags a Mongoose/MongoDB query/update/delete call whose
// filter argument is entirely request/env-derived (`Model.find(req.body)`),
// not a literal filter with individually-typed fields — a different shape
// from SQL injection (no string concatenation to point at; the whole
// filter object being attacker-controlled is what lets operators like
// $ne/$gt through).
func checkJSNoSQLi(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range jsMongoQueryCallQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		arg := caps["arg"]
		if !jsTaintedArg(arg, lang, src) {
			continue
		}
		issues = append(issues, jsIssueAt("js-nosqli", "HIGH", path,
			"MongoDB query filter built entirely from request data",
			string(caps["meth"].Text(src))+"(...) filter argument is derived from request/env input rather than a literal filter with individually-typed fields — passing the whole request payload as a MongoDB filter lets an attacker inject query operators (e.g. $ne, $gt) to bypass intended matching",
			caps["call"]))
	}
	return issues
}

var requireCallQuery = mustTriQuery(`(call_expression function: (identifier) @fname arguments: (arguments . (_) @arg) (#eq? @fname "require")) @call`)

// checkJSUnsafeReflection flags require(...) when the module-specifier
// argument is itself tainted (request/env-derived, directly or through a
// local variable) — not gated on jsIsDynamicString: `require('./plugins/' +
// name)`-shaped dynamic-but-not-attacker-controlled requires are a common,
// legitimate plugin-loading idiom in Node, so only the taint check is used
// (same reasoning as the other *-unsafe-reflection rules).
func checkJSUnsafeReflection(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range requireCallQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		arg := caps["arg"]
		if !jsTaintedArg(arg, lang, src) {
			continue
		}
		issues = append(issues, jsIssueAt("js-unsafe-reflection", "HIGH", path,
			"Module loaded by an attacker-controlled name",
			"require(...) argument is derived from request/env input (directly, or through a local variable) — this loads/executes whatever module path an attacker supplies",
			caps["call"]))
	}
	return issues
}

var jsCookieCallQuery = mustTriQuery(`(call_expression function: (member_expression property: (property_identifier) @meth) arguments: (arguments) @args (#eq? @meth "cookie")) @call`)

func checkJSCookieMissingFlags(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range jsCookieCallQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		args := caps["args"]
		if args.NamedChildCount() < 3 {
			issues = append(issues, jsIssueAt("js-cookie-missing-flags", "LOW", path,
				"Cookie set without httpOnly/secure options", "cookie(...) called without an options object; httpOnly and secure both default to false, weakening cookie protection",
				caps["call"]))
			continue
		}
		opts := args.NamedChild(2)
		if opts.Type(lang) != "object" {
			continue // not a literal — can't introspect a variable/spread without data flow
		}
		has := map[string]bool{}
		for _, c := range opts.Children() {
			if c.Type(lang) != "pair" {
				continue
			}
			key := c.ChildByFieldName("key", lang)
			if key != nil {
				has[string(key.Text(src))] = true
			}
		}
		for _, flag := range []string{"httpOnly", "secure"} {
			if has[flag] {
				continue
			}
			issues = append(issues, jsIssueAt("js-cookie-missing-flags", "LOW", path,
				flag+" not set on cookie options", "cookie(...) options object doesn't set "+flag+"; it defaults to false, weakening cookie protection unless set elsewhere",
				opts))
		}
	}
	return issues
}

func jsCapMap(m gts.QueryMatch) map[string]*gts.Node {
	out := make(map[string]*gts.Node, len(m.Captures))
	for _, c := range m.Captures {
		out[c.Name] = c.Node
	}
	return out
}
