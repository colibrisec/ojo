// JavaScript/TypeScript/TSX rules, using gotreesitter's javascript,
// typescript, and tsx grammars — same pure-Go, no-cgo tree-sitter runtime
// already used for Python (see python.go's package doc). All three grammars
// were verified directly against modern syntax (optional chaining, template
// literals, async/await, private fields, decorators, generics, JSX) before
// adopting them, same methodology as Python's gpython/gotreesitter check.
//
// The three grammars share node types/fields for the plain-JS subset (a
// query compiles identically against all three); JSX-specific queries only
// compile against javascript/tsx, since .ts files can't contain JSX — hence
// triQuery below carries a nil *Query for languages a rule doesn't apply to.
//
// Curated against github.com/semgrep/semgrep-rules' javascript/typescript
// rulesets: same threat coverage, hand-ported rather than executing
// semgrep's rule engine.
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

// triQuery holds a query compiled separately per grammar (Query is bound to
// the Language it was compiled against). A nil entry means the rule doesn't
// apply to that grammar (e.g. JSX-only rules against plain TypeScript).
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

// mustJSXQuery compiles a query only for javascript/tsx — TypeScript files
// can't contain JSX, and the jsx_* node types don't exist in that grammar.
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
	{"js-insecure-random-for-secrets", "INFO", checkJSInsecureRandom},
	{"js-tls-verify-disabled", "HIGH", checkJSTLSVerifyDisabled},
	{"js-dom-xss-innerhtml", "MEDIUM", checkJSDOMXSSInnerHTML},
	{"js-react-dangerously-set-innerhtml", "MEDIUM", checkJSReactDangerouslySetInnerHTML},
	{"js-open-redirect", "MEDIUM", checkJSOpenRedirect},
	{"js-jwt-none-algorithm", "HIGH", checkJSJWTNoneAlgorithm},
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

// jsIsDynamicString reports whether n is built at runtime — a template
// literal with an interpolation, or `+` concatenation — rather than a plain
// string literal. Deliberately narrow (mirrors go/python's isDynamicString):
// a bare identifier argument is not flagged, only literal-cum-substitution.
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

func checkJSEvalDetected(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range evalDetectedQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		fname := string(caps["fname"].Text(src))
		issues = append(issues, jsIssueAt("js-eval-detected", "HIGH", path,
			fname+"() used", fname+"() executes arbitrary code; avoid it on any input that isn't fully trusted",
			caps["call"]))
	}
	return issues
}

var childProcessExecQuery = mustTriQuery(`(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @meth) arguments: (arguments . (_) @arg) (#any-of? @obj "child_process" "cp") (#any-of? @meth "exec" "execSync")) @call`)

func checkJSCommandInjection(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range childProcessExecQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		if !jsIsDynamicString(caps["arg"], lang, src) {
			continue
		}
		issues = append(issues, jsIssueAt("js-command-injection", "HIGH", path,
			"Command built from a non-literal argument",
			string(caps["obj"].Text(src))+"."+string(caps["meth"].Text(src))+" argument is built via template-literal interpolation or concatenation instead of a literal; prefer execFile/spawn with an argument array",
			caps["call"]))
	}
	return issues
}

var sqlQueryCallQuery = mustTriQuery(`(call_expression function: (member_expression property: (property_identifier) @meth) arguments: (arguments . (_) @arg) (#any-of? @meth "query" "execute")) @call`)

func checkJSSQLInjection(root *gts.Node, lang *gts.Language, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range sqlQueryCallQuery.forLang(lang).ExecuteNode(root, lang, src) {
		caps := jsCapMap(m)
		if !jsIsDynamicString(caps["arg"], lang, src) {
			continue
		}
		issues = append(issues, jsIssueAt("js-sql-injection", "HIGH", path,
			"SQL query built from a non-literal string",
			string(caps["meth"].Text(src))+" query argument is built via template-literal interpolation or concatenation instead of parameterized placeholders",
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

var mathRandomQuery = mustTriQuery(`(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @fn) (#eq? @obj "Math") (#eq? @fn "random")) @call`)
var jsFuncDeclQuery = mustTriQuery(`(function_declaration name: (identifier) @fname body: (statement_block) @body) @def`)

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
		if !jsIsDynamicString(arg, lang, src) && !rootedAtRequest(arg, lang, src) {
			continue
		}
		issues = append(issues, jsIssueAt("js-open-redirect", "MEDIUM", path,
			"Redirect target built from request data", "redirect(...) argument is derived from request input rather than a literal/allowlisted URL",
			caps["call"]))
	}
	return issues
}

// rootedAtRequest reports whether n is a member-expression chain (e.g.
// req.query.url) whose root identifier looks like the request object.
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

func jsCapMap(m gts.QueryMatch) map[string]*gts.Node {
	out := make(map[string]*gts.Node, len(m.Captures))
	for _, c := range m.Captures {
		out[c.Name] = c.Node
	}
	return out
}
