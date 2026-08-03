// PHP rules, using gotreesitter's php grammar — same pure-Go, no-cgo
// tree-sitter runtime already used for Python/JS (see python.go's package
// doc). The grammar was verified directly against modern PHP 8 syntax
// (enums, readonly properties, named arguments, the nullsafe operator,
// match expressions, attributes, union types, first-class callable syntax,
// arrow functions, constructor property promotion) before adopting it —
// all parsed clean.
//
// Curated against github.com/semgrep/semgrep-rules' php ruleset: same
// threat coverage, hand-ported rather than executing semgrep's rule engine.
package sast

import (
	"strings"

	gts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"

	"github.com/colibrisec/ojo/internal/model"
)

var phpLang = grammars.PhpLanguage()

func mustPHPQuery(src string) *gts.Query {
	q, err := gts.NewQuery(src, phpLang)
	if err != nil {
		panic("sast: invalid php query: " + err.Error())
	}
	return q
}

type phpRule struct {
	id       string
	severity string
	check    func(root *gts.Node, src []byte, path string) []model.Issue
}

var phpRules = []phpRule{
	{"php-hardcoded-secret", "MEDIUM", checkPHPHardcodedSecret},
	{"php-eval-detected", "HIGH", checkPHPEvalDetected},
	{"php-command-injection", "HIGH", checkPHPCommandInjection},
	{"php-sql-injection", "HIGH", checkPHPSQLInjection},
	{"php-weak-hash", "LOW", checkPHPWeakHash},
	{"php-insecure-deserialization", "HIGH", checkPHPUnserialize},
	{"php-insecure-random-for-secrets", "INFO", checkPHPInsecureRandom},
	{"php-tls-verify-disabled", "HIGH", checkPHPTLSVerifyDisabled},
	{"php-lfi-include", "HIGH", checkPHPLFIInclude},
	{"php-preg-replace-eval-modifier", "HIGH", checkPHPPregReplaceEvalModifier},
}

func phpIssueAt(id, severity, path, title, message string, n *gts.Node) model.Issue {
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

// phpIsDynamicString reports whether n is built at runtime — "."
// concatenation, or a double-quoted/heredoc string with an interpolated
// variable — rather than a plain literal. A bare variable argument (no
// concatenation/interpolation) is deliberately not flagged, mirroring the
// same narrow definition used for Go/Python/JS.
func phpIsDynamicString(n *gts.Node) bool {
	switch n.Type(phpLang) {
	case "binary_expression":
		op := n.ChildByFieldName("operator", phpLang)
		return op != nil // "." is the only binary op PHP allows on strings in this position
	case "encapsed_string", "heredoc":
		return hasDescendant(n, phpLang, "variable_name")
	default:
		return false
	}
}

func hasDescendant(n *gts.Node, lang *gts.Language, typeName string) bool {
	for _, c := range n.Children() {
		if c.Type(lang) == typeName || hasDescendant(c, lang, typeName) {
			return true
		}
	}
	return false
}

func trimPHPQuotes(s string) string {
	if len(s) >= 2 {
		return s[1 : len(s)-1]
	}
	return s
}

var phpSecretAssignQuery = mustPHPQuery(`(assignment_expression left: (variable_name (name) @name) right: [(string) (encapsed_string)] @val) @assign`)

func checkPHPHardcodedSecret(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpSecretAssignQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		name := string(caps["name"].Text(src))
		val := caps["val"]
		if !nameLooksSecret(name) || hasDescendant(val, phpLang, "variable_name") {
			continue
		}
		if len(trimPHPQuotes(string(val.Text(src)))) <= 4 {
			continue
		}
		issues = append(issues, phpIssueAt("php-hardcoded-secret", "MEDIUM", path,
			"Hardcoded secret-looking value", "variable $"+name+" is assigned a literal string",
			caps["assign"]))
	}
	return issues
}

var phpEvalQuery = mustPHPQuery(`(function_call_expression function: (name) @fname (#eq? @fname "eval")) @call`)

func checkPHPEvalDetected(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpEvalQuery.ExecuteNode(root, phpLang, src) {
		issues = append(issues, phpIssueAt("php-eval-detected", "HIGH", path,
			"eval() used", "eval() executes arbitrary code; avoid it on any input that isn't fully trusted",
			phpCapMap(m)["call"]))
	}
	return issues
}

var phpCommandFuncQuery = mustPHPQuery(`(function_call_expression function: (name) @fname arguments: (arguments . (argument (_) @arg)) (#any-of? @fname "system" "exec" "shell_exec" "passthru" "popen" "proc_open")) @call`)

func checkPHPCommandInjection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpCommandFuncQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		if !phpIsDynamicString(caps["arg"]) {
			continue
		}
		fname := string(caps["fname"].Text(src))
		issues = append(issues, phpIssueAt("php-command-injection", "HIGH", path,
			"Command built from a non-literal argument",
			fname+"() argument is built via string concatenation or interpolation instead of a literal",
			caps["call"]))
	}
	return issues
}

var phpSQLMemberCallQuery = mustPHPQuery(`(member_call_expression name: (name) @meth arguments: (arguments . (argument (_) @arg)) (#any-of? @meth "query" "exec")) @call`)

func checkPHPSQLInjection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpSQLMemberCallQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		if !phpIsDynamicString(caps["arg"]) {
			continue
		}
		issues = append(issues, phpIssueAt("php-sql-injection", "HIGH", path,
			"SQL query built from a non-literal string",
			"->"+string(caps["meth"].Text(src))+"(...) query argument is built via concatenation/interpolation instead of a prepared statement placeholder",
			caps["call"]))
	}
	return issues
}

var phpHashFuncQuery = mustPHPQuery(`(function_call_expression function: (name) @fname) @call`)
var phpHashWithAlgQuery = mustPHPQuery(`(function_call_expression function: (name) @fname arguments: (arguments . (argument (string) @alg)) (#eq? @fname "hash")) @call`)

func checkPHPWeakHash(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpHashFuncQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		fname := string(caps["fname"].Text(src))
		if fname != "md5" && fname != "sha1" {
			continue
		}
		issues = append(issues, phpIssueAt("php-weak-hash", "LOW", path,
			"Weak hash algorithm", fname+"() is cryptographically broken; use hash('sha256', ...) or stronger",
			caps["call"]))
	}
	for _, m := range phpHashWithAlgQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		alg := trimPHPQuotes(string(caps["alg"].Text(src)))
		if alg != "md5" && alg != "sha1" {
			continue
		}
		issues = append(issues, phpIssueAt("php-weak-hash", "LOW", path,
			"Weak hash algorithm", "hash('"+alg+"', ...) is cryptographically broken; use 'sha256' or stronger",
			caps["call"]))
	}
	return issues
}

var phpUnserializeQuery = mustPHPQuery(`(function_call_expression function: (name) @fname (#eq? @fname "unserialize")) @call`)

func checkPHPUnserialize(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpUnserializeQuery.ExecuteNode(root, phpLang, src) {
		issues = append(issues, phpIssueAt("php-insecure-deserialization", "HIGH", path,
			"Insecure deserialization via unserialize", "unserialize() can instantiate arbitrary objects and trigger PHP object injection when given untrusted data; use json_decode for plain data",
			phpCapMap(m)["call"]))
	}
	return issues
}

var phpRandFuncQuery = mustPHPQuery(`(function_call_expression function: (name) @fname (#any-of? @fname "rand" "mt_rand")) @call`)
var phpFuncDefQuery = mustPHPQuery(`(function_definition name: (name) @fname body: (compound_statement) @body) @def`)

func checkPHPInsecureRandom(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpFuncDefQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		fname := string(caps["fname"].Text(src))
		if !nameLooksSecret(fname) && !strings.Contains(strings.ToLower(fname), "session") {
			continue
		}
		for _, rm := range phpRandFuncQuery.ExecuteNode(caps["body"], phpLang, src) {
			rcaps := phpCapMap(rm)
			issues = append(issues, phpIssueAt("php-insecure-random-for-secrets", "INFO", path,
				string(rcaps["fname"].Text(src))+"() used in a security-sounding function",
				"function "+fname+" uses "+string(rcaps["fname"].Text(src))+"(), which is not cryptographically secure; consider random_bytes()/random_int()",
				rcaps["call"]))
		}
	}
	return issues
}

var phpVerifyPeerFalseQuery = mustPHPQuery(`(array_element_initializer (string) @key (boolean) @val (#any-of? @key "'verify_peer'" "'verify_peer_name'" "\"verify_peer\"" "\"verify_peer_name\"")) @pair`)
var phpCurlSSLVerifyQuery = mustPHPQuery(`(function_call_expression function: (name) @fn arguments: (arguments (argument (variable_name)) (argument (name) @opt) (argument (boolean) @val)) (#eq? @fn "curl_setopt") (#any-of? @opt "CURLOPT_SSL_VERIFYPEER" "CURLOPT_SSL_VERIFYHOST")) @call`)

func checkPHPTLSVerifyDisabled(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpVerifyPeerFalseQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		if caps["val"].Type(phpLang) != "boolean" || string(caps["val"].Text(src)) != "false" {
			continue
		}
		issues = append(issues, phpIssueAt("php-tls-verify-disabled", "HIGH", path,
			"TLS certificate verification disabled", trimPHPQuotes(string(caps["key"].Text(src)))+" => false disables certificate validation",
			caps["pair"]))
	}
	for _, m := range phpCurlSSLVerifyQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		if string(caps["val"].Text(src)) != "false" {
			continue
		}
		issues = append(issues, phpIssueAt("php-tls-verify-disabled", "HIGH", path,
			"TLS certificate verification disabled", "curl_setopt(..., "+string(caps["opt"].Text(src))+", false) disables certificate validation",
			caps["call"]))
	}
	return issues
}

var phpIncludeQuery = mustPHPQuery(`[
	(include_expression (_) @arg) @inc
	(include_once_expression (_) @arg) @inc
	(require_expression (_) @arg) @inc
	(require_once_expression (_) @arg) @inc
] `)

func checkPHPLFIInclude(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpIncludeQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		arg := caps["arg"]
		if arg.Type(phpLang) == "parenthesized_expression" {
			if arg.NamedChildCount() == 0 {
				continue
			}
			arg = arg.NamedChild(0)
		}
		if arg.Type(phpLang) == "string" {
			continue // literal path, not attacker-influenced
		}
		keyword := strings.TrimSuffix(caps["inc"].Type(phpLang), "_expression")
		issues = append(issues, phpIssueAt("php-lfi-include", "HIGH", path,
			"File include path built from a non-literal value", keyword+" argument is not a literal path; this can lead to local/remote file inclusion if attacker-influenced",
			caps["inc"]))
	}
	return issues
}

var phpPregReplaceQuery = mustPHPQuery(`(function_call_expression function: (name) @fn arguments: (arguments . (argument (string (string_content) @pat))) (#eq? @fn "preg_replace")) @call`)

func checkPHPPregReplaceEvalModifier(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpPregReplaceQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		pat := string(caps["pat"].Text(src))
		if !strings.HasSuffix(pat, "e") || len(pat) < 2 {
			continue
		}
		delim := pat[0]
		if delim != '/' && delim != '#' && delim != '~' {
			continue
		}
		// modifiers follow the closing delimiter; check the closing delimiter
		// appears somewhere before the trailing "e" (i.e. "e" is a modifier,
		// not part of the pattern body).
		if strings.LastIndexByte(pat[:len(pat)-1], delim) < 0 {
			continue
		}
		issues = append(issues, phpIssueAt("php-preg-replace-eval-modifier", "HIGH", path,
			"preg_replace with the /e modifier", "the /e modifier evaluates the replacement as PHP code — removed in PHP 7+, but still a critical RCE if present on an older runtime",
			caps["call"]))
	}
	return issues
}

func phpCapMap(m gts.QueryMatch) map[string]*gts.Node {
	out := make(map[string]*gts.Node, len(m.Captures))
	for _, c := range m.Captures {
		out[c.Name] = c.Node
	}
	return out
}
