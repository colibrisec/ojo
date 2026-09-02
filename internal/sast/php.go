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
	{"php-weak-cipher", "MEDIUM", checkPHPWeakCipher},
	{"php-insecure-deserialization", "HIGH", checkPHPUnserialize},
	{"php-insecure-random-for-secrets", "INFO", checkPHPInsecureRandom},
	{"php-tls-verify-disabled", "HIGH", checkPHPTLSVerifyDisabled},
	{"php-lfi-include", "HIGH", checkPHPLFIInclude},
	{"php-preg-replace-eval-modifier", "HIGH", checkPHPPregReplaceEvalModifier},
	{"php-open-redirect", "MEDIUM", checkPHPOpenRedirect},
	{"php-jwt-none-algorithm", "HIGH", checkPHPJWTNoneAlgorithm},
	{"php-cors-wildcard", "MEDIUM", checkPHPCORSWildcard},
	{"php-insecure-cookie", "MEDIUM", checkPHPInsecureCookie},
	{"php-cookie-missing-flags", "LOW", checkPHPCookieMissingFlags},
	{"php-ssrf", "HIGH", checkPHPSSRF},
	{"php-xxe", "HIGH", checkPHPXXE},
	{"php-nosqli", "HIGH", checkPHPNoSQLi},
	{"php-unsafe-reflection", "HIGH", checkPHPUnsafeReflection},
	{"php-predictable-prng-seed", "MEDIUM", checkPHPPredictablePRNGSeed},
	{"php-mass-assignment", "MEDIUM", checkPHPMassAssignment},
	{"php-empty-exception-handler", "MEDIUM", checkPHPEmptyExceptionHandler},
	{"php-empty-block", "LOW", checkPHPEmptyBlock},
	{"php-unreachable-code", "LOW", checkPHPUnreachableCode},
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

var phpFuncBoundary = map[string]bool{
	"function_definition": true, "method_declaration": true,
	"anonymous_function": true, "arrow_function": true,
}

var phpSuperglobals = map[string]bool{
	"$_GET": true, "$_POST": true, "$_REQUEST": true, "$_COOKIE": true, "$_SERVER": true, "$_FILES": true,
}

// phpRootedAtSuperglobal unwraps `$_GET['x']`-shaped subscript chains down
// to a bare variable_name, and reports whether that name is one of PHP's
// superglobal arrays. subscript_expression's base has no field name in
// this grammar (verified directly), hence NamedChild(0) rather than
// ChildByFieldName.
func phpRootedAtSuperglobal(n *gts.Node, src []byte) bool {
	for {
		switch n.Type(phpLang) {
		case "subscript_expression":
			if n.NamedChildCount() == 0 {
				return false
			}
			n = n.NamedChild(0)
		case "variable_name":
			return phpSuperglobals[string(n.Text(src))]
		default:
			return false
		}
		if n == nil {
			return false
		}
	}
}

// phpIsEnvSource matches getenv(...) by raw text.
func phpIsEnvSource(n *gts.Node, src []byte) bool {
	return strings.HasPrefix(string(n.Text(src)), "getenv(")
}

func phpAssignInfo(n *gts.Node, lang *gts.Language, src []byte) (string, *gts.Node, bool) {
	if n.Type(phpLang) != "assignment_expression" {
		return "", nil, false
	}
	left := n.ChildByFieldName("left", phpLang)
	right := n.ChildByFieldName("right", phpLang)
	if left == nil || right == nil || left.Type(phpLang) != "variable_name" {
		return "", nil, false
	}
	return string(left.Text(src)), right, true
}

// phpExprTainted reports whether n evaluates from tainted input: rooted at
// a superglobal (phpRootedAtSuperglobal), an env-var read, a variable
// already known-tainted in env, or built from any of those via `.`
// concatenation or a function call's arguments.
func phpExprTainted(n *gts.Node, lang *gts.Language, src []byte, env map[string]bool) bool {
	if n == nil {
		return false
	}
	if phpRootedAtSuperglobal(n, src) || phpIsEnvSource(n, src) {
		return true
	}
	switch n.Type(phpLang) {
	case "variable_name":
		return env[string(n.Text(src))]
	case "binary_expression":
		return phpExprTainted(n.ChildByFieldName("left", phpLang), lang, src, env) || phpExprTainted(n.ChildByFieldName("right", phpLang), lang, src, env)
	case "function_call_expression":
		args := n.ChildByFieldName("arguments", phpLang)
		if args == nil {
			return false
		}
		for _, a := range args.Children() {
			inner := a
			if a.Type(phpLang) == "argument" && a.NamedChildCount() > 0 {
				inner = a.NamedChild(0)
			}
			if phpExprTainted(inner, lang, src, env) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// phpTaintedArg reports whether arg evaluates from tainted input, tracking
// through local variable assignments within its enclosing function/method/
// closure (intraprocedural taint tracking — see taint_ts.go).
func phpTaintedArg(arg *gts.Node, src []byte) bool {
	body := tsEnclosingBody(arg, phpLang, phpFuncBoundary)
	env := tsTaintEnv(body, phpLang, src, phpFuncBoundary, phpAssignInfo, phpExprTainted)
	return phpExprTainted(arg, phpLang, src, env)
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
		if !phpIsDynamicString(caps["arg"]) && !phpTaintedArg(caps["arg"], src) {
			continue
		}
		fname := string(caps["fname"].Text(src))
		issues = append(issues, phpIssueAt("php-command-injection", "HIGH", path,
			"Command built from a non-literal argument",
			fname+"() argument is built via string concatenation or interpolation instead of a literal, or is a local variable derived from a superglobal/env input",
			caps["call"]))
	}
	return issues
}

var phpSQLMemberCallQuery = mustPHPQuery(`(member_call_expression name: (name) @meth arguments: (arguments . (argument (_) @arg)) (#any-of? @meth "query" "exec")) @call`)

func checkPHPSQLInjection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpSQLMemberCallQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		if !phpIsDynamicString(caps["arg"]) && !phpTaintedArg(caps["arg"], src) {
			continue
		}
		issues = append(issues, phpIssueAt("php-sql-injection", "HIGH", path,
			"SQL query built from a non-literal string",
			"->"+string(caps["meth"].Text(src))+"(...) query argument is built via concatenation/interpolation instead of a prepared statement placeholder, or is a local variable derived from a superglobal/env input",
			caps["call"]))
	}
	return issues
}

var (
	phpHashFuncQuery    = mustPHPQuery(`(function_call_expression function: (name) @fname) @call`)
	phpHashWithAlgQuery = mustPHPQuery(`(function_call_expression function: (name) @fname arguments: (arguments . (argument (string) @alg)) (#eq? @fname "hash")) @call`)
)

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

var phpOpensslCipherQuery = mustPHPQuery(`(function_call_expression function: (name) @fname arguments: (arguments . (argument (_)) . (argument (string) @alg)) (#any-of? @fname "openssl_encrypt" "openssl_decrypt")) @call`)

// checkPHPWeakCipher flags openssl_encrypt/openssl_decrypt's second
// (cipher-method) argument naming a broken cipher (DES/RC4) or an insecure
// mode (ECB) — same name-in-algorithm-string signal as
// java-weak-cipher/js-weak-cipher, against PHP's OpenSSL method strings.
func checkPHPWeakCipher(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpOpensslCipherQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		alg := trimPHPQuotes(string(caps["alg"].Text(src)))
		upper := strings.ToUpper(alg)
		if !strings.Contains(upper, "DES") && !strings.Contains(upper, "RC4") && !strings.Contains(upper, "ECB") {
			continue
		}
		issues = append(issues, phpIssueAt("php-weak-cipher", "MEDIUM", path,
			"Weak cipher or insecure mode", string(caps["fname"].Text(src))+"(..., '"+alg+"', ...) uses a broken cipher or an insecure mode (ECB); use 'aes-256-gcm' instead",
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

var (
	phpRandFuncQuery = mustPHPQuery(`(function_call_expression function: (name) @fname (#any-of? @fname "rand" "mt_rand")) @call`)
	phpFuncDefQuery  = mustPHPQuery(`(function_definition name: (name) @fname body: (compound_statement) @body) @def`)
)

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

var (
	phpVerifyPeerFalseQuery = mustPHPQuery(`(array_element_initializer (string) @key (boolean) @val (#any-of? @key "'verify_peer'" "'verify_peer_name'" "\"verify_peer\"" "\"verify_peer_name\"")) @pair`)
	phpCurlSSLVerifyQuery   = mustPHPQuery(`(function_call_expression function: (name) @fn arguments: (arguments (argument (variable_name)) (argument (name) @opt) (argument (boolean) @val)) (#eq? @fn "curl_setopt") (#any-of? @opt "CURLOPT_SSL_VERIFYPEER" "CURLOPT_SSL_VERIFYHOST")) @call`)
)

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
		if strings.LastIndexByte(pat[:len(pat)-1], delim) < 0 {
			continue
		}
		issues = append(issues, phpIssueAt("php-preg-replace-eval-modifier", "HIGH", path,
			"preg_replace with the /e modifier", "the /e modifier evaluates the replacement as PHP code — removed in PHP 7+, but still a critical RCE if present on an older runtime",
			caps["call"]))
	}
	return issues
}

var (
	phpFileGetContentsQuery = mustPHPQuery(`(function_call_expression function: (name) @fname arguments: (arguments . (argument (_) @arg)) (#eq? @fname "file_get_contents")) @call`)
	phpCurlURLQuery         = mustPHPQuery(`(function_call_expression function: (name) @fn arguments: (arguments (argument (variable_name)) (argument (name) @opt) (argument (_) @arg)) (#eq? @fn "curl_setopt") (#eq? @opt "CURLOPT_URL")) @call`)
)

func checkPHPSSRF(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpFileGetContentsQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		arg := caps["arg"]
		if !phpIsDynamicString(arg) && !phpTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, phpIssueAt("php-ssrf", "HIGH", path,
			"Outbound request URL built from a non-literal value",
			"file_get_contents(...) argument is built via concatenation/interpolation, or is a local variable derived from a superglobal/env input, rather than a validated/allowlisted URL",
			caps["call"]))
	}
	for _, m := range phpCurlURLQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		arg := caps["arg"]
		if !phpIsDynamicString(arg) && !phpTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, phpIssueAt("php-ssrf", "HIGH", path,
			"Outbound request URL built from a non-literal value",
			"curl_setopt(..., CURLOPT_URL, ...) value is built via concatenation/interpolation, or is a local variable derived from a superglobal/env input, rather than a validated/allowlisted URL",
			caps["call"]))
	}
	return issues
}

var phpDisableEntityLoaderQuery = mustPHPQuery(`(function_call_expression function: (name) @fname arguments: (arguments . (argument (boolean) @val)) (#eq? @fname "libxml_disable_entity_loader")) @call`)

func checkPHPXXE(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpDisableEntityLoaderQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		if string(caps["val"].Text(src)) != "false" {
			continue
		}
		issues = append(issues, phpIssueAt("php-xxe", "HIGH", path,
			"XML external entity loading explicitly enabled", "libxml_disable_entity_loader(false) re-enables external XML entity loading, allowing XXE when parsing untrusted XML",
			caps["call"]))
	}
	return issues
}

var phpMongoQueryCallQuery = mustPHPQuery(`(member_call_expression name: (name) @meth arguments: (arguments . (argument (_) @arg)) (#any-of? @meth "find" "findOne" "updateOne" "updateMany" "deleteOne" "deleteMany")) @call`)

// checkPHPNoSQLi flags a MongoDB driver query/update/delete call whose
// filter argument is entirely superglobal/env-derived, not a literal
// filter with individually-typed fields — a different shape from SQL
// injection (no concatenation to point at; the whole filter array being
// attacker-controlled is what lets operators like $ne/$gt through).
func checkPHPNoSQLi(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpMongoQueryCallQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		arg := caps["arg"]
		if !phpTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, phpIssueAt("php-nosqli", "HIGH", path,
			"MongoDB query filter built entirely from request data",
			"->"+string(caps["meth"].Text(src))+"(...) filter argument is derived from a superglobal/env input rather than a literal filter with individually-typed fields — passing the whole request payload as a MongoDB filter lets an attacker inject query operators (e.g. $ne, $gt) to bypass intended matching",
			caps["call"]))
	}
	return issues
}

var phpCallUserFuncQuery = mustPHPQuery(`(function_call_expression function: (name) @fname arguments: (arguments . (argument (_) @arg)) (#any-of? @fname "call_user_func" "call_user_func_array")) @call`)

// checkPHPUnsafeReflection flags call_user_func(_array) when the callback
// argument is itself tainted (superglobal/env-derived, directly or through
// a local variable) — calling an attacker-chosen function/method name,
// same "arbitrary invocation" gadget class as Ruby's send(tainted).
func checkPHPUnsafeReflection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpCallUserFuncQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		arg := caps["arg"]
		if !phpTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, phpIssueAt("php-unsafe-reflection", "HIGH", path,
			"Function invoked by an attacker-controlled name",
			string(caps["fname"].Text(src))+"(...) callback argument is derived from a superglobal/env input (directly, or through a local variable) — this calls whatever function/method name an attacker supplies",
			caps["call"]))
	}
	return issues
}

var phpSrandQuery = mustPHPQuery(`(function_call_expression function: (name) @fname arguments: (arguments . (argument (integer))) (#any-of? @fname "srand" "mt_srand")) @call`)

// checkPHPPredictablePRNGSeed flags srand(<literal>)/mt_srand(<literal>) —
// a fixed seed makes every subsequent rand()/mt_rand() value fully
// predictable (distinct from php-insecure-random-for-secrets, which flags
// the function choice, not the seed). Called with no args (the normal,
// safe usage) is unaffected.
func checkPHPPredictablePRNGSeed(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpSrandQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		fname := string(caps["fname"].Text(src))
		issues = append(issues, phpIssueAt("php-predictable-prng-seed", "MEDIUM", path,
			"PRNG seeded with a hardcoded literal",
			fname+"(...) is called with a compile-time integer literal; every run produces the same sequence, making all subsequent output predictable",
			caps["call"]))
	}
	return issues
}

var phpHeaderCallQuery = mustPHPQuery(`(function_call_expression function: (name) @fname arguments: (arguments . (argument (_) @arg)) (#eq? @fname "header")) @call`)

func checkPHPOpenRedirect(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpHeaderCallQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		arg := caps["arg"]
		text := strings.ToLower(string(arg.Text(src)))
		if !strings.Contains(text, "location:") || !phpIsDynamicString(arg) {
			continue
		}
		issues = append(issues, phpIssueAt("php-open-redirect", "MEDIUM", path,
			"Redirect target built from a non-literal value",
			`header("Location: ...") value is built via concatenation/interpolation instead of a literal/allowlisted URL`,
			caps["call"]))
	}
	return issues
}

func checkPHPCORSWildcard(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpHeaderCallQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		text := strings.ToLower(strings.TrimSpace(trimPHPQuotes(string(caps["arg"].Text(src)))))
		if !strings.Contains(text, "access-control-allow-origin") || !strings.HasSuffix(text, "*") {
			continue
		}
		issues = append(issues, phpIssueAt("php-cors-wildcard", "MEDIUM", path,
			"CORS allow-origin set to wildcard",
			`header("Access-Control-Allow-Origin: *") allows any origin to make credentialed cross-origin requests`,
			caps["call"]))
	}
	return issues
}

var phpArrayPairQuery = mustPHPQuery(`(array_element_initializer (string) @key (string) @val) @pair`)

func checkPHPJWTNoneAlgorithm(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpArrayPairQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		key := strings.ToLower(trimPHPQuotes(string(caps["key"].Text(src))))
		val := strings.ToLower(trimPHPQuotes(string(caps["val"].Text(src))))
		if key != "alg" || val != "none" {
			continue
		}
		issues = append(issues, phpIssueAt("php-jwt-none-algorithm", "HIGH", path,
			"JWT algorithm set to 'none'", "'alg' => 'none' accepts unsigned tokens, allowing signature bypass",
			caps["pair"]))
	}
	return issues
}

var phpBoolArrayPairQuery = mustPHPQuery(`(array_element_initializer (string) @key (boolean) @val) @pair`)

func checkPHPInsecureCookie(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpBoolArrayPairQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		key := strings.ToLower(trimPHPQuotes(string(caps["key"].Text(src))))
		val := string(caps["val"].Text(src))
		if (key != "secure" && key != "httponly") || val != "false" {
			continue
		}
		issues = append(issues, phpIssueAt("php-insecure-cookie", "MEDIUM", path,
			"Cookie flag explicitly disabled", "'"+key+"' => false weakens cookie protection",
			caps["pair"]))
	}
	return issues
}

var phpSetCookieCallQuery = mustPHPQuery(`(function_call_expression function: (name) @fname arguments: (arguments) @args (#eq? @fname "setcookie")) @call`)

func checkPHPCookieMissingFlags(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpSetCookieCallQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		var argExprs []*gts.Node
		for _, c := range caps["args"].Children() {
			if c.Type(phpLang) == "argument" && c.NamedChildCount() > 0 {
				argExprs = append(argExprs, c.NamedChild(0))
			}
		}
		if len(argExprs) >= 3 && argExprs[2].Type(phpLang) == "array_creation_expression" {
			has := map[string]bool{}
			for _, c := range argExprs[2].Children() {
				if c.Type(phpLang) != "array_element_initializer" || c.NamedChildCount() < 1 {
					continue
				}
				has[strings.ToLower(trimPHPQuotes(string(c.NamedChild(0).Text(src))))] = true
			}
			for _, flag := range []string{"secure", "httponly"} {
				if has[flag] {
					continue
				}
				issues = append(issues, phpIssueAt("php-cookie-missing-flags", "LOW", path,
					"'"+flag+"' not set on setcookie options", "setcookie(..., array $options) doesn't set '"+flag+"'; it defaults to false, weakening cookie protection unless set elsewhere",
					caps["call"]))
			}
			continue
		}
		if len(argExprs) < 6 {
			issues = append(issues, phpIssueAt("php-cookie-missing-flags", "LOW", path,
				"secure/httponly not passed to setcookie", "setcookie(...) is missing the trailing $secure/$httponly parameters; they default to false, weakening cookie protection",
				caps["call"]))
		} else if len(argExprs) < 7 {
			issues = append(issues, phpIssueAt("php-cookie-missing-flags", "LOW", path,
				"httponly not passed to setcookie", "setcookie(...) is missing the trailing $httponly parameter; it defaults to false, weakening cookie protection",
				caps["call"]))
		}
	}
	return issues
}

// phpMassAssignInstanceQuery matches Laravel's instance-method mass-assignment
// sinks: $model->fill($request->all())/->update(...)/->forceFill(...).
// phpMassAssignStaticQuery matches the static form: Model::create(...).
// Both require the argument to be a direct ->all() call — a real filter
// array (even one built from request data per-key) doesn't match, same
// "whole-argument, not a value inside it" shape as ruby-mass-assignment and
// the NoSQLi rules' *TaintedArg checks.
var (
	phpMassAssignInstanceQuery = mustPHPQuery(`(member_call_expression name: (name) @meth arguments: (arguments . (argument (member_call_expression name: (name) @innerMeth))) (#any-of? @meth "fill" "update" "forceFill") (#eq? @innerMeth "all")) @call`)
	phpMassAssignStaticQuery   = mustPHPQuery(`(scoped_call_expression name: (name) @meth arguments: (arguments . (argument (member_call_expression name: (name) @innerMeth))) (#eq? @meth "create") (#eq? @innerMeth "all")) @call`)
)

func checkPHPMassAssignment(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpMassAssignInstanceQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		meth := string(caps["meth"].Text(src))
		issues = append(issues, phpIssueAt("php-mass-assignment", "MEDIUM", path,
			"Mass assignment from unfiltered request input", "->"+meth+"($request->all()) assigns every request field to the model, including ones a real form never exposes; use $request->only([...]) or a $fillable/$guarded allowlist",
			caps["call"]))
	}
	for _, m := range phpMassAssignStaticQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		issues = append(issues, phpIssueAt("php-mass-assignment", "MEDIUM", path,
			"Mass assignment from unfiltered request input", "::create($request->all()) assigns every request field to the model, including ones a real form never exposes; use $request->only([...]) or a $fillable/$guarded allowlist",
			caps["call"]))
	}
	return issues
}

// checkPHPEmptyExceptionHandler flags an empty catch block, which silently
// swallows whatever it caught — SonarQube's S2486/S1166 shape.
var phpCatchQuery = mustPHPQuery(`(catch_clause body: (compound_statement) @body) @catch`)

func checkPHPEmptyExceptionHandler(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpCatchQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		if caps["body"].NamedChildCount() > 0 {
			continue
		}
		issues = append(issues, phpIssueAt("php-empty-exception-handler", "MEDIUM", path,
			"Empty catch block", "catch (...) { } silently swallows the exception, hiding real failures; at minimum log it",
			caps["catch"]))
	}
	return issues
}

// checkPHPEmptyBlock flags an if/else/while/for body with no statements at
// all (SonarQube's S108) — almost always dead code, or (in the if-branch
// case) a silently-swallowed condition.
var (
	phpIfBodyQuery   = mustPHPQuery(`(if_statement body: (compound_statement) @body) @stmt`)
	phpElseBodyQuery = mustPHPQuery(`(else_clause body: (compound_statement) @body) @stmt`)
	phpWhileQuery    = mustPHPQuery(`(while_statement body: (compound_statement) @body) @stmt`)
	phpForBodyQuery  = mustPHPQuery(`(for_statement body: (compound_statement) @body) @stmt`)
)

func checkPHPEmptyBlock(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for shape, q := range map[string]*gts.Query{
		"if": phpIfBodyQuery, "else": phpElseBodyQuery, "while": phpWhileQuery, "for": phpForBodyQuery,
	} {
		for _, m := range q.ExecuteNode(root, phpLang, src) {
			caps := phpCapMap(m)
			if caps["body"].NamedChildCount() > 0 {
				continue
			}
			issues = append(issues, phpIssueAt("php-empty-block", "LOW", path,
				"Empty "+shape+" block", shape+" body has no statements — likely dead code, or (if this is an error check) a silently-swallowed condition",
				caps["stmt"]))
		}
	}
	return issues
}

// checkPHPUnreachableCode flags a statement immediately following a
// return/throw/break/continue in the same block — SonarQube's S1763. PHP's
// grammar represents `throw` as an expression_statement wrapping a
// throw_expression, not a dedicated throw_statement type the way
// Java/JS/Python do — verified against a real parse tree before writing
// this query, not assumed from the other languages' shape.
var phpUnreachableQuery = mustPHPQuery(`(compound_statement [(expression_statement (throw_expression)) (return_statement) (break_statement) (continue_statement)] @term . (_) @after)`)

func checkPHPUnreachableCode(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range phpUnreachableQuery.ExecuteNode(root, phpLang, src) {
		caps := phpCapMap(m)
		issues = append(issues, phpIssueAt("php-unreachable-code", "LOW", path,
			"Unreachable code", "this statement can never execute; it follows a "+string(caps["term"].Text(src))+" in the same block",
			caps["after"]))
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
