package sast

import (
	"strings"

	gts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"

	"github.com/colibrisec/ojo/internal/model"
)

var rubyLang = grammars.RubyLanguage()

func mustRubyQuery(src string) *gts.Query {
	q, err := gts.NewQuery(src, rubyLang)
	if err != nil {
		panic("sast: invalid ruby query: " + err.Error())
	}
	return q
}

type rubyRule struct {
	id       string
	severity string
	check    func(root *gts.Node, src []byte, path string) []model.Issue
}

var rubyRules = []rubyRule{
	{"ruby-hardcoded-secret", "MEDIUM", checkRubyHardcodedSecret},
	{"ruby-eval-detected", "HIGH", checkRubyEvalDetected},
	{"ruby-command-injection", "HIGH", checkRubyCommandInjection},
	{"ruby-sql-injection", "HIGH", checkRubySQLInjection},
	{"ruby-weak-hash", "LOW", checkRubyWeakHash},
	{"ruby-weak-cipher", "MEDIUM", checkRubyWeakCipher},
	{"ruby-insecure-deserialization", "HIGH", checkRubyInsecureDeserialization},
	{"ruby-insecure-random-for-secrets", "INFO", checkRubyInsecureRandom},
	{"ruby-tls-verify-disabled", "HIGH", checkRubyTLSVerifyDisabled},
	{"ruby-mass-assignment", "MEDIUM", checkRubyMassAssignment},
	{"ruby-open-redirect", "MEDIUM", checkRubyOpenRedirect},
	{"ruby-jwt-none-algorithm", "HIGH", checkRubyJWTNoneAlgorithm},
	{"ruby-cors-wildcard", "MEDIUM", checkRubyCORSWildcard},
	{"ruby-insecure-cookie", "MEDIUM", checkRubyInsecureCookie},
	{"ruby-path-traversal", "HIGH", checkRubyPathTraversal},
	{"ruby-cookie-missing-flags", "LOW", checkRubyCookieMissingFlags},
	{"ruby-ssrf", "HIGH", checkRubySSRF},
	{"ruby-xxe", "HIGH", checkRubyXXE},
	{"ruby-ssti", "HIGH", checkRubySSTI},
	{"ruby-unsafe-reflection", "HIGH", checkRubyUnsafeReflection},
	{"ruby-predictable-prng-seed", "MEDIUM", checkRubyPredictablePRNGSeed},
}

func rubyIssueAt(id, severity, path, title, message string, n *gts.Node) model.Issue {
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

func rubyIsDynamicString(n *gts.Node, src []byte) bool {
	switch n.Type(rubyLang) {
	case "string", "subshell":
		return hasDescendant(n, rubyLang, "interpolation")
	case "binary":
		op := n.ChildByFieldName("operator", rubyLang)
		return op != nil && string(op.Text(src)) == "+"
	default:
		return false
	}
}

func trimRubyQuotes(s string) string {
	if len(s) >= 2 {
		return s[1 : len(s)-1]
	}
	return s
}

var rubySecretAssignQuery = mustRubyQuery(`(assignment left: (identifier) @name right: (string) @val) @assign`)

func checkRubyHardcodedSecret(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubySecretAssignQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		name := string(caps["name"].Text(src))
		val := caps["val"]
		if !nameLooksSecret(name) || hasDescendant(val, rubyLang, "interpolation") {
			continue
		}
		if len(trimRubyQuotes(string(val.Text(src)))) <= 4 {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-hardcoded-secret", "MEDIUM", path,
			"Hardcoded secret-looking value", "variable "+name+" is assigned a literal string",
			caps["assign"]))
	}
	return issues
}

var rubyEvalQuery = mustRubyQuery(`(call method: (identifier) @m (#eq? @m "eval")) @call`)

// rubyMetaEvalStringQuery matches instance_eval/class_eval/module_eval only
// in their string-argument form (`obj.class_eval("...")`), which executes
// the string as Ruby code — not their much more common block form
// (`klass.class_eval do ... end`), which is ordinary, safe metaprogramming
// used throughout idiomatic Ruby (Rails, RSpec, DSLs). Verified directly:
// the block form parses with a `block` field and no `arguments` field at
// all, while the string form has `arguments` and no `block` — requiring
// `arguments:` here is what keeps the block form out, not a name check.
var rubyMetaEvalStringQuery = mustRubyQuery(`(call method: (identifier) @m arguments: (argument_list . (_) @arg) (#any-of? @m "instance_eval" "class_eval" "module_eval")) @call`)

func checkRubyEvalDetected(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyEvalQuery.ExecuteNode(root, rubyLang, src) {
		issues = append(issues, rubyIssueAt("ruby-eval-detected", "HIGH", path,
			"eval() used", "eval() executes arbitrary code; avoid it on any input that isn't fully trusted",
			rubyCapMap(m)["call"]))
	}
	for _, m := range rubyMetaEvalStringQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		issues = append(issues, rubyIssueAt("ruby-eval-detected", "HIGH", path,
			string(caps["m"].Text(src))+"() used with a string argument",
			string(caps["m"].Text(src))+"(string) executes the string as Ruby code, just like eval(); avoid it on any input that isn't fully trusted (the block form, "+string(caps["m"].Text(src))+" do ... end, is unaffected — this only matches the string-argument call)",
			caps["call"]))
	}
	return issues
}

var (
	rubyCommandCallQuery = mustRubyQuery(`(call method: (identifier) @m arguments: (argument_list . (_) @arg) (#any-of? @m "system" "exec" "spawn" "popen")) @call`)
	rubySubshellQuery    = mustRubyQuery(`(subshell (interpolation) @interp) @sub`)
)

func checkRubyCommandInjection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyCommandCallQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		if !rubyIsDynamicString(caps["arg"], src) && !rubyTaintedArg(caps["arg"], src) {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-command-injection", "HIGH", path,
			"Command built from a non-literal argument",
			string(caps["m"].Text(src))+"(...) argument is built via string interpolation or `+` concatenation instead of a literal, or is a local variable derived from params/env input",
			caps["call"]))
	}
	for _, m := range rubySubshellQuery.ExecuteNode(root, rubyLang, src) {
		issues = append(issues, rubyIssueAt("ruby-command-injection", "HIGH", path,
			"Backtick/%x command with interpolation", "a subshell command (`...`/%x{...}) interpolates a value; this runs through a shell and can be command injection if the value is attacker-influenced",
			rubyCapMap(m)["sub"]))
	}
	return issues
}

var rubySQLCallQuery = mustRubyQuery(`(call method: (identifier) @m arguments: (argument_list . (_) @arg) (#any-of? @m "where" "find_by_sql" "execute" "select_all" "select_one" "exec_query")) @call`)

func checkRubySQLInjection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubySQLCallQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		if !rubyIsDynamicString(caps["arg"], src) && !rubyTaintedArg(caps["arg"], src) {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-sql-injection", "HIGH", path,
			"SQL query built from a non-literal string",
			string(caps["m"].Text(src))+"(...) query argument is built via string interpolation or concatenation instead of a bound parameter, or is a local variable derived from params/env input",
			caps["call"]))
	}
	return issues
}

var rubyDigestQuery = mustRubyQuery(`(call receiver: (scope_resolution scope: (constant) @mod name: (constant) @alg) method: (identifier) @meth (#eq? @mod "Digest") (#any-of? @alg "MD5" "SHA1")) @call`)

func checkRubyWeakHash(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyDigestQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		alg := string(caps["alg"].Text(src))
		issues = append(issues, rubyIssueAt("ruby-weak-hash", "LOW", path,
			"Weak hash algorithm", "Digest::"+alg+" is cryptographically broken; use Digest::SHA256 or stronger",
			caps["call"]))
	}
	return issues
}

var rubyCipherNewQuery = mustRubyQuery(`(call receiver: (scope_resolution) @recv method: (identifier) @meth arguments: (argument_list (string) @alg) (#eq? @recv "OpenSSL::Cipher") (#eq? @meth "new")) @call`)

// checkRubyWeakCipher flags OpenSSL::Cipher.new(...) with a broken cipher
// (DES/RC4) or an insecure mode (ECB) — same name-in-algorithm-string signal
// as go/java/js/php-weak-cipher, against Ruby's OpenSSL algorithm strings.
func checkRubyWeakCipher(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyCipherNewQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		alg := string(caps["alg"].Text(src))
		upper := strings.ToUpper(alg)
		if !strings.Contains(upper, "DES") && !strings.Contains(upper, "RC4") && !strings.Contains(upper, "ECB") {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-weak-cipher", "MEDIUM", path,
			"Weak cipher or insecure mode", "OpenSSL::Cipher.new("+alg+") uses a broken cipher or an insecure mode (ECB); use 'aes-256-gcm' instead",
			caps["call"]))
	}
	return issues
}

var (
	rubyMarshalLoadQuery = mustRubyQuery(`(call receiver: (constant) @recv method: (identifier) @meth (#eq? @recv "Marshal") (#eq? @meth "load")) @call`)
	rubyYAMLLoadQuery    = mustRubyQuery(`(call receiver: (constant) @recv method: (identifier) @meth (#eq? @recv "YAML") (#eq? @meth "load")) @call`)
)

func checkRubyInsecureDeserialization(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyMarshalLoadQuery.ExecuteNode(root, rubyLang, src) {
		issues = append(issues, rubyIssueAt("ruby-insecure-deserialization", "HIGH", path,
			"Insecure deserialization via Marshal.load", "Marshal.load can instantiate arbitrary objects and execute code when given untrusted data; use JSON for plain data",
			rubyCapMap(m)["call"]))
	}
	for _, m := range rubyYAMLLoadQuery.ExecuteNode(root, rubyLang, src) {
		issues = append(issues, rubyIssueAt("ruby-insecure-deserialization", "HIGH", path,
			"Insecure deserialization via YAML.load", "YAML.load (as opposed to YAML.safe_load) can construct arbitrary Ruby objects from untrusted YAML",
			rubyCapMap(m)["call"]))
	}
	return issues
}

var (
	rubyRandCallQuery  = mustRubyQuery(`(call method: (identifier) @m (#eq? @m "rand")) @call`)
	rubyMethodDefQuery = mustRubyQuery(`(method name: (identifier) @fname body: (body_statement) @body) @def`)
)

func checkRubyInsecureRandom(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyMethodDefQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		fname := string(caps["fname"].Text(src))
		if !nameLooksSecret(fname) && !strings.Contains(strings.ToLower(fname), "session") {
			continue
		}
		for _, rm := range rubyRandCallQuery.ExecuteNode(caps["body"], rubyLang, src) {
			issues = append(issues, rubyIssueAt("ruby-insecure-random-for-secrets", "INFO", path,
				"rand() used in a security-sounding method",
				"method "+fname+" uses Kernel#rand, which is not cryptographically secure; consider SecureRandom",
				rubyCapMap(rm)["call"]))
		}
	}
	return issues
}

var rubyVerifyNoneQuery = mustRubyQuery(`(scope_resolution) @scope (#eq? @scope "OpenSSL::SSL::VERIFY_NONE")`)

func checkRubyTLSVerifyDisabled(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyVerifyNoneQuery.ExecuteNode(root, rubyLang, src) {
		issues = append(issues, rubyIssueAt("ruby-tls-verify-disabled", "HIGH", path,
			"TLS certificate verification disabled", "OpenSSL::SSL::VERIFY_NONE disables certificate validation",
			rubyCapMap(m)["scope"]))
	}
	return issues
}

var rubyPermitBangQuery = mustRubyQuery(`(call receiver: (identifier) @recv method: (identifier) @meth (#eq? @recv "params") (#eq? @meth "permit!")) @call`)

func checkRubyMassAssignment(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyPermitBangQuery.ExecuteNode(root, rubyLang, src) {
		issues = append(issues, rubyIssueAt("ruby-mass-assignment", "MEDIUM", path,
			"params.permit! bypasses strong parameters", "permit! whitelists every attribute in params, allowing mass assignment of any model attribute; list permitted keys explicitly instead",
			rubyCapMap(m)["call"]))
	}
	return issues
}

var rubyRedirectToQuery = mustRubyQuery(`(call method: (identifier) @m arguments: (argument_list . (_) @arg) (#eq? @m "redirect_to")) @call`)

func checkRubyOpenRedirect(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyRedirectToQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		arg := caps["arg"]
		if !rubyIsDynamicString(arg, src) && !rubyTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-open-redirect", "MEDIUM", path,
			"Redirect target built from request data", "redirect_to(...) argument is derived from params/request input (directly, or through a local variable) rather than a literal/allowlisted URL",
			caps["call"]))
	}
	return issues
}

var rubyFuncBoundary = map[string]bool{"method": true, "singleton_method": true, "lambda": true, "block": true}

func rubyAssignInfo(n *gts.Node, lang *gts.Language, src []byte) (string, *gts.Node, bool) {
	switch n.Type(rubyLang) {
	case "assignment", "operator_assignment":
		left := n.ChildByFieldName("left", rubyLang)
		right := n.ChildByFieldName("right", rubyLang)
		if left == nil || right == nil || left.Type(rubyLang) != "identifier" {
			return "", nil, false
		}
		return string(left.Text(src)), right, true
	default:
		return "", nil, false
	}
}

// rubyIsEnvSource matches ENV[...]/ENV.fetch(...) by raw text.
func rubyIsEnvSource(n *gts.Node, src []byte) bool {
	text := string(n.Text(src))
	return strings.HasPrefix(text, "ENV[") || strings.HasPrefix(text, "ENV.fetch(")
}

// rubyExprTainted reports whether n evaluates from tainted input: rooted
// at params/request (rubyRootedAtParams), an env-var read, a variable
// already known-tainted in env, or built from any of those via `+`
// concatenation, string interpolation, or a call's arguments.
func rubyExprTainted(n *gts.Node, lang *gts.Language, src []byte, env map[string]bool) bool {
	if n == nil {
		return false
	}
	if rubyRootedAtParams(n, src) || rubyIsEnvSource(n, src) {
		return true
	}
	switch n.Type(rubyLang) {
	case "identifier":
		return env[string(n.Text(src))]
	case "binary":
		op := n.ChildByFieldName("operator", rubyLang)
		if op == nil || string(op.Text(src)) != "+" {
			return false
		}
		return rubyExprTainted(n.ChildByFieldName("left", rubyLang), lang, src, env) || rubyExprTainted(n.ChildByFieldName("right", rubyLang), lang, src, env)
	case "string":
		for _, c := range n.Children() {
			if c.Type(rubyLang) != "interpolation" || c.NamedChildCount() == 0 {
				continue
			}
			if rubyExprTainted(c.NamedChild(0), lang, src, env) {
				return true
			}
		}
		return false
	case "call":
		args := n.ChildByFieldName("arguments", rubyLang)
		if args == nil {
			return false
		}
		for _, a := range args.Children() {
			if rubyExprTainted(a, lang, src, env) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// rubyTaintedArg reports whether arg evaluates from tainted input, tracking
// through local variable assignments within its enclosing method/lambda/
// block (intraprocedural taint tracking — see taint_ts.go).
func rubyTaintedArg(arg *gts.Node, src []byte) bool {
	body := tsEnclosingBody(arg, rubyLang, rubyFuncBoundary)
	env := tsTaintEnv(body, rubyLang, src, rubyFuncBoundary, rubyAssignInfo, rubyExprTainted)
	return rubyExprTainted(arg, rubyLang, src, env)
}

func rubyRootedAtParams(n *gts.Node, src []byte) bool {
	for {
		switch n.Type(rubyLang) {
		case "element_reference":
			n = n.ChildByFieldName("object", rubyLang)
		case "call":
			recv := n.ChildByFieldName("receiver", rubyLang)
			if recv == nil {
				return false
			}
			n = recv
		default:
			if n.Type(rubyLang) != "identifier" {
				return false
			}
			name := string(n.Text(src))
			return name == "params" || name == "request"
		}
		if n == nil {
			return false
		}
	}
}

var (
	rubyJWTPairQuery   = mustRubyQuery(`(pair key: (hash_key_symbol) @key value: (string) @val) @pair`)
	rubyJWTEncodeQuery = mustRubyQuery(`(call receiver: (constant) @recv method: (identifier) @meth arguments: (argument_list (_) (_) (string) @alg) (#eq? @recv "JWT") (#eq? @meth "encode")) @call`)
)

func checkRubyJWTNoneAlgorithm(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyJWTPairQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		if string(caps["key"].Text(src)) != "alg" || trimRubyQuotes(string(caps["val"].Text(src))) != "none" {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-jwt-none-algorithm", "HIGH", path,
			"JWT algorithm set to 'none'", "alg: 'none' accepts unsigned tokens, allowing signature bypass",
			caps["pair"]))
	}
	for _, m := range rubyJWTEncodeQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		if trimRubyQuotes(string(caps["alg"].Text(src))) != "none" {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-jwt-none-algorithm", "HIGH", path,
			"JWT algorithm set to 'none'", "JWT.encode(..., 'none') accepts unsigned tokens, allowing signature bypass",
			caps["call"]))
	}
	return issues
}

var rubyHeaderAssignQuery = mustRubyQuery(`(assignment left: (element_reference object: (_) @recv (string) @key) right: (string) @val) @assign`)

func checkRubyCORSWildcard(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyHeaderAssignQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		if !strings.Contains(strings.ToLower(string(caps["recv"].Text(src))), "headers") {
			continue
		}
		key := trimRubyQuotes(string(caps["key"].Text(src)))
		val := trimRubyQuotes(string(caps["val"].Text(src)))
		if !strings.EqualFold(key, "Access-Control-Allow-Origin") || val != "*" {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-cors-wildcard", "MEDIUM", path,
			"CORS allow-origin set to wildcard", "headers['Access-Control-Allow-Origin'] = '*' allows any origin to make credentialed cross-origin requests",
			caps["assign"]))
	}
	return issues
}

var rubyCookieBoolPairQuery = mustRubyQuery(`(pair key: (hash_key_symbol) @key value: (false)) @pair`)

func checkRubyInsecureCookie(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyCookieBoolPairQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		key := strings.ToLower(string(caps["key"].Text(src)))
		if key != "secure" && key != "httponly" {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-insecure-cookie", "MEDIUM", path,
			"Cookie flag explicitly disabled", key+": false weakens cookie protection",
			caps["pair"]))
	}
	return issues
}

var rubyFileOpenQuery = mustRubyQuery(`(call receiver: (constant) @recv method: (identifier) @meth arguments: (argument_list . (_) @arg) (#eq? @recv "File") (#any-of? @meth "open" "read")) @call`)

func checkRubyPathTraversal(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyFileOpenQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		arg := caps["arg"]
		if !rubyIsDynamicString(arg, src) && !rubyTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-path-traversal", "HIGH", path,
			"File path built from request data", "File."+string(caps["meth"].Text(src))+"(...) path is derived from params/request input (directly, or through a local variable) or built via interpolation/concatenation rather than a validated literal; sanitize/allowlist before use",
			caps["call"]))
	}
	return issues
}

var (
	rubyNetHTTPGetQuery = mustRubyQuery(`(call receiver: (scope_resolution scope: (constant) @mod name: (constant) @cls) method: (identifier) @meth arguments: (argument_list . (_) @arg) (#eq? @mod "Net") (#eq? @cls "HTTP") (#eq? @meth "get")) @call`)
	rubyURIOpenQuery    = mustRubyQuery(`(call receiver: (constant) @mod method: (identifier) @meth arguments: (argument_list . (_) @arg) (#eq? @mod "URI") (#eq? @meth "open")) @call`)
)

func checkRubySSRF(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyNetHTTPGetQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		arg := caps["arg"]
		if !rubyIsDynamicString(arg, src) && !rubyTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-ssrf", "HIGH", path,
			"Outbound request URL built from request data",
			"Net::HTTP.get(...) URL argument is derived from params/env input (directly, or through a local variable) or built via interpolation/concatenation rather than a validated/allowlisted URL",
			caps["call"]))
	}
	for _, m := range rubyURIOpenQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		arg := caps["arg"]
		if !rubyIsDynamicString(arg, src) && !rubyTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-ssrf", "HIGH", path,
			"Outbound request URL built from request data",
			"URI.open(...) URL argument is derived from params/env input (directly, or through a local variable) or built via interpolation/concatenation rather than a validated/allowlisted URL",
			caps["call"]))
	}
	return issues
}

var (
	rubyNoentConstQuery = mustRubyQuery(`(scope_resolution name: (constant) @c (#eq? @c "NOENT")) @ref`)
	rubyNoentCallQuery  = mustRubyQuery(`(call method: (identifier) @m (#eq? @m "noent")) @call`)
)

func checkRubyXXE(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyNoentConstQuery.ExecuteNode(root, rubyLang, src) {
		issues = append(issues, rubyIssueAt("ruby-xxe", "HIGH", path,
			"XML entity substitution enabled", "Nokogiri::XML::ParseOptions::NOENT enables entity substitution, allowing XXE when parsing untrusted XML",
			rubyCapMap(m)["ref"]))
	}
	for _, m := range rubyNoentCallQuery.ExecuteNode(root, rubyLang, src) {
		issues = append(issues, rubyIssueAt("ruby-xxe", "HIGH", path,
			"XML entity substitution enabled", "config.noent enables entity substitution in a Nokogiri parse-options block, allowing XXE when parsing untrusted XML",
			rubyCapMap(m)["call"]))
	}
	return issues
}

var rubyERBNewQuery = mustRubyQuery(`(call receiver: (constant) @mod method: (identifier) @meth arguments: (argument_list . (_) @arg) (#eq? @mod "ERB") (#eq? @meth "new")) @call`)

func checkRubySSTI(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyERBNewQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		arg := caps["arg"]
		if !rubyIsDynamicString(arg, src) && !rubyTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-ssti", "HIGH", path,
			"Template source built from request data",
			"ERB.new(...) argument is derived from params/env input (directly, or through a local variable) or built via interpolation/concatenation — the template source itself is attacker-controlled, which is server-side template injection, not just a data-substitution issue",
			caps["call"]))
	}
	return issues
}

var rubySendQuery = mustRubyQuery(`(call method: (identifier) @m arguments: (argument_list . (_) @arg) (#any-of? @m "send" "public_send" "__send__")) @call`)

// checkRubyUnsafeReflection flags .send/.public_send/.__send__ when the
// method-name argument is itself tainted (request/env-derived, directly or
// through a local variable) — arbitrary method invocation, a well-known
// Ruby/Rails RCE-adjacent gadget class. Not gated on rubyIsDynamicString:
// the overwhelmingly common, safe usage is a literal symbol
// (`obj.send(:foo)`), which never matches either dynamic-string or taint
// shape, so only the taint check is needed and it stays quiet on that idiom.
func checkRubyUnsafeReflection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubySendQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		arg := caps["arg"]
		if !rubyTaintedArg(arg, src) {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-unsafe-reflection", "HIGH", path,
			"Method invoked by an attacker-controlled name",
			string(caps["m"].Text(src))+"(...) method-name argument is derived from params/env input (directly, or through a local variable) — this calls whatever method name an attacker supplies, letting them invoke methods the application never intended to expose",
			caps["call"]))
	}
	return issues
}

var rubySrandQuery = mustRubyQuery(`(call method: (identifier) @m arguments: (argument_list . (integer)) (#eq? @m "srand")) @call`)

// checkRubyPredictablePRNGSeed flags srand(<literal>) — a fixed seed makes
// every subsequent Kernel#rand value fully predictable (distinct from
// ruby-insecure-random-for-secrets, which flags the module choice, not the
// seed). srand() with no args is unaffected.
func checkRubyPredictablePRNGSeed(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubySrandQuery.ExecuteNode(root, rubyLang, src) {
		issues = append(issues, rubyIssueAt("ruby-predictable-prng-seed", "MEDIUM", path,
			"PRNG seeded with a hardcoded literal",
			"srand(...) is called with a compile-time integer literal; every run produces the same sequence, making all subsequent output predictable",
			rubyCapMap(m)["call"]))
	}
	return issues
}

var rubyCookieAssignQuery = mustRubyQuery(`(assignment left: (element_reference object: (_) @recv) right: (_) @val) @assign`)

func checkRubyCookieMissingFlags(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyCookieAssignQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		if !strings.Contains(strings.ToLower(string(caps["recv"].Text(src))), "cookies") {
			continue
		}
		val := caps["val"]
		if val.Type(rubyLang) != "hash" {
			issues = append(issues, rubyIssueAt("ruby-cookie-missing-flags", "LOW", path,
				"Cookie set without secure/httponly options", "cookies[...] = ... assigns a plain value instead of a hash with secure/httponly options; both default to false, weakening cookie protection",
				caps["assign"]))
			continue
		}
		has := map[string]bool{}
		for _, c := range val.Children() {
			if c.Type(rubyLang) != "pair" {
				continue
			}
			key := c.ChildByFieldName("key", rubyLang)
			if key != nil {
				has[strings.ToLower(string(key.Text(src)))] = true
			}
		}
		for _, flag := range []string{"secure", "httponly"} {
			if has[flag] {
				continue
			}
			issues = append(issues, rubyIssueAt("ruby-cookie-missing-flags", "LOW", path,
				flag+" not set on cookie options", "cookies[...] = {...} doesn't set "+flag+"; it defaults to false, weakening cookie protection unless set elsewhere",
				val))
		}
	}
	return issues
}

func rubyCapMap(m gts.QueryMatch) map[string]*gts.Node {
	out := make(map[string]*gts.Node, len(m.Captures))
	for _, c := range m.Captures {
		out[c.Name] = c.Node
	}
	return out
}
