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
	{"ruby-insecure-deserialization", "HIGH", checkRubyInsecureDeserialization},
	{"ruby-insecure-random-for-secrets", "INFO", checkRubyInsecureRandom},
	{"ruby-tls-verify-disabled", "HIGH", checkRubyTLSVerifyDisabled},
	{"ruby-mass-assignment", "MEDIUM", checkRubyMassAssignment},
	{"ruby-open-redirect", "MEDIUM", checkRubyOpenRedirect},
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

func checkRubyEvalDetected(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyEvalQuery.ExecuteNode(root, rubyLang, src) {
		issues = append(issues, rubyIssueAt("ruby-eval-detected", "HIGH", path,
			"eval() used", "eval() executes arbitrary code; avoid it on any input that isn't fully trusted",
			rubyCapMap(m)["call"]))
	}
	return issues
}

var (
	rubyCommandCallQuery = mustRubyQuery(`(call method: (identifier) @m arguments: (argument_list . (_) @arg) (#any-of? @m "system" "exec" "spawn")) @call`)
	rubySubshellQuery    = mustRubyQuery(`(subshell (interpolation) @interp) @sub`)
)

func checkRubyCommandInjection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range rubyCommandCallQuery.ExecuteNode(root, rubyLang, src) {
		caps := rubyCapMap(m)
		if !rubyIsDynamicString(caps["arg"], src) {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-command-injection", "HIGH", path,
			"Command built from a non-literal argument",
			string(caps["m"].Text(src))+"(...) argument is built via string interpolation or `+` concatenation instead of a literal",
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
		if !rubyIsDynamicString(caps["arg"], src) {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-sql-injection", "HIGH", path,
			"SQL query built from a non-literal string",
			string(caps["m"].Text(src))+"(...) query argument is built via string interpolation or concatenation instead of a bound parameter",
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
		if !rubyIsDynamicString(arg, src) && !rubyRootedAtParams(arg, src) {
			continue
		}
		issues = append(issues, rubyIssueAt("ruby-open-redirect", "MEDIUM", path,
			"Redirect target built from request data", "redirect_to(...) argument is derived from params/request input rather than a literal/allowlisted URL",
			caps["call"]))
	}
	return issues
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

func rubyCapMap(m gts.QueryMatch) map[string]*gts.Node {
	out := make(map[string]*gts.Node, len(m.Captures))
	for _, c := range m.Captures {
		out[c.Name] = c.Node
	}
	return out
}
