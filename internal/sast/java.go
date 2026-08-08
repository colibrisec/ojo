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
		if !javaIsDynamicString(caps["arg"], src) {
			continue
		}
		issues = append(issues, javaIssueAt("java-command-injection", "HIGH", path,
			"Command built from a non-literal argument",
			"Runtime.getRuntime().exec(...) argument is built via `+` concatenation instead of a literal/argument array",
			caps["call"]))
	}
	for _, m := range javaProcessBuilderQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		if !javaIsDynamicString(caps["arg"], src) {
			continue
		}
		issues = append(issues, javaIssueAt("java-command-injection", "HIGH", path,
			"Command built from a non-literal argument",
			"new ProcessBuilder(...) argument is built via `+` concatenation instead of a literal/argument array",
			caps["call"]))
	}
	return issues
}

var javaStatementExecuteQuery = mustJavaQuery(`(method_invocation name: (identifier) @m arguments: (argument_list . (_) @arg) (#any-of? @m "execute" "executeQuery" "executeUpdate")) @call`)

func checkJavaSQLInjection(root *gts.Node, src []byte, path string) []model.Issue {
	var issues []model.Issue
	for _, m := range javaStatementExecuteQuery.ExecuteNode(root, javaLang, src) {
		caps := javaCapMap(m)
		if !javaIsDynamicString(caps["arg"], src) {
			continue
		}
		issues = append(issues, javaIssueAt("java-sql-injection", "HIGH", path,
			"SQL query built from a non-literal string",
			string(caps["m"].Text(src))+"(...) query argument is built via `+` concatenation instead of a PreparedStatement placeholder",
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

func javaCapMap(m gts.QueryMatch) map[string]*gts.Node {
	out := make(map[string]*gts.Node, len(m.Captures))
	for _, c := range m.Captures {
		out[c.Name] = c.Node
	}
	return out
}
