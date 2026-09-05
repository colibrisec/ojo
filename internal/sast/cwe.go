package sast

import "strings"

// sastLangPrefixes are the per-language prefixes on every sast rule ID
// (go-sql-injection, java-sql-injection, js-sql-injection, ...). Rule IDs
// share the same category suffix across languages, so categoryCWEs is
// keyed by category instead of repeating each CWE six times over.
var sastLangPrefixes = []string{"go-", "java-", "js-", "php-", "py-", "ruby-"}

var categoryCWEs = map[string][]string{
	"hardcoded-secret":                {"CWE-798"},
	"command-injection":               {"CWE-78"},
	"sql-injection":                   {"CWE-89"},
	"nosqli":                          {"CWE-943"},
	"weak-hash":                       {"CWE-328"},
	"weak-cipher":                     {"CWE-327"},
	"weak-cipher-des":                 {"CWE-327"},
	"insecure-random-for-secrets":     {"CWE-338"},
	"predictable-prng-seed":           {"CWE-336"},
	"discarded-auth-error":            {"CWE-252"},
	"tls-insecure-skip-verify":        {"CWE-295"},
	"tls-verify-disabled":             {"CWE-295"},
	"tls-trust-manager-bypass":        {"CWE-295"},
	"permissive-file-mode":            {"CWE-732"},
	"open-redirect":                   {"CWE-601"},
	"jwt-none-algorithm":              {"CWE-347"},
	"jwt-verify-disabled":             {"CWE-347"},
	"cors-wildcard":                   {"CWE-942"},
	"insecure-cookie":                 {"CWE-614"},
	"cookie-missing-flags":            {"CWE-614"},
	"path-traversal":                  {"CWE-22"},
	"lfi-include":                     {"CWE-98"},
	"ssrf":                            {"CWE-918"},
	"ssti":                            {"CWE-1336"},
	"empty-block":                     {"CWE-1071"},
	"empty-exception-handler":         {"CWE-390"},
	"unreachable-code":                {"CWE-561"},
	"eval-detected":                   {"CWE-95"},
	"eval-exec":                       {"CWE-95"},
	"insecure-deserialization":        {"CWE-502"},
	"pickle-deserialization":          {"CWE-502"},
	"unsafe-reflection":               {"CWE-470"},
	"xxe":                             {"CWE-611"},
	"yaml-unsafe-load":                {"CWE-502"},
	"dom-xss-innerhtml":               {"CWE-79"},
	"react-dangerously-set-innerhtml": {"CWE-79"},
	"mass-assignment":                 {"CWE-915"},
	"preg-replace-eval-modifier":      {"CWE-95"},
	"flask-debug-enabled":             {"CWE-489"},
	"jinja2-autoescape-disabled":      {"CWE-79"},
	"insecure-tempfile":               {"CWE-377"},
	"agent-unsandboxed-exec":          {"CWE-94"},
}

// cweFor returns the CWE IDs for a sast rule ID by stripping its language
// prefix and looking up the shared category.
func cweFor(ruleID string) []string {
	category := ruleID
	for _, p := range sastLangPrefixes {
		if rest, ok := strings.CutPrefix(ruleID, p); ok {
			category = rest
			break
		}
	}
	return categoryCWEs[category]
}
