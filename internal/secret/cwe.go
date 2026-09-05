package secret

// ruleCWEs maps a secret-detection rule ID to its applicable CWE IDs.
// Nearly everything here is CWE-798 (hardcoded credential); "private-key"
// additionally carries CWE-321 (a hardcoded cryptographic key is a stricter
// case than a hardcoded credential). A rule with no entry (e.g. a
// user-supplied custom rule) simply gets no CWEs.
var ruleCWEs = map[string][]string{
	"aws-access-key-id":         {"CWE-798"},
	"aws-secret-access-key":     {"CWE-798"},
	"github-pat":                {"CWE-798"},
	"github-fine-grained-pat":   {"CWE-798"},
	"slack-token":               {"CWE-798"},
	"slack-webhook":             {"CWE-798"},
	"google-api-key":            {"CWE-798"},
	"stripe-key":                {"CWE-798"},
	"twilio-api-key":            {"CWE-798"},
	"npm-token":                 {"CWE-798"},
	"private-key":               {"CWE-321", "CWE-798"},
	"jwt":                       {"CWE-798"},
	"db-connection-string":      {"CWE-798"},
	"generic-secret-assignment": {"CWE-798"},
}
