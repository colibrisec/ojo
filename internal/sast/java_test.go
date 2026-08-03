package sast

import (
	"os"
	"path/filepath"
	"testing"
)

const javaVulnerable = `import java.io.ObjectInputStream;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.net.ssl.HostnameVerifier;

class App {
    String apiToken = "sk_super_secret_value_123";

    void run(String userInput, java.sql.Statement stmt, ObjectInputStream ois) throws Exception {
        Runtime.getRuntime().exec("echo " + userInput);
        new ProcessBuilder("echo " + userInput);
        stmt.executeQuery("SELECT * FROM t WHERE id=" + userInput);
        MessageDigest.getInstance("MD5");
        Cipher.getInstance("DES");
        ois.readObject();
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        HostnameVerifier hv = new HostnameVerifier() {
            public boolean verify(String h, javax.net.ssl.SSLSession s) { return true; }
        };
    }

    int generateSessionToken() {
        return new Random().nextInt();
    }
}
`

const javaClean = `class App {
    void run(String[] args) {
        ProcessBuilder pb = new ProcessBuilder("ls", "-la");
    }
}
`

func TestJavaScanFindsVulnerablePatterns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "App.java"), []byte(javaVulnerable), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"java-hardcoded-secret":            false,
		"java-command-injection":           false,
		"java-sql-injection":               false,
		"java-weak-hash":                   false,
		"java-weak-cipher":                 false,
		"java-insecure-deserialization":    false,
		"java-insecure-random-for-secrets": false,
		"java-tls-trust-manager-bypass":    false,
		"java-xxe":                         false,
	}
	for _, i := range issues {
		if _, ok := want[i.RuleID]; ok {
			want[i.RuleID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected rule %s to fire, got issues: %+v", id, issues)
		}
	}
}

func TestJavaScanNoFalsePositiveOnLiteralCommand(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "App.java"), []byte(javaClean), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues for a literal ProcessBuilder call, got: %+v", issues)
	}
}
