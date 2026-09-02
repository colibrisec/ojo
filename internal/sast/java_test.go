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

const javaNewRules = `class GoServlet {
    void go(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws java.io.IOException {
        response.sendRedirect(request.getParameter("next"));
        response.sendRedirect("/home");
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Content-Type", "application/json");
    }
}
`

func TestJavaScanFindsNewRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "App2.java"), []byte(javaNewRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	counts := map[string]int{}
	for _, i := range issues {
		counts[i.RuleID]++
	}
	if counts["java-open-redirect"] != 1 {
		t.Errorf("expected 1 java-open-redirect issue, got %d: %+v", counts["java-open-redirect"], issues)
	}
	if counts["java-cors-wildcard"] != 1 {
		t.Errorf("expected 1 java-cors-wildcard issue, got %d: %+v", counts["java-cors-wildcard"], issues)
	}
}

const javaCookieAndPathRules = `class GoServlet {
    void go(javax.servlet.http.HttpServletRequest request, javax.servlet.http.Cookie cookie) throws java.io.IOException {
        cookie.setSecure(false);
        cookie.setHttpOnly(false);
        new File(request.getParameter("path"));
        new File("/safe/path");
    }
}
`

func TestJavaScanFindsCookieAndPathTraversal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "App3.java"), []byte(javaCookieAndPathRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	counts := map[string]int{}
	for _, i := range issues {
		counts[i.RuleID]++
	}
	if counts["java-insecure-cookie"] != 2 {
		t.Errorf("expected 2 java-insecure-cookie issues (setSecure + setHttpOnly), got %d: %+v", counts["java-insecure-cookie"], issues)
	}
	if counts["java-path-traversal"] != 1 {
		t.Errorf("expected 1 java-path-traversal issue, got %d: %+v", counts["java-path-traversal"], issues)
	}
}

const javaCookieMissingFlagsRules = `class GoServlet {
    void unhardened() {
        Cookie c = new Cookie("id", "v");
        resp.addCookie(c);
    }

    void hardened() {
        Cookie c = new Cookie("id2", "v2");
        c.setSecure(true);
        c.setHttpOnly(true);
        resp.addCookie(c);
    }
}
`

func TestJavaScanFindsCookieMissingFlags(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "App4.java"), []byte(javaCookieMissingFlagsRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "java-cookie-missing-flags" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 java-cookie-missing-flags issues (setSecure + setHttpOnly missing in unhardened() only), got %d: %+v", count, issues)
	}
}

const javaJWTNoneRules = `class App {
    void go() {
        Algorithm alg = Algorithm.none();
        String jwt = JWT.create().withIssuer("auth0").sign(Algorithm.none());
        SignatureAlgorithm sa = SignatureAlgorithm.NONE;
        Jwts.builder().signWith(SignatureAlgorithm.HS256, "key");
    }
}
`

func TestJavaScanFindsJWTNoneAlgorithm(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "jwt.java"), []byte(javaJWTNoneRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, i := range issues {
		if i.RuleID == "java-jwt-none-algorithm" {
			count++
		}
	}
	if count != 3 {
		t.Errorf("expected 3 java-jwt-none-algorithm issues (2 Algorithm.none() calls + 1 SignatureAlgorithm.NONE, not the HS256 signWith), got %d: %+v", count, issues)
	}
}

const javaReliabilityRules = `class App {
    void a() {
        try { f(); } catch (Exception e) { }
        try { f(); } catch (Exception e) { log(e); }
        if (x) { }
        if (x) { } else { }
        while (x) { }
        for (int i=0;i<3;i++) { }
        if (x) { return; y(); }
    }
}
`

func TestJavaScanFindsReliabilityRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Reliability.java"), []byte(javaReliabilityRules), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	counts := map[string]int{}
	for _, i := range issues {
		counts[i.RuleID]++
	}
	if counts["java-empty-exception-handler"] != 1 {
		t.Errorf("expected 1 java-empty-exception-handler issue (not the catch that logs), got %d: %+v", counts["java-empty-exception-handler"], issues)
	}
	if counts["java-empty-block"] != 5 {
		t.Errorf("expected 5 java-empty-block issues (empty if, empty if+else=2, empty while, empty for), got %d: %+v", counts["java-empty-block"], issues)
	}
	if counts["java-unreachable-code"] != 1 {
		t.Errorf("expected 1 java-unreachable-code issue, got %d: %+v", counts["java-unreachable-code"], issues)
	}
}
