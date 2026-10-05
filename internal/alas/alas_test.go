package alas

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

const testFeed = `<?xml version="1.0" ?>
<updates>
<update status="final" version="1.4" type="security">
  <id>ALAS2023-2024-100</id>
  <title>Amazon Linux 2023 - ALAS2023-2024-100: Important priority package update for openssl</title>
  <severity>Important</severity>
  <description>Package updates are available for Amazon Linux 2023 that fix the following vulnerabilities:
CVE-2024-1111:
	A buffer overflow in openssl.

CVE-2024-2222:
	A timing side channel in openssl.
</description>
  <references>
    <reference href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1111" id="CVE-2024-1111" type="cve" />
    <reference href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2222" id="CVE-2024-2222" type="cve" />
  </references>
  <pkglist><collection short="amazon-linux-2023">
    <package name="openssl-libs" version="3.0.8" release="1.amzn2023.0.10" epoch="1" arch="x86_64" />
    <package name="openssl-libs" version="3.0.8" release="1.amzn2023.0.10" epoch="1" arch="aarch64" />
  </collection></pkglist>
</update>
<update status="final" version="1.4" type="security">
  <id>ALAS2023-2025-200</id>
  <title>Amazon Linux 2023 - ALAS2023-2025-200: Medium priority package update for openssl</title>
  <severity>Medium</severity>
  <description>CVE-2024-2222:
	A timing side channel in openssl.
</description>
  <references><reference id="CVE-2024-2222" type="cve" /></references>
  <pkglist><collection>
    <package name="openssl-libs" version="3.2.2" release="1.amzn2023.0.1" epoch="1" arch="x86_64" />
  </collection></pkglist>
</update>
<update status="final" version="1.4" type="security">
  <id>ALAS2023-2025-300</id>
  <title>Amazon Linux 2023 - ALAS2023-2025-300: Low priority package update for bash</title>
  <severity>Low</severity>
  <description>No CVE was assigned.</description>
  <pkglist><collection>
    <package name="bash" version="5.2.15" release="1.amzn2023.0.3" epoch="0" arch="x86_64" />
  </collection></pkglist>
</update>
<update status="final" version="1.4" type="bugfix">
  <id>ALAS2023-2025-400</id>
  <pkglist><collection>
    <package name="zlib" version="9.9" release="9.amzn2023" epoch="0" arch="x86_64" />
  </collection></pkglist>
</update>
</updates>`

// serveFeed points the Amazon Linux 2023 release at a test repository
// serving feed, laid out the way Amazon's CDN is.
func serveFeed(t *testing.T, feed string) {
	t.Helper()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(feed))
	zw.Close()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/mirror.list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(srv.URL + "/repo/\n"))
	})
	mux.HandleFunc("/repo/repodata/repomd.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<repomd><data type="primary"><location href="repodata/primary.xml.gz"/></data>` +
			`<data type="updateinfo"><location href="repodata/updateinfo.xml.gz"/></data></repomd>`))
	})
	mux.HandleFunc("/repo/repodata/updateinfo.xml.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Write(gz.Bytes())
	})

	old := releases["2023"]
	releases["2023"] = release{mirrorList: srv.URL + "/mirror.list", site: "AL2023"}
	t.Cleanup(func() { releases["2023"] = old })
}

func TestScan(t *testing.T) {
	serveFeed(t, testFeed)
	pkgs := []model.Package{
		{Name: "openssl-libs", Version: "1:3.0.8-1.amzn2023.0.3", Ecosystem: "Amazon Linux:2023", Source: "rpm"},
		{Name: "bash", Version: "5.2.15-1.amzn2023.0.2", Ecosystem: "Amazon Linux:2023", Source: "rpm"},
		// Already at the fixed version, and one only a bugfix update names.
		{Name: "bash-completion", Version: "2.11-2.amzn2023.0.2", Ecosystem: "Amazon Linux:2023", Source: "rpm"},
		{Name: "zlib", Version: "1.2.11-33.amzn2023.0.5", Ecosystem: "Amazon Linux:2023", Source: "rpm"},
		// Not Amazon Linux: left for OSV.
		{Name: "openssl-libs", Version: "1:3.0.1-1.el9", Ecosystem: "Rocky Linux:9", Source: "rpm"},
	}
	findings, err := Scan(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want openssl-libs and bash: %+v", len(findings), findings)
	}

	openssl := findings[0]
	if openssl.Package != pkgs[0] || len(openssl.Vulns) != 2 {
		t.Fatalf("openssl-libs finding = %+v", openssl)
	}
	v := openssl.Vulns[0]
	if v.ID != "CVE-2024-1111" || v.Severity != "HIGH" || v.FixedVersion != "1:3.0.8-1.amzn2023.0.10" ||
		v.Summary != "A buffer overflow in openssl." || v.URL != "https://alas.aws.amazon.com/AL2023/ALAS2023-2024-100.html" ||
		len(v.Aliases) != 1 || v.Aliases[0] != "ALAS2023-2024-100" {
		t.Errorf("CVE-2024-1111 = %+v", v)
	}
	// Fixed by two advisories: the closest fix above the installed version wins.
	if v := openssl.Vulns[1]; v.ID != "CVE-2024-2222" || v.FixedVersion != "1:3.0.8-1.amzn2023.0.10" || v.Severity != "HIGH" {
		t.Errorf("CVE-2024-2222 = %+v", v)
	}

	// An advisory without a CVE is reported under its own ID.
	bash := findings[1]
	if len(bash.Vulns) != 1 || bash.Vulns[0].ID != "ALAS2023-2025-300" || bash.Vulns[0].Severity != "LOW" ||
		bash.Vulns[0].FixedVersion != "5.2.15-1.amzn2023.0.3" || bash.Vulns[0].Summary != "Low priority package update for bash" ||
		len(bash.Vulns[0].Aliases) != 0 {
		t.Errorf("bash finding = %+v", bash)
	}
}

func TestScanNotVulnerableAtOrAboveFix(t *testing.T) {
	serveFeed(t, testFeed)
	for _, version := range []string{"1:3.2.2-1.amzn2023.0.1", "1:3.5.0-1.amzn2023.0.1", "2:1.0-1.amzn2023"} {
		findings, err := Scan(context.Background(), []model.Package{{Name: "openssl-libs", Version: version, Ecosystem: "Amazon Linux:2023"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 0 {
			t.Errorf("openssl-libs %s: expected no findings, got %+v", version, findings)
		}
	}
}

// A feed that can't be read is an error: an empty result would look clean.
func TestScanFeedErrors(t *testing.T) {
	pkgs := []model.Package{{Name: "bash", Version: "5.2.15-1.amzn2023.0.2", Ecosystem: "Amazon Linux:2023"}}

	serveFeed(t, "<updates><update")
	if _, err := Scan(context.Background(), pkgs); err == nil {
		t.Error("expected an error for a truncated feed")
	}

	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	old := releases["2023"]
	releases["2023"] = release{mirrorList: srv.URL + "/mirror.list", site: "AL2023"}
	defer func() { releases["2023"] = old }()
	if _, err := Scan(context.Background(), pkgs); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("expected the HTTP status in the error, got %v", err)
	}

	unknown := []model.Package{{Name: "bash", Version: "1", Ecosystem: "Amazon Linux:1999"}}
	if _, err := Scan(context.Background(), unknown); err == nil {
		t.Error("expected an error for a release without a feed")
	}
}

func TestEcosystem(t *testing.T) {
	if eco, ok := Ecosystem("2023"); !ok || eco != "Amazon Linux:2023" || !Covers(model.Package{Ecosystem: eco}) {
		t.Errorf("Ecosystem(2023) = %q, %v", eco, ok)
	}
	if _, ok := Ecosystem("2018.03"); ok {
		t.Error("Amazon Linux 1 has no advisory feed")
	}
	if Covers(model.Package{Ecosystem: "Rocky Linux:9"}) {
		t.Error("Rocky Linux is not covered")
	}
}

func TestVercmp(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0.1", "2.0", 1},
		{"1.10", "1.9", 1},
		{"1.010", "1.10", 0},
		{"1.amzn2023.0.10", "1.amzn2023.0.3", 1},
		{"52.amzn2023.0.7", "181.amzn2023.0.1", -1},
		{"8.20170212.amzn2.1.4", "8.20170212.amzn2.1.6", -1},
		{"1.0a", "1.0", 1},
		{"1.0a", "1.0.1", -1}, // a number beats letters
		{"1.0", "1.0.a", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0^git1", "1.0", 1},
		{"1.0^git1", "1.0.1", -1},
		{"1.0.", "1.0", 0},
		{"1_0", "1.0", 0},
	}
	for _, c := range cases {
		got := vercmp(c.a, c.b)
		if (got < 0) != (c.want < 0) || (got > 0) != (c.want > 0) {
			t.Errorf("vercmp(%q, %q) = %d, want sign of %d", c.a, c.b, got, c.want)
		}
		if rev := vercmp(c.b, c.a); (rev < 0) != (c.want > 0) || (rev > 0) != (c.want < 0) {
			t.Errorf("vercmp(%q, %q) = %d, want the opposite of %d", c.b, c.a, rev, c.want)
		}
	}
}

func TestEVR(t *testing.T) {
	v := parseEVR("1:3.0.8-1.amzn2023.0.3")
	if v != (evr{"1", "3.0.8", "1.amzn2023.0.3"}) || v.String() != "1:3.0.8-1.amzn2023.0.3" {
		t.Errorf("parseEVR = %+v (%s)", v, v)
	}
	if v := parseEVR("5.2.15-1.amzn2023.0.2"); v != (evr{"", "5.2.15", "1.amzn2023.0.2"}) {
		t.Errorf("parseEVR without epoch = %+v", v)
	}
	if s := (evr{"0", "1.0", "2"}).String(); s != "1.0-2" {
		t.Errorf("a zero epoch should be left out, got %q", s)
	}
	// An epoch outranks any version.
	if compareEVR(parseEVR("1:1.0-1"), parseEVR("9.0-1")) <= 0 {
		t.Error("expected epoch 1 to be newer than no epoch")
	}
	if compareEVR(parseEVR("0:1.0-1"), parseEVR("1.0-1")) != 0 {
		t.Error("expected epoch 0 to equal no epoch")
	}
}
