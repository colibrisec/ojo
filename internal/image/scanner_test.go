package image

import (
	"archive/tar"
	"bytes"
	"testing"
)

func TestReadImageFSFollowsSymlinkedOSRelease(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	content := []byte("ID=debian\nVERSION_ID=\"13\"\n")
	writeTarFile(t, tw, "usr/lib/os-release", content)
	writeTarSymlink(t, tw, "etc/os-release", "../usr/lib/os-release")
	writeTarFile(t, tw, "var/lib/dpkg/status", []byte("Package: tar\nStatus: install ok installed\nVersion: 1.35+dfsg-3.1\n\n"))
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	osRelease, _, dpkgStatus, err := readImageFS(tar.NewReader(&buf))
	if err != nil {
		t.Fatal(err)
	}
	if len(osRelease) == 0 {
		t.Fatal("expected os-release content to be read via the usr/lib/os-release fallback, got empty")
	}

	info := parseOSRelease(osRelease)
	eco := osEcosystem(info)
	if eco != "Debian:13" {
		t.Errorf("expected ecosystem Debian:13, got %q (empty ecosystem causes OSV to loosely match across unrelated ecosystems)", eco)
	}
	if dpkgStatus == nil {
		t.Error("expected dpkg status to also be read")
	}
}

func writeTarFile(t *testing.T, tw *tar.Writer, name string, content []byte) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(content)), Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
}

func TestScanRefusesUnknownEcosystem(t *testing.T) {
	if eco := osEcosystem(map[string]string{}); eco != "" {
		t.Fatalf("expected empty ecosystem for unknown OS, got %q", eco)
	}
}

func writeTarSymlink(t *testing.T, tw *tar.Writer, name, target string) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
}

func TestParseApk(t *testing.T) {
	data := []byte("P:apk-tools\nV:2.10.6-r0\nA:x86_64\n\nP:busybox\nV:1.30.1-r3\n\n")
	pkgs := parseApk(data, "Alpine:v3.10")
	if len(pkgs) != 2 || pkgs[0].Name != "apk-tools" || pkgs[0].Version != "2.10.6-r0" {
		t.Fatalf("unexpected packages: %+v", pkgs)
	}
}

func TestParseDpkg(t *testing.T) {
	data := []byte("Package: bash\nStatus: install ok installed\nVersion: 5.0-6\n\n" +
		"Package: removed-pkg\nStatus: deinstall ok config-files\nVersion: 1.0\n\n")
	pkgs := parseDpkg(data, "Debian:11")
	if len(pkgs) != 1 || pkgs[0].Name != "bash" || pkgs[0].Version != "5.0-6" {
		t.Fatalf("expected only the installed package, got: %+v", pkgs)
	}
}

func TestOSEcosystem(t *testing.T) {
	cases := []struct {
		info map[string]string
		want string
	}{
		{map[string]string{"ID": "alpine", "VERSION_ID": "3.18.4"}, "Alpine:v3.18"},
		{map[string]string{"ID": "debian", "VERSION_ID": "11"}, "Debian:11"},
		{map[string]string{"ID": "ubuntu", "VERSION_ID": "22.04"}, "Ubuntu:22.04:LTS"},
		{map[string]string{"ID": "ubuntu", "VERSION_ID": "23.10"}, "Ubuntu:23.10"},
	}
	for _, c := range cases {
		if got := string(osEcosystem(c.info)); got != c.want {
			t.Errorf("osEcosystem(%+v) = %q, want %q", c.info, got, c.want)
		}
	}
}

func TestCleanPath(t *testing.T) {
	cases := map[string]string{
		`bin\arch`:         "bin/arch",
		"./etc/os-release": "etc/os-release",
		"/etc/os-release":  "etc/os-release",
		"etc/os-release":   "etc/os-release",
	}
	for in, want := range cases {
		if got := cleanPath(in); got != want {
			t.Errorf("cleanPath(%q) = %q, want %q", in, got, want)
		}
	}
}
