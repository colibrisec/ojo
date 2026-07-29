package image

import "testing"

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
