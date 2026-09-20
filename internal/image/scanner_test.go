package image

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/colibrisec/ojo/internal/model"
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

	files, err := readImageFS(tar.NewReader(&buf))
	if err != nil {
		t.Fatal(err)
	}
	osRelease, dpkgStatus := files.osRelease, files.dpkgStatus
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

func TestParseApkRecordsSourcePackage(t *testing.T) {
	data := []byte("P:libcrypto3\nV:3.5.6-r0\no:openssl\n\nP:busybox\nV:1.37.0-r0\no:busybox\n\nP:nosource\nV:1.0-r0\n\n")
	pkgs := parseApk(data, "Alpine:v3.23")
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %+v", pkgs)
	}
	if pkgs[0].Name != "libcrypto3" || pkgs[0].Origin != "openssl" {
		t.Errorf("libcrypto3: want Name=libcrypto3 Origin=openssl, got %+v", pkgs[0])
	}
	if pkgs[2].Origin != "" {
		t.Errorf("package without o: should have empty Origin, got %q", pkgs[2].Origin)
	}
}

func TestParseDpkgRecordsSourcePackage(t *testing.T) {
	data := []byte("Package: libc6\nStatus: install ok installed\nSource: glibc (2.36-9+deb12u4)\nVersion: 2.36-9+deb12u4\n\n" +
		"Package: libbash\nStatus: install ok installed\nSource: bash\nVersion: 5.2-1\n\n" +
		"Package: tar\nStatus: install ok installed\nVersion: 1.34-1\n\n")
	pkgs := parseDpkg(data, "Debian:12")
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %+v", pkgs)
	}
	want := []string{"glibc", "bash", ""}
	for i, w := range want {
		if pkgs[i].Origin != w {
			t.Errorf("%s: want Origin=%q, got %q", pkgs[i].Name, w, pkgs[i].Origin)
		}
	}
}

func TestNodePackage(t *testing.T) {
	cases := []struct {
		path string
		ok   bool
		want model.Package
	}{
		{"usr/local/lib/node_modules/npm/node_modules/tar/package.json", true, model.Package{Name: "tar", Version: "7.5.11"}},
		{"app/node_modules/@sigstore/core/package.json", true, model.Package{Name: "@sigstore/core", Version: "2.0.0"}},
		{"app/node_modules/a/node_modules/b/package.json", true, model.Package{Name: "b", Version: "1.0.0"}},
		{"app/package.json", false, model.Package{}},
		{"app/node_modules/a/lib/package.json", false, model.Package{}},
		{"app/node_modules/.bin/package.json", false, model.Package{}},
	}
	for _, c := range cases {
		data := []byte(`{"name": "` + c.want.Name + `", "version": "` + c.want.Version + `"}`)
		if c.want.Name == "" {
			data = []byte(`{"name": "x", "version": "1.0.0"}`)
		}
		got, ok := nodePackage(c.path, data)
		if ok != c.ok {
			t.Errorf("nodePackage(%q) ok = %v, want %v", c.path, ok, c.ok)
			continue
		}
		if ok && (got.Name != c.want.Name || got.Version != c.want.Version || got.Ecosystem != model.EcosystemNpm || got.Source != c.path) {
			t.Errorf("nodePackage(%q) = %+v", c.path, got)
		}
	}
	if _, ok := nodePackage("app/node_modules/x/package.json", []byte(`{"name": "x"}`)); ok {
		t.Error("package.json without a version must be ignored")
	}
	if _, ok := nodePackage("app/node_modules/x/package.json", []byte(`not json`)); ok {
		t.Error("invalid package.json must be ignored")
	}
}

func TestReadImageFSCollectsNodePackages(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	writeTarFile(t, tw, "etc/os-release", []byte("ID=alpine\nVERSION_ID=3.23.4\n"))
	writeTarFile(t, tw, "usr/local/lib/node_modules/npm/node_modules/tar/package.json", []byte(`{"name":"tar","version":"7.5.11"}`))
	writeTarFile(t, tw, "usr/local/lib/node_modules/npm/node_modules/tar/lib/package.json", []byte(`{"type":"module"}`))
	writeTarFile(t, tw, "app/package.json", []byte(`{"name":"app","version":"1.0.0"}`))
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	files, err := readImageFS(tar.NewReader(&buf))
	if err != nil {
		t.Fatal(err)
	}
	if len(files.npm) != 1 || files.npm[0].Name != "tar" || files.npm[0].Version != "7.5.11" {
		t.Errorf("expected only node_modules/tar, got %+v", files.npm)
	}
}

func imageTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		writeTarFile(t, tw, n, []byte(files[n]))
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var alpineNodeImage = map[string]string{
	"etc/os-release":       "ID=alpine\nVERSION_ID=3.23.4\n",
	"lib/apk/db/installed": "P:libcrypto3\nV:3.5.6-r0\no:openssl\n\n",
	"usr/local/lib/node_modules/npm/node_modules/tar/package.json":                     `{"name":"tar","version":"7.5.11"}`,
	"usr/local/lib/node_modules/npm/node_modules/foo/node_modules/tar/package.json":    `{"name":"tar","version":"7.5.11"}`,
	"usr/local/lib/node_modules/npm/node_modules/pacote/package.json":                  `{"name":"pacote","version":"19.0.2"}`,
	"usr/local/lib/node_modules/npm/node_modules/pacote/node_modules/tar/package.json": `{"name":"tar","version":"6.2.0"}`,
}

func checkAlpineNodeImage(t *testing.T, pkgs []model.Package, label string) {
	t.Helper()
	if label != "alpine 3.23.4" {
		t.Errorf("label = %q, want %q", label, "alpine 3.23.4")
	}
	var got []string
	for _, p := range pkgs {
		got = append(got, string(p.Ecosystem)+" "+p.Name+"@"+p.Version+" origin="+p.Origin)
	}
	sort.Strings(got)
	want := []string{
		"Alpine:v3.23 libcrypto3@3.5.6-r0 origin=openssl",
		"npm pacote@19.0.2 origin=",
		"npm tar@6.2.0 origin=",
		"npm tar@7.5.11 origin=",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("packages = %q, want %q (npm packages deduplicated by name and version)", got, want)
	}
}

func TestScanFSAlpineWithNodePackages(t *testing.T) {
	pkgs, label, err := scanFS(bytes.NewReader(imageTar(t, alpineNodeImage)), "test")
	if err != nil {
		t.Fatal(err)
	}
	checkAlpineNodeImage(t, pkgs, label)
}

func TestScanFSDebian(t *testing.T) {
	fsTar := imageTar(t, map[string]string{
		"etc/os-release":      "ID=debian\nVERSION_ID=\"12\"\n",
		"var/lib/dpkg/status": "Package: libc6\nStatus: install ok installed\nSource: glibc (2.36-9)\nVersion: 2.36-9\n\n",
	})
	pkgs, label, err := scanFS(bytes.NewReader(fsTar), "test")
	if err != nil {
		t.Fatal(err)
	}
	if label != "debian 12" {
		t.Errorf("label = %q, want %q", label, "debian 12")
	}
	if len(pkgs) != 1 || pkgs[0].Name != "libc6" || pkgs[0].Origin != "glibc" || pkgs[0].Ecosystem != "Debian:12" {
		t.Errorf("unexpected packages: %+v", pkgs)
	}
}

func TestScanFSWithoutPackageDatabases(t *testing.T) {
	pkgs, _, err := scanFS(bytes.NewReader(imageTar(t, map[string]string{"etc/os-release": "ID=alpine\nVERSION_ID=3.23.4\n"})), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected no packages, got %+v", pkgs)
	}
}

func TestScanFSRejectsRPMImages(t *testing.T) {
	_, _, err := scanFS(bytes.NewReader(imageTar(t, map[string]string{"etc/os-release": "ID=rhel\nVERSION_ID=9.3\n"})), "test")
	if err == nil || !strings.Contains(err.Error(), "rpm-based") {
		t.Errorf("expected an rpm-based image error, got %v", err)
	}
}

func TestScanFSRequiresOSRelease(t *testing.T) {
	_, _, err := scanFS(bytes.NewReader(imageTar(t, map[string]string{"app/node_modules/x/package.json": `{"name":"x","version":"1.0.0"}`})), "test")
	if err == nil || !strings.Contains(err.Error(), "could not determine OS") {
		t.Errorf("expected an unknown OS error, got %v", err)
	}
}

func TestScanFSInvalidTar(t *testing.T) {
	_, _, err := scanFS(strings.NewReader(strings.Repeat("x", 512)), "test")
	if err == nil || !strings.Contains(err.Error(), "reading image filesystem") {
		t.Errorf("expected a filesystem read error, got %v", err)
	}
}

func TestScanInvalidReference(t *testing.T) {
	_, _, err := Scan(context.Background(), "not a valid reference!", "")
	if err == nil || !strings.Contains(err.Error(), "pulling") {
		t.Errorf("expected a pull error, got %v", err)
	}
}

func TestScanPullsImageFromRegistry(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()

	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(imageTar(t, alpineNodeImage))), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	ref := strings.TrimPrefix(srv.URL, "http://") + "/test/node:latest"
	parsed, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(parsed, img); err != nil {
		t.Fatal(err)
	}

	pkgs, label, err := Scan(context.Background(), ref, "")
	if err != nil {
		t.Fatal(err)
	}
	checkAlpineNodeImage(t, pkgs, label)
}
