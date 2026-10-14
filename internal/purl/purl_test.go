package purl

import (
	"testing"

	"github.com/colibrisec/ojo/internal/model"
)

func TestRoundTrip(t *testing.T) {
	cases := []struct {
		pkg  model.Package
		purl string
	}{
		{model.Package{Name: "github.com/pkg/errors", Version: "0.9.1", Ecosystem: model.EcosystemGo}, "pkg:golang/github.com/pkg/errors@v0.9.1"},
		{model.Package{Name: "lodash", Version: "4.17.21", Ecosystem: model.EcosystemNpm}, "pkg:npm/lodash@4.17.21"},
		{model.Package{Name: "@babel/core", Version: "7.0.0", Ecosystem: model.EcosystemNpm}, "pkg:npm/%40babel/core@7.0.0"},
		{model.Package{Name: "django", Version: "3.2.0", Ecosystem: model.EcosystemPyPI}, "pkg:pypi/django@3.2.0"},
		{model.Package{Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", Ecosystem: model.EcosystemMaven}, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		{model.Package{Name: "serde", Version: "1.0.0", Ecosystem: model.EcosystemCratesIO}, "pkg:cargo/serde@1.0.0"},
		{model.Package{Name: "rails", Version: "6.1.0", Ecosystem: model.EcosystemRubyGems}, "pkg:gem/rails@6.1.0"},
		{model.Package{Name: "Newtonsoft.Json", Version: "12.0.1", Ecosystem: model.EcosystemNuGet}, "pkg:nuget/Newtonsoft.Json@12.0.1"},
		{model.Package{Name: "laravel/framework", Version: "8.0.0", Ecosystem: model.EcosystemPackagist}, "pkg:composer/laravel/framework@8.0.0"},
		{model.Package{Name: "http", Version: "0.13.0", Ecosystem: model.EcosystemPub}, "pkg:pub/http@0.13.0"},
		{model.Package{Name: "github.com/apple/swift-nio", Version: "2.0.0", Ecosystem: model.EcosystemSwiftURL}, "pkg:swift/github.com/apple/swift-nio@2.0.0"},
		{model.Package{Name: "GoogleUtilities/NSData+zlib", Version: "7.5.2", Ecosystem: model.EcosystemCocoaPods}, "pkg:cocoapods/GoogleUtilities@7.5.2#NSData%2Bzlib"},
		{model.Package{Name: "libssl3", Version: "3.0.11-1~deb12u2", Origin: "openssl", Ecosystem: "Debian:12", Source: "dpkg"}, "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12&upstream=openssl"},
		{model.Package{Name: "bash", Version: "5.1-6ubuntu1", Ecosystem: "Ubuntu:22.04:LTS", Source: "dpkg"}, "pkg:deb/ubuntu/bash@5.1-6ubuntu1?distro=ubuntu-22.04"},
		{model.Package{Name: "libcrypto3", Version: "3.1.4-r5", Origin: "openssl", Ecosystem: "Alpine:v3.19", Source: "apk"}, "pkg:apk/alpine/libcrypto3@3.1.4-r5?distro=alpine-3.19&upstream=openssl"},
		{model.Package{Name: "openssl-libs", Version: "1:3.0.7-25.el9_3", Origin: "openssl", Ecosystem: "Red Hat:enterprise_linux:9", Source: "rpm"}, "pkg:rpm/redhat/openssl-libs@3.0.7-25.el9_3?distro=rhel-9&epoch=1&upstream=openssl"},
		{model.Package{Name: "curl", Version: "8.5.0-1.amzn2023.0.2", Ecosystem: "Amazon Linux:2023", Source: "rpm"}, "pkg:rpm/amazon/curl@8.5.0-1.amzn2023.0.2?distro=amzn-2023"},
		{model.Package{Name: "glibc", Version: "2.38-1.fc39", Ecosystem: "fedora", Source: "rpm"}, "pkg:rpm/fedora/glibc@2.38-1.fc39"},
	}
	for _, c := range cases {
		got := FromPackage(c.pkg)
		if got != c.purl {
			t.Errorf("FromPackage(%+v) = %q, want %q", c.pkg, got, c.purl)
		}
		back, ok := ToPackage(got)
		if !ok || back != c.pkg {
			t.Errorf("ToPackage(%q) = %+v, %v, want %+v", got, back, ok, c.pkg)
		}
	}
}

func TestToPackageOtherProducers(t *testing.T) {
	cases := []struct {
		purl string
		want model.Package
	}{
		// syft
		{"pkg:deb/debian/libc6@2.36-9%2Bdeb12u4?arch=amd64&upstream=glibc&distro=debian-12", model.Package{Name: "libc6", Version: "2.36-9+deb12u4", Origin: "glibc", Ecosystem: "Debian:12", Source: "dpkg"}},
		{"pkg:rpm/rhel/openssl-libs@3.0.7-25.el9_3?arch=x86_64&epoch=1&upstream=openssl-3.0.7-25.el9_3.src.rpm&distro=rhel-9.3", model.Package{Name: "openssl-libs", Version: "1:3.0.7-25.el9_3", Origin: "openssl", Ecosystem: "Red Hat:enterprise_linux:9", Source: "rpm"}},
		{"pkg:apk/alpine/busybox@1.36.1-r15?arch=x86_64&upstream=busybox&distro=alpine-3.19.1", model.Package{Name: "busybox", Version: "1.36.1-r15", Ecosystem: "Alpine:v3.19", Source: "apk"}},
		// trivy
		{"pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1?arch=amd64&distro=debian-12.4", model.Package{Name: "zlib1g", Version: "1:1.2.13.dfsg-1", Ecosystem: "Debian:12", Source: "dpkg"}},
		{"pkg:deb/debian/login@4.13%2Bdfsg1-1%2Bdeb12u2?arch=amd64&distro=debian-12.15&epoch=1", model.Package{Name: "login", Version: "1:4.13+dfsg1-1+deb12u2", Ecosystem: "Debian:12", Source: "dpkg"}},
		{"pkg:golang/golang.org/x/net@v0.17.0", model.Package{Name: "golang.org/x/net", Version: "0.17.0", Ecosystem: model.EcosystemGo}},
		// no distro: the release is unknown
		{"pkg:deb/debian/bash@5.2.15-2", model.Package{Name: "bash", Version: "5.2.15-2", Ecosystem: "debian", Source: "dpkg"}},
	}
	for _, c := range cases {
		got, ok := ToPackage(c.purl)
		if !ok || got != c.want {
			t.Errorf("ToPackage(%q) = %+v, %v, want %+v", c.purl, got, ok, c.want)
		}
	}
	for _, bad := range []string{"pkg:github/actions/checkout@v4", "pkg:npm/lodash", "not a purl"} {
		if p, ok := ToPackage(bad); ok {
			t.Errorf("ToPackage(%q) = %+v, want not ok", bad, p)
		}
	}
}
