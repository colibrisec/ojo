package version

import "testing"

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

type orderCase struct {
	ecosystem, a, b string
	want            int
}

func TestCompare(t *testing.T) {
	cases := []orderCase{
		// dpkg
		{"Debian:12", "1.0~rc1", "1.0", -1},
		{"Debian:12", "1.0", "1.0+deb1", -1},
		{"Debian:12", "1:0.9", "2.0", 1},
		{"Ubuntu:22.04:LTS", "1.35+dfsg-3.1", "1.35+dfsg-4", -1},
		{"Debian:12", "2.2.28", "2.2.9", 1},
		{"Debian:12", "1.0-1", "1.0-1", 0},
		{"Debian:12", "1.0a", "1.0+", -1},
		{"Debian:12", "1.0~~", "1.0~", -1},
		{"Debian:12", "0:1.2", "1.2", 0},
		{"Debian:12", "1.0~", "1.0", -1},
		{"Debian:12", "1.0-1", "1.0", 1},
		// rpm
		{"Red Hat:enterprise_linux:9", "1:1.0-1", "9.0-1", 1},
		{"Rocky Linux:9", "1.0~rc1-1", "1.0-1", -1},
		{"AlmaLinux:9", "3.0.7-25.el9_3", "3.0.7-27.el9", -1},
		{"Amazon Linux:2023", "1.0^git1", "1.0", 1},
		// apk
		{"Alpine:v3.19", "1.2.3-r0", "1.2.3-r1", -1},
		{"Alpine:v3.19", "1.2.3_rc1", "1.2.3", -1},
		{"Alpine:v3.19", "1.2.3", "1.2.3_p1", -1},
		{"Alpine:v3.19", "1.2.3a", "1.2.3", 1},
		{"Alpine:v3.19", "1.2", "1.2.1", -1},
		{"Alpine:v3.19", "1.2.3_alpha", "1.2.3_beta", -1},
		{"Alpine:v3.19", "3.0.10-r0", "3.0.9-r5", 1},
		// PEP 440
		{"PyPI", "1.0.dev1", "1.0a1", -1},
		{"PyPI", "1.0a1", "1.0b1", -1},
		{"PyPI", "1.0b2", "1.0rc1", -1},
		{"PyPI", "1.0rc1", "1.0", -1},
		{"PyPI", "1.0", "1.0.post1", -1},
		{"PyPI", "1.0", "1.0.0", 0},
		{"PyPI", "1.0", "1.0+local", -1},
		{"PyPI", "1!0.5", "2.0", 1},
		{"PyPI", "2.0.0", "2.0.0-RC1", 1},
		{"PyPI", "1.0.post1.dev1", "1.0.post1", -1},
		{"PyPI", "3.2.13", "3.2.9", 1},
		{"PyPI", "1.0+abc.5", "1.0+abc.10", -1},
		{"PyPI", "1.0+abc", "1.0+5", -1},
		{"PyPI", "1.0+abc.1", "1.0+abd", -1},
		{"PyPI", "1.0+ubuntu-1", "1.0+ubuntu.1", 0},
		{"PyPI", "1.0+abc", "1.0+abc.1", -1},
		{"PyPI", "not a version", "1.0", 1},
		// Maven
		{"Maven", "1.0-alpha1", "1.0-beta1", -1},
		{"Maven", "1.0-SNAPSHOT", "1.0", -1},
		{"Maven", "1.0-rc1", "1.0-SNAPSHOT", -1},
		{"Maven", "1.0", "1.0.0", 0},
		{"Maven", "1.0.Final", "1.0", 0},
		{"Maven", "1.0", "1.0-sp1", -1},
		{"Maven", "1.0", "1.0.1", -1},
		{"Maven", "2.14.1", "2.15.0", -1},
		{"Maven", "1.0-cr1", "1.0-rc1", 0},
		{"Maven", "1.0.RELEASE", "1.0.1", -1},
		{"Maven", "1-1", "1.1", -1},
		{"Maven", "1.0-a1", "1.0-alpha1", 0},
		{"Maven", "1.0-b1", "1.0-beta1", 0},
		{"Maven", "1.0-m1", "1.0-milestone1", 0},
		{"Maven", "1.0-m1", "1.0-rc1", -1},
		{"Maven", "1.0-foo", "1.0-sp", 1},
		{"Maven", "1.0-bar", "1.0-foo", -1},
		{"Maven", "1..0", "1.0.0", 0},
		// RubyGems
		{"RubyGems", "1.0.0.pre", "1.0.0", -1},
		{"RubyGems", "1.0.0-rc1", "1.0.0", -1},
		{"RubyGems", "1.0", "1.0.0", 0},
		{"RubyGems", "1.0.a", "1.0.b", -1},
		{"RubyGems", "1.10", "1.9", 1},
		{"RubyGems", "6.1.7.3", "6.1.7.10", -1},
		// Go
		{"Go", "1.2.3", "v1.2.4", -1},
		{"Go", "0.0.0-20210101000000-abcdef123456", "0.1.0", -1},
		{"Go", "1.0.0-rc.1", "1.0.0", -1},
		{"Go", "1.2", "1.10", -1},
		{"Go", "1.2.3.4", "1.2.3", 1},
		// semver
		{"npm", "1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"npm", "1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"npm", "1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"npm", "1.0.0-rc.1", "1.0.0", -1},
		{"crates.io", "1.0.0+build", "1.0.0", 0},
		{"NuGet", "1.0.0.1", "1.0.0", 1},
		{"NuGet", "1.0.0-RC1", "1.0.0-rc2", -1},
		{"Packagist", "v2.0.0", "2.0.1", -1},
		// generic
		{"unknown", "2.2.28", "2.2.9", 1},
		{"unknown", "1.0.0", "1.0.1", -1},
	}
	for _, c := range cases {
		if got := sign(Compare(c.ecosystem, c.a, c.b)); got != c.want {
			t.Errorf("Compare(%q, %q, %q) = %d, want %d", c.ecosystem, c.a, c.b, got, c.want)
		}
		if got := sign(Compare(c.ecosystem, c.b, c.a)); got != -c.want {
			t.Errorf("Compare(%q, %q, %q) = %d, want %d", c.ecosystem, c.b, c.a, got, -c.want)
		}
	}
}
