package model

import "testing"

func TestPackageQueryName(t *testing.T) {
	cases := []struct {
		name string
		pkg  Package
		want string
	}{
		{"binary package with a source package", Package{Name: "libcrypto3", Origin: "openssl"}, "openssl"},
		{"package without an origin", Package{Name: "busybox"}, "busybox"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.pkg.QueryName(); got != c.want {
				t.Errorf("QueryName() = %q, want %q", got, c.want)
			}
		})
	}
}
