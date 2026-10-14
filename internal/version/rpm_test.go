package version

import "testing"

func TestRPMVercmp(t *testing.T) {
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
		got := RPMVercmp(c.a, c.b)
		if (got < 0) != (c.want < 0) || (got > 0) != (c.want > 0) {
			t.Errorf("RPMVercmp(%q, %q) = %d, want sign of %d", c.a, c.b, got, c.want)
		}
		if rev := RPMVercmp(c.b, c.a); (rev < 0) != (c.want > 0) || (rev > 0) != (c.want < 0) {
			t.Errorf("RPMVercmp(%q, %q) = %d, want the opposite of %d", c.b, c.a, rev, c.want)
		}
	}
}
