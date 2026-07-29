package secret

import "math"

// shannonEntropy returns the Shannon entropy (bits/char) of s, used to filter
// low-entropy false positives (e.g. "password" or "changeme") out of generic rules.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	var entropy float64
	n := float64(len(s))
	for _, c := range counts {
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
