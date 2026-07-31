package osv

import (
	"math"
	"strings"
)

// cvss3SeverityLabel derives a CRITICAL/HIGH/MEDIUM/LOW/NONE label from a
// CVSS v3.0/v3.1 base vector, for advisory sources (Debian, Alpine, ...)
// that supply a CVSS vector but no pre-computed severity label the way
// GHSA's database_specific.severity does. Returns ok=false for anything
// that isn't a well-formed CVSS v3.x base vector (e.g. CVSS v2, or a vector
// missing a required metric).
func cvss3SeverityLabel(vector string) (string, bool) {
	score, ok := cvss3BaseScore(vector)
	if !ok {
		return "", false
	}
	switch {
	case score >= 9.0:
		return "CRITICAL", true
	case score >= 7.0:
		return "HIGH", true
	case score >= 4.0:
		return "MEDIUM", true
	case score > 0.0:
		return "LOW", true
	default:
		return "NONE", true
	}
}

var (
	cvssAV          = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	cvssAC          = map[string]float64{"L": 0.77, "H": 0.44}
	cvssUI          = map[string]float64{"N": 0.85, "R": 0.62}
	cvssCIA         = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	cvssPRUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	cvssPRChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
)

// cvss3BaseScore implements the CVSS v3.1 base score formula (spec section 7.4).
func cvss3BaseScore(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0, false
	}

	metrics := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		k, v, ok := strings.Cut(part, ":")
		if ok {
			metrics[k] = v
		}
	}

	av, ok := cvssAV[metrics["AV"]]
	if !ok {
		return 0, false
	}
	ac, ok := cvssAC[metrics["AC"]]
	if !ok {
		return 0, false
	}
	ui, ok := cvssUI[metrics["UI"]]
	if !ok {
		return 0, false
	}
	scopeChanged := metrics["S"] == "C"
	prTable := cvssPRUnchanged
	if scopeChanged {
		prTable = cvssPRChanged
	}
	pr, ok := prTable[metrics["PR"]]
	if !ok {
		return 0, false
	}
	c, ok := cvssCIA[metrics["C"]]
	if !ok {
		return 0, false
	}
	i, ok := cvssCIA[metrics["I"]]
	if !ok {
		return 0, false
	}
	a, ok := cvssCIA[metrics["A"]]
	if !ok {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	if scopeChanged {
		base = cvssRoundUp(math.Min(1.08*(impact+exploitability), 10))
	} else {
		base = cvssRoundUp(math.Min(impact+exploitability, 10))
	}
	return base, true
}

// cvssRoundUp implements the CVSS spec's "Roundup" function: round to the
// nearest 0.1, always rounding up (not standard rounding).
func cvssRoundUp(x float64) float64 {
	intInput := int64(math.Round(x * 100000))
	if intInput%10000 == 0 {
		return float64(intInput) / 100000
	}
	return float64(intInput/10000+1) / 10
}
