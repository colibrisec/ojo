package osv

import (
	"sort"

	"github.com/colibrisec/ojo/internal/model"
)

func dedupeVulns(vulns []model.Vulnerability) []model.Vulnerability {
	if len(vulns) < 2 {
		return vulns
	}

	var groups [][]model.Vulnerability
	for _, v := range vulns {
		placed := false
		for gi, g := range groups {
			for _, m := range g {
				if shareAlias(v, m) {
					groups[gi] = append(groups[gi], v)
					placed = true
					break
				}
			}
			if placed {
				break
			}
		}
		if !placed {
			groups = append(groups, []model.Vulnerability{v})
		}
	}

	merged := make([]model.Vulnerability, 0, len(groups))
	for _, g := range groups {
		merged = append(merged, mergeGroup(g))
	}
	return merged
}

func shareAlias(a, b model.Vulnerability) bool {
	if a.ID == b.ID {
		return true
	}
	ids := make(map[string]bool, 1+len(a.Aliases))
	ids[a.ID] = true
	for _, al := range a.Aliases {
		ids[al] = true
	}
	if ids[b.ID] {
		return true
	}
	for _, al := range b.Aliases {
		if ids[al] {
			return true
		}
	}
	return false
}

func mergeGroup(g []model.Vulnerability) model.Vulnerability {
	rep := g[0]
	for _, v := range g[1:] {
		if isMoreInformative(v, rep) {
			rep = v
		}
	}

	aliasSet := map[string]bool{}
	for _, v := range g {
		aliasSet[v.ID] = true
		for _, a := range v.Aliases {
			aliasSet[a] = true
		}
	}
	delete(aliasSet, rep.ID)

	merged := rep
	merged.Aliases = make([]string, 0, len(aliasSet))
	for a := range aliasSet {
		merged.Aliases = append(merged.Aliases, a)
	}
	sort.Strings(merged.Aliases)
	return merged
}

func isMoreInformative(a, b model.Vulnerability) bool {
	aKnown, bKnown := a.Severity != "" && a.Severity != "UNKNOWN", b.Severity != "" && b.Severity != "UNKNOWN"
	if aKnown != bKnown {
		return aKnown
	}
	aFixed, bFixed := a.FixedVersion != "", b.FixedVersion != ""
	if aFixed != bFixed {
		return aFixed
	}
	return len(a.Summary) > len(b.Summary)
}
