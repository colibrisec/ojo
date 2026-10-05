package license

import "strings"

// spdxIDs is the set of SPDX license identifiers ojo recognizes -- the ones
// that cover the overwhelming majority of real packages, not the full SPDX
// list (600+ entries, revised several times a year). CycloneDX only allows a
// license "id" from the SPDX list, so anything outside this set is written
// as a free-form license "name" instead: still present in the SBOM, just
// not machine-classified.
var spdxIDs = func() map[string]bool {
	ids := strings.Fields(`
0BSD AFL-2.1 AFL-3.0 AGPL-1.0-only AGPL-1.0-or-later AGPL-3.0-only
AGPL-3.0-or-later Apache-1.1 Apache-2.0 Artistic-1.0 Artistic-1.0-Perl
Artistic-2.0 BlueOak-1.0.0 BSD-1-Clause BSD-2-Clause BSD-2-Clause-Patent
BSD-3-Clause BSD-3-Clause-Clear BSD-4-Clause BSL-1.0 BUSL-1.1 CC-BY-3.0
CC-BY-4.0 CC-BY-SA-3.0 CC-BY-SA-4.0 CC0-1.0 CDDL-1.0 CDDL-1.1 CPL-1.0
curl ECL-2.0 EPL-1.0 EPL-2.0 EUPL-1.1 EUPL-1.2 FSFAP FTL GFDL-1.2-only
GFDL-1.2-or-later GFDL-1.3-only GFDL-1.3-or-later GPL-1.0-only
GPL-1.0-or-later GPL-2.0-only GPL-2.0-or-later GPL-3.0-only
GPL-3.0-or-later HPND ICU IJG ImageMagick ISC JSON LGPL-2.0-only
LGPL-2.0-or-later LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0-only
LGPL-3.0-or-later Libpng libtiff MIT MIT-0 MIT-CMU MPL-1.1 MPL-2.0 MS-PL
MS-RL NCSA OFL-1.1 OLDAP-2.8 OpenSSL PHP-3.0 PHP-3.01 PostgreSQL
PSF-2.0 Python-2.0 Ruby SSPL-1.0 SISSL Sleepycat TCL Unicode-3.0
Unicode-DFS-2016 Unlicense UPL-1.0 Vim W3C WTFPL X11 Zlib ZPL-2.1
bzip2-1.0.6 blessing
GPL-2.0 GPL-2.0+ GPL-3.0 GPL-3.0+ LGPL-2.0 LGPL-2.0+ LGPL-2.1 LGPL-2.1+
LGPL-3.0 LGPL-3.0+ AGPL-3.0 GPL-1.0 GPL-1.0+ GFDL-1.2 GFDL-1.3`)
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}()

// spdxExceptions are the identifiers allowed after WITH.
var spdxExceptions = map[string]bool{
	"Classpath-exception-2.0": true, "GCC-exception-2.0": true,
	"GCC-exception-3.1": true, "LLVM-exception": true,
	"OpenSSL-exception": true, "Autoconf-exception-3.0": true,
	"Bison-exception-2.2": true, "Libtool-exception": true,
	"Linux-syscall-note": true, "OCaml-LGPL-linking-exception": true,
	"Qt-LGPL-exception-1.1": true, "Font-exception-2.0": true,
}

// IsSPDXID reports whether s is a single SPDX license identifier ojo
// recognizes.
func IsSPDXID(s string) bool { return spdxIDs[s] }

// IsSPDXExpression reports whether s is a compound SPDX license expression
// ("MIT OR Apache-2.0", "GPL-2.0-only WITH Classpath-exception-2.0") built
// only from identifiers ojo recognizes. A single identifier is not an
// expression; see IsSPDXID.
func IsSPDXExpression(s string) bool {
	tokens := strings.Fields(strings.NewReplacer("(", " ", ")", " ").Replace(s))
	if len(tokens) < 3 || strings.Count(s, "(") != strings.Count(s, ")") {
		return false
	}
	wantOperator := false
	afterWith := false
	for _, tok := range tokens {
		if wantOperator {
			if tok != "AND" && tok != "OR" && (tok != "WITH" || afterWith) {
				return false
			}
			afterWith = tok == "WITH"
			wantOperator = false
			continue
		}
		if afterWith {
			if !spdxExceptions[tok] {
				return false
			}
		} else if !spdxIDs[strings.TrimSuffix(tok, "+")] {
			return false
		}
		wantOperator = true
	}
	return wantOperator // must end on an identifier, not an operator
}
