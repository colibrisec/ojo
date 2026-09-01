package cli

import (
	"github.com/colibrisec/ojo/internal/image"
	"github.com/colibrisec/ojo/internal/kev"
	"github.com/colibrisec/ojo/internal/osv"
)

// Indirected through vars, not called directly, so tests can substitute
// fakes for calls that would otherwise hit a real external service (OSV.dev,
// a container registry, CISA's KEV feed) this package has no other way to
// stub -- same idiom internal/osv/internal/kev already use internally for
// their own network calls (apiBase/feedURL).
var (
	osvScan   = osv.Scan
	imageScan = image.Scan
	kevLoad   = kev.Load
)
