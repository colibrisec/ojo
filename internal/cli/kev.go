package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/colibrisec/ojo/internal/kev"
	"github.com/colibrisec/ojo/internal/model"
)

// annotateKEV loads the CISA KEV catalog (cached ~/.cache/ojo/kev.json,
// refetched once a day) and marks findings whose CVE is in it. A failed
// fetch with no usable cache is returned as an error -- the user explicitly
// asked for KEV data via --kev, so silently skipping it would hide that it
// didn't happen; a fetch failure with a stale cache available prints a
// warning to stderr instead, since stale KEV data is still useful.
func annotateKEV(cmd *cobra.Command, findings []model.Finding) error {
	set, stale, err := kevLoad(kev.DefaultCachePath())
	if err != nil {
		return fmt.Errorf("loading KEV catalog: %w", err)
	}
	if stale {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: could not refresh the CISA KEV catalog, using a cached copy that may be out of date")
	}
	kev.Annotate(findings, set)
	return nil
}
