// Package image scans a container image's OS package databases for
// vulnerable packages, producing model.Package values that feed the same
// OSV pipeline used for filesystem dependency scanning.
package image

import (
	"context"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// extractFS resolves ref against its registry and returns a tar stream of
// the image's flattened (whiteout-resolved) filesystem. Defaults to
// linux/amd64.
//
// ponytail: single fixed platform for v1; add a --platform flag if
// multi-arch scanning is needed.
func extractFS(ctx context.Context, ref string) (io.ReadCloser, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	img, err := remote.Image(r,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"}),
	)
	if err != nil {
		return nil, err
	}
	return mutate.Extract(img), nil
}
