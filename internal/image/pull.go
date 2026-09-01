// Package image scans a container image's OS package databases for
// vulnerable packages, producing model.Package values that feed the same
// OSV pipeline used for filesystem dependency scanning.
package image

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// parsePlatform parses a "--platform os/arch" value. "" means the default,
// linux/amd64.
func parsePlatform(s string) (v1.Platform, error) {
	if s == "" {
		return v1.Platform{OS: "linux", Architecture: "amd64"}, nil
	}
	os, arch, ok := strings.Cut(s, "/")
	if !ok || os == "" || arch == "" {
		return v1.Platform{}, fmt.Errorf("invalid --platform %q, expected \"os/arch\" (e.g. linux/arm64)", s)
	}
	return v1.Platform{OS: os, Architecture: arch}, nil
}

func extractFS(ctx context.Context, ref, platform string) (io.ReadCloser, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	plat, err := parsePlatform(platform)
	if err != nil {
		return nil, err
	}
	img, err := remote.Image(r,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithPlatform(plat),
	)
	if err != nil {
		return nil, err
	}
	return mutate.Extract(img), nil
}
