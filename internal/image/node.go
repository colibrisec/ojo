package image

import (
	"encoding/json"
	"regexp"

	"github.com/colibrisec/ojo/internal/model"
)

const maxPackageJSONSize = 1 << 20

var nodePackageJSONRe = regexp.MustCompile(`(^|/)node_modules/(@[^/]+/)?[^/@.][^/]*/package\.json$`)

func nodePackage(path string, data []byte) (model.Package, bool) {
	if !nodePackageJSONRe.MatchString(path) {
		return model.Package{}, false
	}
	var pj struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		License any    `json:"license"` // "MIT", or the legacy {"type": "MIT", "url": "..."}
	}
	if err := json.Unmarshal(data, &pj); err != nil || pj.Name == "" || pj.Version == "" {
		return model.Package{}, false
	}
	license, _ := pj.License.(string)
	if obj, ok := pj.License.(map[string]any); ok {
		license, _ = obj["type"].(string)
	}
	return model.Package{Name: pj.Name, Version: pj.Version, Ecosystem: model.EcosystemNpm, Source: path, License: license}, true
}
