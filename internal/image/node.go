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
	}
	if err := json.Unmarshal(data, &pj); err != nil || pj.Name == "" || pj.Version == "" {
		return model.Package{}, false
	}
	return model.Package{Name: pj.Name, Version: pj.Version, Ecosystem: model.EcosystemNpm, Source: path}, true
}
