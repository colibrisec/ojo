package image

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

func parseOSRelease(data []byte) map[string]string {
	info := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		info[k] = strings.Trim(v, `"'`)
	}
	return info
}

var rpmDistros = map[string]bool{"rhel": true, "centos": true, "fedora": true, "amzn": true, "rocky": true, "almalinux": true}

func isRPMBased(info map[string]string) bool {
	if rpmDistros[info["ID"]] {
		return true
	}
	for _, like := range strings.Fields(info["ID_LIKE"]) {
		if rpmDistros[like] {
			return true
		}
	}
	return false
}

// osEcosystem builds the OSV.dev ecosystem string for the detected distro.
//
// ponytail: Ubuntu LTS detection is a release-history heuristic (even year,
// April release), not derived from a Debian/Ubuntu API. Verify against
// OSV's actual ecosystem list if scanning Ubuntu images matters to you.
func osEcosystem(info map[string]string) model.Ecosystem {
	id := info["ID"]
	version := info["VERSION_ID"]
	switch id {
	case "alpine":
		parts := strings.SplitN(version, ".", 3)
		if len(parts) >= 2 {
			version = parts[0] + "." + parts[1]
		}
		return model.Ecosystem("Alpine:v" + version)
	case "debian":
		return model.Ecosystem("Debian:" + version)
	case "ubuntu":
		if isUbuntuLTS(version) {
			return model.Ecosystem("Ubuntu:" + version + ":LTS")
		}
		return model.Ecosystem("Ubuntu:" + version)
	default:
		return model.Ecosystem(id)
	}
}

func isUbuntuLTS(version string) bool {
	year, month, ok := strings.Cut(version, ".")
	if !ok || month != "04" {
		return false
	}
	y, err := strconv.Atoi(year)
	return err == nil && y%2 == 0
}
