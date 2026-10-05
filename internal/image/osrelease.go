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
	case "rocky":
		return model.Ecosystem("Rocky Linux:" + majorVersion(version))
	case "almalinux":
		return model.Ecosystem("AlmaLinux:" + majorVersion(version))
	case "rhel": // also Red Hat's UBI images
		// Through RHEL 9, OSV files advisories per major version and
		// repository (internal/osv adds the repository); from RHEL 10 on,
		// per minor version.
		if major := majorVersion(version); major == "7" || major == "8" || major == "9" {
			return model.Ecosystem("Red Hat:enterprise_linux:" + major)
		}
		return model.Ecosystem("Red Hat:enterprise_linux:" + version)
	default:
		// Not a distribution ojo can form an OSV ecosystem for; see
		// WithoutAdvisories.
		return model.Ecosystem(id)
	}
}

func majorVersion(version string) string {
	major, _, _ := strings.Cut(version, ".")
	return major
}

func isUbuntuLTS(version string) bool {
	year, month, ok := strings.Cut(version, ".")
	if !ok || month != "04" {
		return false
	}
	y, err := strconv.Atoi(year)
	return err == nil && y%2 == 0
}
