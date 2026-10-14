// Package purl converts between packages and package-urls
// (https://github.com/package-url/purl-spec).
package purl

import (
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/colibrisec/ojo/internal/image"
	"github.com/colibrisec/ojo/internal/model"
)

type distro struct {
	prefix    string // ecosystem prefix
	namespace string // purl namespace
	id        string // os-release ID
	purlType  string
}

var distros = []distro{
	{"Debian:", "debian", "debian", packageurl.TypeDebian},
	{"Ubuntu:", "ubuntu", "ubuntu", packageurl.TypeDebian},
	{"Alpine:v", "alpine", "alpine", packageurl.TypeApk},
	{"Rocky Linux:", "rocky", "rocky", packageurl.TypeRPM},
	{"AlmaLinux:", "almalinux", "almalinux", packageurl.TypeRPM},
	{"Red Hat:enterprise_linux:", "redhat", "rhel", packageurl.TypeRPM},
	{"Amazon Linux:", "amazon", "amzn", packageurl.TypeRPM},
}

var osSourceTypes = map[string]string{"dpkg": packageurl.TypeDebian, "apk": packageurl.TypeApk, "rpm": packageurl.TypeRPM}

var langTypes = map[model.Ecosystem]string{
	model.EcosystemNpm:       packageurl.TypeNPM,
	model.EcosystemPyPI:      packageurl.TypePyPi,
	model.EcosystemCratesIO:  packageurl.TypeCargo,
	model.EcosystemRubyGems:  packageurl.TypeGem,
	model.EcosystemNuGet:     packageurl.TypeNuget,
	model.EcosystemPub:       packageurl.TypePub,
	model.EcosystemCocoaPods: packageurl.TypeCocoapods,
}

// FromPackage returns p's package-url.
func FromPackage(p model.Package) string {
	var ns, name, subpath string
	version := p.Version
	var qualifiers packageurl.Qualifiers
	typ := packageurl.TypeGeneric

	switch p.Ecosystem {
	case model.EcosystemGo:
		typ, ns, name = packageurl.TypeGolang, dir(p.Name), base(p.Name)
		if version != "" && !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
	case model.EcosystemMaven:
		typ = packageurl.TypeMaven
		if g, a, ok := strings.Cut(p.Name, ":"); ok {
			ns, name = g, a
		} else {
			name = p.Name
		}
	case model.EcosystemPackagist:
		typ, ns, name = packageurl.TypeComposer, dir(p.Name), base(p.Name)
	case model.EcosystemSwiftURL:
		typ, ns, name = packageurl.TypeSwift, dir(p.Name), base(p.Name)
	case model.EcosystemNpm:
		typ, ns, name = packageurl.TypeNPM, dir(p.Name), base(p.Name)
	case model.EcosystemCocoaPods:
		typ = packageurl.TypeCocoapods
		name, subpath, _ = strings.Cut(p.Name, "/")
	default:
		if t, ok := langTypes[p.Ecosystem]; ok {
			typ, name = t, p.Name
			break
		}
		if d, release, ok := distroOf(p.Ecosystem); ok {
			typ, ns, name = d.purlType, d.namespace, p.Name
			qualifiers = append(qualifiers, packageurl.Qualifier{Key: "distro", Value: d.id + "-" + release})
		} else if t, ok := osSourceTypes[p.Source]; ok {
			typ, ns, name = t, strings.ToLower(string(p.Ecosystem)), p.Name
		} else {
			name = p.Name
			break
		}
		if typ == packageurl.TypeRPM {
			if epoch, rest, ok := strings.Cut(version, ":"); ok {
				version = rest
				qualifiers = append(qualifiers, packageurl.Qualifier{Key: "epoch", Value: epoch})
			}
		}
		if p.Origin != "" && p.Origin != p.Name {
			qualifiers = append(qualifiers, packageurl.Qualifier{Key: "upstream", Value: p.Origin})
		}
	}
	return packageurl.NewPackageURL(typ, ns, name, version, qualifiers, subpath).ToString()
}

func distroOf(eco model.Ecosystem) (distro, string, bool) {
	for _, d := range distros {
		if release, ok := strings.CutPrefix(string(eco), d.prefix); ok {
			return d, strings.TrimSuffix(release, ":LTS"), true
		}
	}
	return distro{}, "", false
}

func dir(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[:i]
	}
	return ""
}

func base(name string) string {
	return name[strings.LastIndex(name, "/")+1:]
}

func join(ns, name, sep string) string {
	if ns == "" {
		return name
	}
	return ns + sep + name
}

var namespaceIDs = map[string]string{"redhat": "rhel", "amazon": "amzn"}

// ToPackage maps a package-url to a package. ok is false for a purl type
// ojo can't check, or one without a version. OS packages get the
// Source "dpkg", "apk" or "rpm", as an image scan gives them.
func ToPackage(s string) (p model.Package, ok bool) {
	u, err := packageurl.FromString(s)
	if err != nil || u.Version == "" {
		return model.Package{}, false
	}
	p.Version = u.Version
	switch u.Type {
	case packageurl.TypeGolang:
		p.Ecosystem, p.Name = model.EcosystemGo, join(u.Namespace, u.Name, "/")
		p.Version = strings.TrimPrefix(p.Version, "v")
	case packageurl.TypeNPM:
		p.Ecosystem, p.Name = model.EcosystemNpm, join(u.Namespace, u.Name, "/")
	case packageurl.TypeMaven:
		p.Ecosystem, p.Name = model.EcosystemMaven, join(u.Namespace, u.Name, ":")
	case packageurl.TypeComposer:
		p.Ecosystem, p.Name = model.EcosystemPackagist, join(u.Namespace, u.Name, "/")
	case packageurl.TypeSwift:
		p.Ecosystem, p.Name = model.EcosystemSwiftURL, join(u.Namespace, u.Name, "/")
	case packageurl.TypeCocoapods:
		p.Ecosystem, p.Name = model.EcosystemCocoaPods, join(u.Name, u.Subpath, "/")
		if u.Subpath == "" {
			p.Name = u.Name
		}
	case packageurl.TypeDebian, packageurl.TypeApk, packageurl.TypeRPM:
		return osPackage(u)
	default:
		for eco, t := range langTypes {
			if t == u.Type {
				p.Ecosystem, p.Name = eco, u.Name
				return p, true
			}
		}
		return model.Package{}, false
	}
	return p, true
}

func osPackage(u packageurl.PackageURL) (model.Package, bool) {
	q := u.Qualifiers.Map()
	p := model.Package{Name: u.Name, Version: u.Version}
	for source, t := range osSourceTypes {
		if t == u.Type {
			p.Source = source
		}
	}

	id := strings.ToLower(u.Namespace)
	if mapped, ok := namespaceIDs[id]; ok {
		id = mapped
	}
	release := q["distro"]
	if before, after, ok := strings.Cut(release, "-"); ok && !startsWithDigit(before) {
		release = after
	}
	if !startsWithDigit(release) {
		release = ""
	}
	if id == "debian" {
		release, _, _ = strings.Cut(release, ".")
	}
	if release == "" {
		p.Ecosystem = model.Ecosystem(id)
	} else {
		p.Ecosystem = image.OSEcosystem(id, release)
	}

	if q["epoch"] != "" && q["epoch"] != "0" && !strings.Contains(p.Version, ":") {
		p.Version = q["epoch"] + ":" + p.Version
	}
	if up := q["upstream"]; up != "" {
		up, _, _ = strings.Cut(up, "@")
		if strings.HasSuffix(up, ".rpm") {
			up = image.RPMSourceName(up)
		}
		if up != p.Name {
			p.Origin = up
		}
	}
	return p, true
}

func startsWithDigit(s string) bool {
	return s != "" && s[0] >= '0' && s[0] <= '9'
}
