package misconfig

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/shogo82148/androidbinary"

	"github.com/colibrisec/ojo/internal/model"
)

func isAPKFile(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".apk")
}

type androidPermission struct {
	Name string `xml:"http://schemas.android.com/apk/res/android name,attr"`
}

// androidComponent covers an activity/service/receiver/provider -- the four
// manifest element types that share the same exported/permission/
// intent-filter shape.
type androidComponent struct {
	Name          string     `xml:"http://schemas.android.com/apk/res/android name,attr"`
	Exported      string     `xml:"http://schemas.android.com/apk/res/android exported,attr"`
	Permission    string     `xml:"http://schemas.android.com/apk/res/android permission,attr"`
	IntentFilters []struct{} `xml:"intent-filter"`
}

type androidApplication struct {
	Debuggable           string             `xml:"http://schemas.android.com/apk/res/android debuggable,attr"`
	UsesCleartextTraffic string             `xml:"http://schemas.android.com/apk/res/android usesCleartextTraffic,attr"`
	Permission           string             `xml:"http://schemas.android.com/apk/res/android permission,attr"`
	Activities           []androidComponent `xml:"activity"`
	Services             []androidComponent `xml:"service"`
	Receivers            []androidComponent `xml:"receiver"`
	Providers            []androidComponent `xml:"provider"`
}

type androidManifest struct {
	XMLName         xml.Name            `xml:"manifest"`
	Package         string              `xml:"package,attr"`
	UsesPermissions []androidPermission `xml:"uses-permission"`
	Application     androidApplication  `xml:"application"`
}

// decodeAndroidManifest opens path as a zip archive, decodes its
// AndroidManifest.xml entry from Android's compiled binary XML format
// (AXML) via androidbinary, and unmarshals the resulting plain XML into an
// androidManifest.
func decodeAndroidManifest(path string) (androidManifest, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return androidManifest{}, err
	}
	defer r.Close()

	var raw []byte
	for _, f := range r.File {
		if f.Name == "AndroidManifest.xml" {
			rc, err := f.Open()
			if err != nil {
				return androidManifest{}, err
			}
			raw, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return androidManifest{}, err
			}
			break
		}
	}
	if raw == nil {
		return androidManifest{}, fmt.Errorf("%s: no AndroidManifest.xml entry", path)
	}

	xf, err := androidbinary.NewXMLFile(bytes.NewReader(raw))
	if err != nil {
		return androidManifest{}, err
	}
	xmlBytes, err := io.ReadAll(xf.Reader())
	if err != nil {
		return androidManifest{}, err
	}

	var m androidManifest
	if err := xml.Unmarshal(xmlBytes, &m); err != nil {
		return androidManifest{}, err
	}
	return m, nil
}

// scanAndroidManifest decodes path's AndroidManifest.xml and runs every
// android-* misconfig check against it.
func scanAndroidManifest(path string) ([]model.Issue, error) {
	m, err := decodeAndroidManifest(path)
	if err != nil {
		return nil, err
	}
	var issues []model.Issue
	issues = append(issues, checkAndroidDebuggable(m, path)...)
	issues = append(issues, checkAndroidCleartextTraffic(m, path)...)
	issues = append(issues, checkAndroidExportedComponents(m, path)...)
	issues = append(issues, checkAndroidBroadPermissions(m, path)...)
	return issues, nil
}

func checkAndroidDebuggable(m androidManifest, path string) []model.Issue {
	if m.Application.Debuggable == "true" {
		return []model.Issue{newIssue("android-debuggable", "HIGH", path, 1,
			"Application is debuggable",
			`<application android:debuggable="true"> ships in the built APK`)}
	}
	return nil
}

func checkAndroidCleartextTraffic(m androidManifest, path string) []model.Issue {
	if m.Application.UsesCleartextTraffic == "true" {
		return []model.Issue{newIssue("android-cleartext-traffic", "MEDIUM", path, 1,
			"Application explicitly allows cleartext network traffic",
			`<application android:usesCleartextTraffic="true">`)}
	}
	return nil
}

func checkAndroidExportedComponents(m androidManifest, path string) []model.Issue {
	var issues []model.Issue
	kinds := []struct {
		kind string
		list []androidComponent
	}{
		{"activity", m.Application.Activities},
		{"service", m.Application.Services},
		{"receiver", m.Application.Receivers},
		{"provider", m.Application.Providers},
	}
	for _, k := range kinds {
		for _, c := range k.list {
			// A component with no explicit android:exported is exported by
			// default when it has an intent-filter -- real pre-API-31
			// platform behavior, not a guess.
			exported := c.Exported == "true" || (c.Exported == "" && len(c.IntentFilters) > 0)
			if !exported {
				continue
			}
			if c.Permission != "" || m.Application.Permission != "" {
				continue
			}
			issues = append(issues, newIssue("android-exported-component-no-permission", "HIGH", path, 1,
				"Exported component has no permission guard",
				fmt.Sprintf("%s %s is exported with no android:permission at the component or application level", k.kind, c.Name)))
		}
	}
	return issues
}

// androidBroadPermissions is a curated, deliberately non-exhaustive list of
// high-risk permissions -- same curated-list precedent as this package's
// mcp-cross-origin-credential vendor table.
var androidBroadPermissions = map[string]bool{
	"android.permission.QUERY_ALL_PACKAGES":         true,
	"android.permission.SYSTEM_ALERT_WINDOW":        true,
	"android.permission.REQUEST_INSTALL_PACKAGES":   true,
	"android.permission.READ_SMS":                   true,
	"android.permission.RECEIVE_SMS":                true,
	"android.permission.BIND_ACCESSIBILITY_SERVICE": true,
	"android.permission.WRITE_SECURE_SETTINGS":      true,
	"android.permission.MANAGE_EXTERNAL_STORAGE":    true,
}

func checkAndroidBroadPermissions(m androidManifest, path string) []model.Issue {
	var issues []model.Issue
	for _, p := range m.UsesPermissions {
		if androidBroadPermissions[p.Name] {
			issues = append(issues, newIssue("android-broad-permission", "MEDIUM", path, 1,
				"Requests a high-risk permission",
				"uses-permission "+p.Name))
		}
	}
	return issues
}
