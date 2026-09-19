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
