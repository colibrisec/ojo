package misconfig

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/shogo82148/androidbinary"

	"github.com/colibrisec/ojo/internal/model"
)

// maxManifestSize caps how many bytes decodeAndroidManifest will read from
// a .apk's AndroidManifest.xml zip entry. A real AndroidManifest.xml is
// single-digit KB; this is deliberately generous while still defending
// against a decompression bomb (a few KB of zip data that inflates to many
// GB) in a fully attacker-controlled binary.
const maxManifestSize = 10 * 1024 * 1024 // 10 MiB

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
	Name          string                `xml:"http://schemas.android.com/apk/res/android name,attr"`
	Exported      string                `xml:"http://schemas.android.com/apk/res/android exported,attr"`
	Permission    string                `xml:"http://schemas.android.com/apk/res/android permission,attr"`
	IntentFilters []androidIntentFilter `xml:"intent-filter"`
}

// androidIntentFilter models only what's needed to detect the standard
// MAIN+LAUNCHER combination -- the one intent-filter shape that's expected,
// required, and present on virtually every app's entry activity, so an
// exported-with-no-permission finding on it is a false positive rather than
// a real misconfiguration signal.
type androidIntentFilter struct {
	Actions    []androidIntentFilterName `xml:"action"`
	Categories []androidIntentFilterName `xml:"category"`
}

type androidIntentFilterName struct {
	Name string `xml:"http://schemas.android.com/apk/res/android name,attr"`
}

// isLauncherIntentFilter reports whether f is the standard "this is the
// app's main entry point" intent-filter: android.intent.action.MAIN paired
// with android.intent.category.LAUNCHER in the same filter.
func isLauncherIntentFilter(f androidIntentFilter) bool {
	hasMain := false
	for _, a := range f.Actions {
		if a.Name == "android.intent.action.MAIN" {
			hasMain = true
			break
		}
	}
	if !hasMain {
		return false
	}
	for _, c := range f.Categories {
		if c.Name == "android.intent.category.LAUNCHER" {
			return true
		}
	}
	return false
}

// componentHasLauncherIntent reports whether any of c's intent-filters is
// the standard MAIN+LAUNCHER launcher-activity filter.
func componentHasLauncherIntent(c androidComponent) bool {
	for _, f := range c.IntentFilters {
		if isLauncherIntentFilter(f) {
			return true
		}
	}
	return false
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

// sanityCheckAXML performs a minimal size-vs-declared-count pre-flight over
// raw AXML bytes before handing them to androidbinary.NewXMLFile. AXML's
// string pool chunk declares its StringCount/StyleCount near the front of
// the file (byte offsets 16 and 20 -- 8 bytes for the outer chunk's own
// ResChunkHeader, then 8 more for the string pool chunk's own ResChunkHeader,
// then the two uint32 counts), and androidbinary trusts those values to
// allocate a same-sized slice with no bounds check -- a crafted file
// declaring an enormous count triggers an unrecoverable
// "fatal error: out of memory" (recover() cannot catch a Go runtime fatal
// error) before any real parsing happens. A pool can't legitimately declare
// more strings/styles than there's room for 4-byte offset entries in the
// file, so this catches the attack class cheaply and deterministically.
func sanityCheckAXML(raw []byte) error {
	const stringCountOffset = 16
	const minLen = stringCountOffset + 8 // + StringCount(4) + StyleCount(4)
	if len(raw) < minLen {
		return fmt.Errorf("AXML data too short (%d bytes) to contain a string pool header", len(raw))
	}
	stringCount := binary.LittleEndian.Uint32(raw[stringCountOffset : stringCountOffset+4])
	styleCount := binary.LittleEndian.Uint32(raw[stringCountOffset+4 : stringCountOffset+8])
	if uint64(stringCount)*4 > uint64(len(raw)) {
		return fmt.Errorf("AXML string pool declares %d strings, impossible for a %d-byte file", stringCount, len(raw))
	}
	if uint64(styleCount)*4 > uint64(len(raw)) {
		return fmt.Errorf("AXML string pool declares %d styles, impossible for a %d-byte file", styleCount, len(raw))
	}
	return nil
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
			if f.UncompressedSize64 > maxManifestSize {
				return androidManifest{}, fmt.Errorf("%s: AndroidManifest.xml entry too large (%d bytes, cap %d)", path, f.UncompressedSize64, uint64(maxManifestSize))
			}
			rc, err := f.Open()
			if err != nil {
				return androidManifest{}, err
			}
			raw, err = io.ReadAll(io.LimitReader(rc, maxManifestSize+1))
			rc.Close()
			if err != nil {
				return androidManifest{}, err
			}
			if len(raw) > maxManifestSize {
				return androidManifest{}, fmt.Errorf("%s: AndroidManifest.xml entry exceeds %d-byte cap", path, maxManifestSize)
			}
			break
		}
	}
	if raw == nil {
		return androidManifest{}, fmt.Errorf("%s: no AndroidManifest.xml entry", path)
	}
	if err := sanityCheckAXML(raw); err != nil {
		return androidManifest{}, fmt.Errorf("%s: %w", path, err)
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
			if componentHasLauncherIntent(c) {
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
