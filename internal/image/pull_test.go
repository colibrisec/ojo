package image

import "testing"

func TestParsePlatform(t *testing.T) {
	got, err := parsePlatform("")
	if err != nil || got.OS != "linux" || got.Architecture != "amd64" {
		t.Errorf("expected default linux/amd64, got %+v, err=%v", got, err)
	}

	got, err = parsePlatform("linux/arm64")
	if err != nil || got.OS != "linux" || got.Architecture != "arm64" {
		t.Errorf("expected linux/arm64, got %+v, err=%v", got, err)
	}

	if _, err := parsePlatform("linux"); err == nil {
		t.Error("expected an error for a platform with no arch")
	}
	if _, err := parsePlatform("/arm64"); err == nil {
		t.Error("expected an error for a platform with no os")
	}
}
