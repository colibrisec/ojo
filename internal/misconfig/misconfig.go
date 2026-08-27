// Package misconfig checks Dockerfiles, Kubernetes manifests, Terraform, MCP
// server configs, and Claude Code skill definitions for common security
// misconfigurations.
package misconfig

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/walk"
)

func newIssue(ruleID, severity, path string, line int, title, message string) model.Issue {
	return model.Issue{
		Scanner:  "misconfig",
		RuleID:   ruleID,
		Title:    title,
		Severity: severity,
		File:     path,
		Line:     line,
		Message:  message,
	}
}

func Scan(root string) ([]model.Issue, error) {
	var issues []model.Issue
	tfFilesByDir := map[string][]string{}

	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		name := d.Name()
		switch {
		case isDockerfile(name):
			found, err := scanDockerfile(path)
			if err != nil {
				return nil // ponytail: skip unparsable file, don't fail the whole scan
			}
			issues = append(issues, found...)
		case isSkillFile(name):
			found, err := scanSkill(path)
			if err != nil {
				return nil
			}
			issues = append(issues, found...)
		case strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml"):
			// A YAML file is tried as both a Kubernetes manifest and a
			// CloudFormation template -- each is a no-op on a file that
			// doesn't look like its format, so there's no real ambiguity cost.
			if found, err := scanK8sManifest(path); err == nil {
				issues = append(issues, found...)
			}
			if found, err := scanCloudFormation(path); err == nil {
				issues = append(issues, found...)
			}
		case strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".template"):
			if found, err := scanCloudFormation(path); err == nil {
				issues = append(issues, found...)
			}
			if found, err := scanMCPConfig(path); err == nil {
				issues = append(issues, found...)
			}
		case strings.HasSuffix(name, ".tf"):
			// Grouped by directory, not scanned file-by-file: all .tf files in
			// one directory form a single Terraform module, sharing locals and
			// variables and routinely splitting one resource's related config
			// (e.g. an S3 bucket and its versioning) across files.
			dir := filepath.Dir(path)
			tfFilesByDir[dir] = append(tfFilesByDir[dir], path)
		}
		return nil
	})
	if err != nil {
		return issues, err
	}

	dirs := make([]string, 0, len(tfFilesByDir))
	for dir := range tfFilesByDir {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		issues = append(issues, scanTerraformDir(tfFilesByDir[dir])...)
	}
	return issues, nil
}
