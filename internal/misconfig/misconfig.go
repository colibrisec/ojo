// Package misconfig checks Dockerfiles, Kubernetes manifests, and Terraform
// for common security misconfigurations.
package misconfig

import (
	"io/fs"
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

// Scan walks root and runs Dockerfile, Kubernetes, and Terraform checks
// against every recognized file.
func Scan(root string) ([]model.Issue, error) {
	var issues []model.Issue
	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		name := d.Name()
		switch {
		case isDockerfile(name):
			found, err := scanDockerfile(path)
			if err != nil {
				return nil // ponytail: skip unparsable file, don't fail the whole scan
			}
			issues = append(issues, found...)
		case strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml"):
			found, err := scanK8sManifest(path)
			if err != nil {
				return nil
			}
			issues = append(issues, found...)
		case strings.HasSuffix(name, ".tf"):
			found, err := scanTerraform(path)
			if err != nil {
				return nil
			}
			issues = append(issues, found...)
		}
		return nil
	})
	return issues, err
}
