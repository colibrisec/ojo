package misconfig

import (
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/colibrisec/ojo/internal/model"
)

func scanTerraform(path string) ([]model.Issue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, diags := hclsyntax.ParseConfig(data, path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() || f == nil {
		return nil, nil // ponytail: skip files we can't parse, don't fail the whole scan
	}
	body, ok := f.Body.(*hclsyntax.Body)
	if !ok {
		return nil, nil
	}

	var issues []model.Issue
	for _, block := range body.Blocks {
		if block.Type != "resource" || len(block.Labels) < 2 {
			continue
		}
		issues = append(issues, terraformResourceChecks(block, path)...)
	}
	return issues, nil
}

func terraformResourceChecks(block *hclsyntax.Block, path string) []model.Issue {
	resType, resName := block.Labels[0], block.Labels[1]
	line := block.DefRange().Start.Line
	var issues []model.Issue

	switch {
	case resType == "aws_s3_bucket":
		if acl, ok := attrString(block.Body, "acl"); ok && (acl == "public-read" || acl == "public-read-write") {
			issues = append(issues, newIssue("tf-s3-public-acl", "CRITICAL", path, line,
				"S3 bucket has a public ACL", resType+"."+resName+" acl = \""+acl+"\""))
		}

	case resType == "aws_security_group" || resType == "aws_security_group_rule":
		for _, ing := range findIngressBlocks(block) {
			if hasOpenCIDR(ing) {
				issues = append(issues, newIssue("tf-security-group-open-ingress", "CRITICAL", path, line,
					"Security group allows ingress from 0.0.0.0/0", resType+"."+resName))
			}
		}

	case resType == "aws_db_instance" || resType == "aws_ebs_volume":
		if b, ok := attrBool(block.Body, "storage_encrypted"); ok && !b {
			issues = append(issues, newIssue("tf-unencrypted-storage", "HIGH", path, line,
				"Storage is explicitly unencrypted", resType+"."+resName+" storage_encrypted = false"))
		}

	case resType == "aws_iam_policy" || resType == "aws_iam_role_policy" || resType == "aws_iam_user_policy":
		if policy, ok := attrString(block.Body, "policy"); ok &&
			strings.Contains(policy, `"Action": "*"`) && strings.Contains(policy, `"Resource": "*"`) {
			issues = append(issues, newIssue("tf-iam-wildcard-policy", "CRITICAL", path, line,
				"IAM policy grants Action=* on Resource=*", resType+"."+resName))
		}
	}
	return issues
}

func findIngressBlocks(block *hclsyntax.Block) []*hclsyntax.Block {
	var out []*hclsyntax.Block
	if block.Type == "ingress" {
		out = append(out, block)
	}
	for _, b := range block.Body.Blocks {
		out = append(out, findIngressBlocks(b)...)
	}
	return out
}

func hasOpenCIDR(block *hclsyntax.Block) bool {
	attr, ok := block.Body.Attributes["cidr_blocks"]
	if !ok {
		return false
	}
	val, diags := attr.Expr.Value(nil)
	if diags.HasErrors() || val.IsNull() || !val.CanIterateElements() {
		return false
	}
	for it := val.ElementIterator(); it.Next(); {
		_, v := it.Element()
		if v.Type() == cty.String && v.AsString() == "0.0.0.0/0" {
			return true
		}
	}
	return false
}

func attrString(body *hclsyntax.Body, name string) (string, bool) {
	attr, ok := body.Attributes[name]
	if !ok {
		return "", false
	}
	val, diags := attr.Expr.Value(nil)
	if diags.HasErrors() || val.Type() != cty.String {
		return "", false
	}
	return val.AsString(), true
}

func attrBool(body *hclsyntax.Body, name string) (bool, bool) {
	attr, ok := body.Attributes[name]
	if !ok {
		return false, false
	}
	val, diags := attr.Expr.Value(nil)
	if diags.HasErrors() || val.Type() != cty.Bool {
		return false, false
	}
	return val.True(), true
}
