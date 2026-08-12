package misconfig

import (
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/colibrisec/ojo/internal/model"
)

// Checks below intentionally treat "attribute absent" the same as "attribute
// false" for attributes whose Terraform/provider default is the insecure
// value (e.g. a security group's absent `internal` defaults to
// internet-facing). Attribute values are resolved through an hcl.EvalContext
// built from locals{} and variable{default=...} blocks in the same
// directory (see buildEvalContext) -- an expression that still can't be
// resolved (a module input, a reference to another resource's attribute,
// dynamic blocks) falls back to the same "can't tell -> flag" treatment.
// See the "literal values only" limitation in docs/roadmap.md.

// tfBlock pairs a parsed block with the file it came from, since checks
// need the file path for reporting but directory-level scanning parses
// several files together.
type tfBlock struct {
	block *hclsyntax.Block
	path  string
}

func parseTFFile(path string) (*hclsyntax.Body, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	f, diags := hclsyntax.ParseConfig(data, path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() || f == nil {
		return nil, false // ponytail: skip files we can't parse, don't fail the whole scan
	}
	body, ok := f.Body.(*hclsyntax.Body)
	return body, ok
}

// scanTerraformDir scans every .tf file in one directory as a single
// Terraform module: shared locals/variables, and cross-resource checks
// (e.g. S3 bucket <-> its versioning/logging resources) matched across
// files, not just within one.
func scanTerraformDir(files []string) []model.Issue {
	var resources, dataSources, localsBlocks, variableBlocks []tfBlock

	for _, path := range files {
		body, ok := parseTFFile(path)
		if !ok {
			continue
		}
		for _, block := range body.Blocks {
			switch block.Type {
			case "resource":
				if len(block.Labels) >= 2 {
					resources = append(resources, tfBlock{block, path})
				}
			case "data":
				if len(block.Labels) >= 2 {
					dataSources = append(dataSources, tfBlock{block, path})
				}
			case "locals":
				localsBlocks = append(localsBlocks, tfBlock{block, path})
			case "variable":
				if len(block.Labels) >= 1 {
					variableBlocks = append(variableBlocks, tfBlock{block, path})
				}
			}
		}
	}

	ctx := buildEvalContext(localsBlocks, variableBlocks)

	var issues []model.Issue
	for _, r := range resources {
		issues = append(issues, terraformResourceChecks(r.block, r.path, ctx)...)
	}
	issues = append(issues, terraformS3CrossResourceChecks(resources, ctx)...)
	issues = append(issues, terraformVPCFlowLogChecks(resources)...)
	for _, d := range dataSources {
		issues = append(issues, terraformDataSourceChecks(d.block, d.path)...)
	}
	return issues
}

// buildEvalContext resolves `local.x` and `var.x` (variables with a
// literal default) so attribute checks can see through them. Locals may
// reference other locals or variables; since there's no dependency graph
// here, a few passes converge on the common case of a short chain.
func buildEvalContext(localsBlocks, variableBlocks []tfBlock) *hcl.EvalContext {
	ctx := &hcl.EvalContext{Variables: map[string]cty.Value{}}

	varVals := map[string]cty.Value{}
	for _, vb := range variableBlocks {
		def, ok := vb.block.Body.Attributes["default"]
		if !ok {
			continue
		}
		if v, diags := def.Expr.Value(nil); !diags.HasErrors() {
			varVals[vb.block.Labels[0]] = v
		}
	}
	ctx.Variables["var"] = cty.ObjectVal(varVals)

	localVals := map[string]cty.Value{}
	for range 5 {
		ctx.Variables["local"] = cty.ObjectVal(localVals)
		changed := false
		for _, lb := range localsBlocks {
			for name, attr := range lb.block.Body.Attributes {
				v, diags := attr.Expr.Value(ctx)
				if diags.HasErrors() {
					continue
				}
				if existing, ok := localVals[name]; !ok || !existing.RawEquals(v) {
					localVals[name] = v
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	ctx.Variables["local"] = cty.ObjectVal(localVals)
	return ctx
}

// resourceCheck inspects one resource block in isolation. Each check owns
// its own resource-type filter, so a resource type can be covered by
// several independent checks (e.g. aws_db_instance gets encryption,
// Performance Insights, and IAM-auth checks from three different funcs).
type resourceCheck func(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue

// terraformChecks is every registered check across all provider files
// (this file's AWS checks, terraform_azure.go's azurerm checks,
// terraform_gcp.go's google checks) -- combined here so
// terraformResourceChecks doesn't need to know about providers at all.
var terraformChecks = slices.Concat(awsResourceChecks, azureResourceChecks, gcpResourceChecks)

var awsResourceChecks = []resourceCheck{
	checkS3PublicACL,
	checkS3BucketNameDNSCompliant,
	checkSecurityGroupRules,
	checkStorageEncryption,
	checkIAMWildcardPolicy,
	checkIAMUserPolicyAttachment,
	checkIAMPasswordPolicy,
	checkIMDSv2,
	checkEBSRootVolumeEncryption,
	checkCloudWatchLogGroupEncryption,
	checkALB,
	checkLBListenerPlainHTTP,
	checkLambdaXRay,
	checkLambdaFunctionURLAuth,
	checkRDSPerformanceInsightsAndIAMAuth,
	checkECR,
	checkSNSEncryption,
	checkSQSEncryption,
	checkSecretsManagerEncryption,
	checkKMSRotation,
	checkCloudFrontWAFAndLogging,
	checkCloudFrontTLS,
	checkAPIGatewayLogging,
	checkAPIGatewayMethodAuth,
	checkEKSCluster,
	checkCloudTrail,
	checkGuardDuty,
	checkDynamoDBPITR,
	checkElastiCacheEncryption,
	checkRedshift,
	checkEFSEncryption,
	checkKinesisEncryption,
	checkECSTaskDefinition,
}

func terraformResourceChecks(block *hclsyntax.Block, path string, ctx *hcl.EvalContext) []model.Issue {
	resType, resName := block.Labels[0], block.Labels[1]
	line := block.DefRange().Start.Line
	var issues []model.Issue
	for _, check := range terraformChecks {
		issues = append(issues, check(resType, resName, path, line, block.Body, ctx)...)
	}
	return issues
}

func terraformDataSourceChecks(block *hclsyntax.Block, path string) []model.Issue {
	if block.Labels[0] != "aws_ami" {
		return nil
	}
	if _, ok := block.Body.Attributes["owners"]; ok {
		return nil
	}
	return []model.Issue{newIssue("tf-ami-no-owners", "LOW", path, block.DefRange().Start.Line,
		"aws_ami data source does not restrict owners",
		"data.aws_ami."+block.Labels[1]+" has no owners filter")}
}

// --- S3 ---

func checkS3PublicACL(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_s3_bucket" {
		return nil
	}
	if acl, ok := attrString(body, "acl", ctx); ok && (acl == "public-read" || acl == "public-read-write") {
		return []model.Issue{newIssue("tf-s3-public-acl", "CRITICAL", path, line,
			"S3 bucket has a public ACL", resType+"."+resName+" acl = \""+acl+"\"")}
	}
	return nil
}

var s3NameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func checkS3BucketNameDNSCompliant(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_s3_bucket" {
		return nil
	}
	name, ok := attrString(body, "bucket", ctx)
	if !ok || s3NameRe.MatchString(name) {
		return nil
	}
	return []model.Issue{newIssue("tf-s3-bucket-name-not-dns-compliant", "MEDIUM", path, line,
		"S3 bucket name is not DNS-compliant", resType+"."+resName+" bucket = \""+name+"\"")}
}

// terraformS3CrossResourceChecks handles the modern (provider v4+) style
// where versioning/encryption/logging/public-access-block are separate
// resources that reference their bucket via `bucket = aws_s3_bucket.x.id`,
// plus the older inline-block style on aws_s3_bucket itself. References
// are matched across every file in the directory (see scanTerraformDir).
func terraformS3CrossResourceChecks(resources []tfBlock, ctx *hcl.EvalContext) []model.Issue {
	type bucketInfo struct {
		block               *hclsyntax.Block
		path                string
		versioned           bool
		encrypted           bool
		logged              bool
		hasAccessBlock      bool
		accessBlockComplete bool
	}
	buckets := map[string]*bucketInfo{}
	get := func(name string) *bucketInfo {
		if b, ok := buckets[name]; ok {
			return b
		}
		b := &bucketInfo{}
		buckets[name] = b
		return b
	}

	for _, rb := range resources {
		r := rb.block
		resType, resName := r.Labels[0], r.Labels[1]
		switch resType {
		case "aws_s3_bucket":
			b := get(resName)
			b.block = r
			b.path = rb.path
			for _, nested := range r.Body.Blocks {
				switch nested.Type {
				case "versioning":
					if s, ok := attrString(nested.Body, "status", ctx); ok && s == "Enabled" {
						b.versioned = true
					} else if e, ok := attrBool(nested.Body, "enabled", ctx); ok && e {
						b.versioned = true
					}
				case "server_side_encryption_configuration":
					b.encrypted = true
				case "logging":
					b.logged = true
				}
			}
		case "aws_s3_bucket_versioning":
			name, ok := attrRefName(r.Body, "bucket", "aws_s3_bucket")
			if !ok {
				continue
			}
			if vc := findBlockByType(r.Body, "versioning_configuration"); vc != nil {
				if s, ok := attrString(vc.Body, "status", ctx); ok && s == "Enabled" {
					get(name).versioned = true
				}
			}
		case "aws_s3_bucket_server_side_encryption_configuration":
			if name, ok := attrRefName(r.Body, "bucket", "aws_s3_bucket"); ok {
				get(name).encrypted = true
			}
		case "aws_s3_bucket_logging":
			if name, ok := attrRefName(r.Body, "bucket", "aws_s3_bucket"); ok {
				get(name).logged = true
			}
		case "aws_s3_bucket_public_access_block":
			name, ok := attrRefName(r.Body, "bucket", "aws_s3_bucket")
			if !ok {
				continue
			}
			b := get(name)
			b.hasAccessBlock = true
			complete := true
			for _, attrName := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
				if v, ok := attrBool(r.Body, attrName, ctx); !ok || !v {
					complete = false
				}
			}
			b.accessBlockComplete = complete
		}
	}

	var issues []model.Issue
	for name, b := range buckets {
		if b.block == nil {
			continue // referenced by a sub-resource but not declared in this directory (module input, etc.)
		}
		line := b.block.DefRange().Start.Line
		addr := "aws_s3_bucket." + name
		if !b.versioned {
			issues = append(issues, newIssue("tf-s3-versioning-disabled", "MEDIUM", b.path, line,
				"S3 bucket does not have versioning enabled", addr))
		}
		if !b.logged {
			issues = append(issues, newIssue("tf-s3-logging-disabled", "LOW", b.path, line,
				"S3 bucket does not have access logging enabled", addr))
		}
		if !b.encrypted {
			issues = append(issues, newIssue("tf-s3-unencrypted", "MEDIUM", b.path, line,
				"S3 bucket has no server-side encryption configuration", addr))
		}
		if !b.hasAccessBlock {
			issues = append(issues, newIssue("tf-s3-missing-public-access-block", "HIGH", b.path, line,
				"S3 bucket has no aws_s3_bucket_public_access_block resource", addr))
		} else if !b.accessBlockComplete {
			issues = append(issues, newIssue("tf-s3-public-access-block-incomplete", "HIGH", b.path, line,
				"S3 bucket's public access block does not block all public access", addr))
		}
	}
	return issues
}

// --- VPC / networking ---

// terraformVPCFlowLogChecks flags an aws_vpc with no aws_flow_log resource
// referencing it anywhere in the directory.
func terraformVPCFlowLogChecks(resources []tfBlock) []model.Issue {
	type vpcInfo struct {
		block   *hclsyntax.Block
		path    string
		resName string
		logged  bool
	}
	vpcs := map[string]*vpcInfo{}

	for _, rb := range resources {
		r := rb.block
		if r.Labels[0] == "aws_vpc" {
			vpcs[r.Labels[1]] = &vpcInfo{block: r, path: rb.path, resName: r.Labels[1]}
		}
	}
	if len(vpcs) == 0 {
		return nil
	}
	for _, rb := range resources {
		r := rb.block
		if r.Labels[0] != "aws_flow_log" {
			continue
		}
		if name, ok := attrRefName(r.Body, "vpc_id", "aws_vpc"); ok {
			if v, ok := vpcs[name]; ok {
				v.logged = true
			}
		}
	}

	var issues []model.Issue
	for _, v := range vpcs {
		if !v.logged {
			issues = append(issues, newIssue("tf-vpc-no-flow-log", "MEDIUM", v.path, v.block.DefRange().Start.Line,
				"VPC does not have flow logging enabled", "aws_vpc."+v.resName))
		}
	}
	return issues
}

func checkSecurityGroupRules(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	var issues []model.Issue
	switch resType {
	case "aws_security_group", "aws_default_security_group":
		for _, b := range body.Blocks {
			if b.Type == "ingress" || b.Type == "egress" {
				issues = append(issues, sgRuleIssues(b.Type, b.Body, resType, resName, path, line, ctx)...)
			}
		}
	case "aws_security_group_rule":
		if kind, ok := attrString(body, "type", ctx); ok && (kind == "ingress" || kind == "egress") {
			issues = append(issues, sgRuleIssues(kind, body, resType, resName, path, line, ctx)...)
		}
	}
	return issues
}

func sgRuleIssues(kind string, body *hclsyntax.Body, resType, resName, path string, line int, ctx *hcl.EvalContext) []model.Issue {
	var issues []model.Issue
	if hasOpenCIDR(body, ctx) {
		if kind == "egress" {
			issues = append(issues, newIssue("tf-security-group-open-egress", "CRITICAL", path, line,
				"Security group allows unrestricted egress to 0.0.0.0/0", resType+"."+resName))
		} else {
			issues = append(issues, newIssue("tf-security-group-open-ingress", "CRITICAL", path, line,
				"Security group allows ingress from 0.0.0.0/0", resType+"."+resName))
		}
	}
	if _, ok := attrString(body, "description", ctx); !ok {
		issues = append(issues, newIssue("tf-security-group-rule-no-description", "LOW", path, line,
			"Security group "+kind+" rule has no description", resType+"."+resName))
	}
	return issues
}

func hasOpenCIDR(body *hclsyntax.Body, ctx *hcl.EvalContext) bool {
	return listAttrContainsOpenCIDR(body, ctx, "cidr_blocks", "ipv6_cidr_blocks")
}

// listAttrContainsOpenCIDR checks whether any of the given list-typed
// attributes contains a wide-open CIDR ("0.0.0.0/0" or "::/0"). Shared by
// AWS security group rules and GCP firewall rules, which both express
// source ranges as a plain string list (Azure's NSG rules use a single
// string attribute instead -- see azureNSGRuleOpen).
func listAttrContainsOpenCIDR(body *hclsyntax.Body, ctx *hcl.EvalContext, attrNames ...string) bool {
	for _, attrName := range attrNames {
		attr, ok := body.Attributes[attrName]
		if !ok {
			continue
		}
		val, diags := attr.Expr.Value(ctx)
		if diags.HasErrors() || val.IsNull() || !val.CanIterateElements() {
			continue
		}
		for it := val.ElementIterator(); it.Next(); {
			_, v := it.Element()
			if v.Type() != cty.String {
				continue
			}
			if s := v.AsString(); s == "0.0.0.0/0" || s == "::/0" {
				return true
			}
		}
	}
	return false
}

// --- Storage / database ---

func checkStorageEncryption(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	switch resType {
	case "aws_db_instance":
		if enc, ok := attrBool(body, "storage_encrypted", ctx); !ok || !enc {
			return []model.Issue{newIssue("tf-unencrypted-storage", "HIGH", path, line,
				"Storage is not encrypted", resType+"."+resName+" storage_encrypted is not true")}
		}
	case "aws_ebs_volume":
		if enc, ok := attrBool(body, "encrypted", ctx); !ok || !enc {
			return []model.Issue{newIssue("tf-unencrypted-storage", "HIGH", path, line,
				"Storage is not encrypted", resType+"."+resName+" encrypted is not true")}
		}
	default:
		return nil
	}
	return nil
}

func checkEBSRootVolumeEncryption(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_instance" && resType != "aws_launch_template" {
		return nil
	}
	rbd := findBlockByType(body, "root_block_device")
	if rbd == nil {
		return nil // no explicit root_block_device -> can't tell, provider/AMI default varies
	}
	if enc, ok := attrBool(rbd.Body, "encrypted", ctx); !ok || !enc {
		return []model.Issue{newIssue("tf-ebs-root-volume-unencrypted", "MEDIUM", path, line,
			"Root block device is not encrypted", resType+"."+resName+" root_block_device.encrypted is not true")}
	}
	return nil
}

func checkRDSPerformanceInsightsAndIAMAuth(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_db_instance" {
		return nil
	}
	var issues []model.Issue
	if pi, ok := attrBool(body, "performance_insights_enabled", ctx); !ok || !pi {
		issues = append(issues, newIssue("tf-rds-performance-insights-disabled", "LOW", path, line,
			"RDS instance does not have Performance Insights enabled", resType+"."+resName))
	} else if _, ok := attrString(body, "performance_insights_kms_key_id", ctx); !ok {
		issues = append(issues, newIssue("tf-rds-performance-insights-not-cmk", "LOW", path, line,
			"RDS Performance Insights is not encrypted with a customer-managed key", resType+"."+resName))
	}
	if engine, ok := attrString(body, "engine", ctx); ok && (strings.HasPrefix(engine, "mysql") || strings.HasPrefix(engine, "postgres")) {
		if iamAuth, ok := attrBool(body, "iam_database_authentication_enabled", ctx); !ok || !iamAuth {
			issues = append(issues, newIssue("tf-rds-iam-auth-disabled", "MEDIUM", path, line,
				"RDS instance does not have IAM database authentication enabled", resType+"."+resName))
		}
	}
	return issues
}

func checkDynamoDBPITR(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_dynamodb_table" {
		return nil
	}
	pitr := findBlockByType(body, "point_in_time_recovery")
	if pitr != nil {
		if enabled, ok := attrBool(pitr.Body, "enabled", ctx); ok && enabled {
			return nil
		}
	}
	return []model.Issue{newIssue("tf-dynamodb-pitr-disabled", "MEDIUM", path, line,
		"DynamoDB table does not have point-in-time recovery enabled", resType+"."+resName)}
}

func checkElastiCacheEncryption(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_elasticache_replication_group" {
		return nil
	}
	var issues []model.Issue
	if v, ok := attrBool(body, "at_rest_encryption_enabled", ctx); !ok || !v {
		issues = append(issues, newIssue("tf-elasticache-not-encrypted-at-rest", "HIGH", path, line,
			"ElastiCache replication group is not encrypted at rest", resType+"."+resName))
	}
	if v, ok := attrBool(body, "transit_encryption_enabled", ctx); !ok || !v {
		issues = append(issues, newIssue("tf-elasticache-not-encrypted-in-transit", "HIGH", path, line,
			"ElastiCache replication group does not encrypt data in transit", resType+"."+resName))
	}
	return issues
}

func checkRedshift(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_redshift_cluster" {
		return nil
	}
	var issues []model.Issue
	if v, ok := attrBool(body, "encrypted", ctx); !ok || !v {
		issues = append(issues, newIssue("tf-redshift-unencrypted", "HIGH", path, line,
			"Redshift cluster is not encrypted", resType+"."+resName))
	}
	if v, ok := attrBool(body, "publicly_accessible", ctx); ok && v {
		issues = append(issues, newIssue("tf-redshift-publicly-accessible", "HIGH", path, line,
			"Redshift cluster is publicly accessible", resType+"."+resName))
	}
	return issues
}

func checkEFSEncryption(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_efs_file_system" {
		return nil
	}
	if v, ok := attrBool(body, "encrypted", ctx); !ok || !v {
		return []model.Issue{newIssue("tf-efs-unencrypted", "HIGH", path, line,
			"EFS file system is not encrypted", resType+"."+resName)}
	}
	return nil
}

func checkKinesisEncryption(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_kinesis_stream" {
		return nil
	}
	if t, ok := attrString(body, "encryption_type", ctx); !ok || t != "KMS" {
		return []model.Issue{newIssue("tf-kinesis-not-encrypted", "MEDIUM", path, line,
			"Kinesis stream is not encrypted with KMS", resType+"."+resName)}
	}
	return nil
}

// --- IAM ---

func checkIAMWildcardPolicy(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_iam_policy" && resType != "aws_iam_role_policy" && resType != "aws_iam_user_policy" {
		return nil
	}
	policy, ok := attrString(body, "policy", ctx)
	if !ok {
		return nil
	}
	var issues []model.Issue
	fullResource := strings.Contains(policy, `"Resource": "*"`) || strings.Contains(policy, `"Resource":"*"`)
	if strings.Contains(policy, `"Action": "*"`) && fullResource {
		issues = append(issues, newIssue("tf-iam-wildcard-policy", "CRITICAL", path, line,
			"IAM policy grants Action=* on Resource=*", resType+"."+resName))
	}
	if strings.Contains(policy, `"s3:*"`) && fullResource {
		issues = append(issues, newIssue("tf-iam-s3-wildcard-policy", "HIGH", path, line,
			"IAM policy grants unrestricted S3 access (s3:*) on all resources", resType+"."+resName))
	}
	if strings.Contains(policy, `"iam:PassRole"`) && fullResource && !strings.Contains(policy, `"Condition"`) {
		issues = append(issues, newIssue("tf-iam-passrole-unrestricted", "MEDIUM", path, line,
			"IAM policy grants iam:PassRole on all resources with no condition", resType+"."+resName))
	}
	return issues
}

func checkIAMUserPolicyAttachment(resType, resName, path string, line int, _ *hclsyntax.Body, _ *hcl.EvalContext) []model.Issue {
	if resType != "aws_iam_user_policy" && resType != "aws_iam_user_policy_attachment" {
		return nil
	}
	return []model.Issue{newIssue("tf-iam-policy-attached-to-user", "LOW", path, line,
		"IAM policy is attached directly to a user instead of a role or group", resType+"."+resName)}
}

func checkIAMPasswordPolicy(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_iam_account_password_policy" {
		return nil
	}
	var issues []model.Issue
	if n, ok := attrNumber(body, "minimum_password_length", ctx); !ok || n < 14 {
		issues = append(issues, newIssue("tf-iam-weak-password-policy", "MEDIUM", path, line,
			"IAM account password policy allows short passwords (minimum_password_length < 14)", resType+"."+resName))
	}
	for _, attrName := range []string{"require_lowercase_characters", "require_uppercase_characters", "require_numbers", "require_symbols"} {
		if v, ok := attrBool(body, attrName, ctx); !ok || !v {
			issues = append(issues, newIssue("tf-iam-weak-password-policy", "LOW", path, line,
				"IAM account password policy does not require "+attrName, resType+"."+resName))
		}
	}
	return issues
}

// --- Compute ---

func checkIMDSv2(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_instance" && resType != "aws_launch_template" {
		return nil
	}
	mo := findBlockByType(body, "metadata_options")
	if mo == nil {
		return []model.Issue{newIssue("tf-imdsv1-enabled", "HIGH", path, line,
			"Instance metadata service allows IMDSv1 (no metadata_options block)",
			resType+"."+resName+" has no metadata_options block; http_tokens defaults to \"optional\"")}
	}
	tokens, ok := attrString(mo.Body, "http_tokens", ctx)
	shown := tokens
	if !ok {
		shown = "<absent>"
	}
	if !ok || tokens != "required" {
		return []model.Issue{newIssue("tf-imdsv1-enabled", "HIGH", path, line,
			"Instance metadata service allows IMDSv1 (http_tokens != \"required\")",
			resType+"."+resName+" metadata_options.http_tokens = \""+shown+"\"")}
	}
	return nil
}

func checkLambdaXRay(resType, resName, path string, line int, body *hclsyntax.Body, _ *hcl.EvalContext) []model.Issue {
	if resType != "aws_lambda_function" {
		return nil
	}
	if findBlockByType(body, "tracing_config") == nil {
		return []model.Issue{newIssue("tf-lambda-no-xray-tracing", "LOW", path, line,
			"Lambda function does not have X-Ray tracing enabled", resType+"."+resName)}
	}
	return nil
}

func checkLambdaFunctionURLAuth(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_lambda_function_url" {
		return nil
	}
	if t, ok := attrString(body, "authorization_type", ctx); ok && t == "NONE" {
		return []model.Issue{newIssue("tf-lambda-function-url-no-auth", "HIGH", path, line,
			"Lambda function URL has no authorization", resType+"."+resName)}
	}
	return nil
}

func checkECSTaskDefinition(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_ecs_task_definition" {
		return nil
	}
	def, ok := attrString(body, "container_definitions", ctx)
	if !ok {
		return nil
	}
	var issues []model.Issue
	if strings.Contains(def, `"privileged": true`) || strings.Contains(def, `"privileged":true`) {
		issues = append(issues, newIssue("tf-ecs-privileged-container", "HIGH", path, line,
			"ECS task definition runs a privileged container", resType+"."+resName))
	}
	if !strings.Contains(def, `"readonlyRootFilesystem": true`) && !strings.Contains(def, `"readonlyRootFilesystem":true`) {
		issues = append(issues, newIssue("tf-ecs-no-readonly-root-fs", "LOW", path, line,
			"ECS task definition does not set a read-only root filesystem", resType+"."+resName))
	}
	return issues
}

// --- Load balancing ---

func checkALB(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_lb" && resType != "aws_alb" {
		return nil
	}
	var issues []model.Issue
	if lbType, _ := attrString(body, "load_balancer_type", ctx); lbType == "" || lbType == "application" {
		if drop, ok := attrBool(body, "drop_invalid_header_fields", ctx); !ok || !drop {
			issues = append(issues, newIssue("tf-alb-invalid-headers-allowed", "HIGH", path, line,
				"ALB does not drop invalid HTTP headers", resType+"."+resName+" drop_invalid_header_fields is not true"))
		}
	}
	if internal, ok := attrBool(body, "internal", ctx); !ok || !internal {
		issues = append(issues, newIssue("tf-lb-internet-facing", "HIGH", path, line,
			"Load balancer is internet-facing", resType+"."+resName+" internal is not true"))
	}
	return issues
}

func checkLBListenerPlainHTTP(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_lb_listener" && resType != "aws_alb_listener" {
		return nil
	}
	if proto, ok := attrString(body, "protocol", ctx); ok && proto == "HTTP" {
		return []model.Issue{newIssue("tf-lb-listener-plain-http", "CRITICAL", path, line,
			"Load balancer listener uses plain HTTP", resType+"."+resName+" protocol = \"HTTP\"")}
	}
	return nil
}

// --- API Gateway ---

func checkAPIGatewayLogging(resType, resName, path string, line int, body *hclsyntax.Body, _ *hcl.EvalContext) []model.Issue {
	if resType != "aws_api_gateway_stage" && resType != "aws_apigatewayv2_stage" {
		return nil
	}
	if findBlockByType(body, "access_log_settings") == nil {
		return []model.Issue{newIssue("tf-apigateway-no-access-logging", "MEDIUM", path, line,
			"API Gateway stage does not have access logging enabled", resType+"."+resName)}
	}
	return nil
}

func checkAPIGatewayMethodAuth(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_api_gateway_method" {
		return nil
	}
	if auth, ok := attrString(body, "authorization", ctx); ok && auth == "NONE" {
		return []model.Issue{newIssue("tf-apigateway-method-no-auth", "MEDIUM", path, line,
			"API Gateway method has no authorization", resType+"."+resName)}
	}
	return nil
}

// --- Other AWS services ---

func checkCloudWatchLogGroupEncryption(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_cloudwatch_log_group" {
		return nil
	}
	if _, ok := attrString(body, "kms_key_id", ctx); !ok {
		return []model.Issue{newIssue("tf-cloudwatch-log-group-unencrypted", "LOW", path, line,
			"CloudWatch log group is not encrypted with a customer-managed KMS key", resType+"."+resName)}
	}
	return nil
}

func checkECR(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_ecr_repository" {
		return nil
	}
	var issues []model.Issue
	if m, ok := attrString(body, "image_tag_mutability", ctx); !ok || m != "IMMUTABLE" {
		issues = append(issues, newIssue("tf-ecr-tag-mutable", "HIGH", path, line,
			"ECR repository allows mutable image tags", resType+"."+resName))
	}
	notCMK := true
	if enc := findBlockByType(body, "encryption_configuration"); enc != nil {
		if t, ok := attrString(enc.Body, "encryption_type", ctx); ok && t == "KMS" {
			notCMK = false
		}
	}
	if notCMK {
		issues = append(issues, newIssue("tf-ecr-not-cmk-encrypted", "LOW", path, line,
			"ECR repository is not encrypted with a customer-managed KMS key", resType+"."+resName))
	}
	return issues
}

func checkSNSEncryption(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_sns_topic" {
		return nil
	}
	if _, ok := attrString(body, "kms_master_key_id", ctx); !ok {
		return []model.Issue{newIssue("tf-sns-unencrypted", "HIGH", path, line,
			"SNS topic is not encrypted", resType+"."+resName)}
	}
	return nil
}

func checkSQSEncryption(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_sqs_queue" {
		return nil
	}
	if _, ok := attrString(body, "kms_master_key_id", ctx); !ok {
		return []model.Issue{newIssue("tf-sqs-not-cmk", "LOW", path, line,
			"SQS queue is not encrypted with a customer-managed key", resType+"."+resName)}
	}
	return nil
}

func checkSecretsManagerEncryption(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_secretsmanager_secret" {
		return nil
	}
	if _, ok := attrString(body, "kms_key_id", ctx); !ok {
		return []model.Issue{newIssue("tf-secretsmanager-not-cmk", "LOW", path, line,
			"Secrets Manager secret is not encrypted with a customer-managed key", resType+"."+resName)}
	}
	return nil
}

func checkKMSRotation(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_kms_key" {
		return nil
	}
	if r, ok := attrBool(body, "enable_key_rotation", ctx); !ok || !r {
		return []model.Issue{newIssue("tf-kms-rotation-disabled", "MEDIUM", path, line,
			"KMS key does not have automatic rotation enabled", resType+"."+resName)}
	}
	return nil
}

func checkCloudFrontWAFAndLogging(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_cloudfront_distribution" {
		return nil
	}
	var issues []model.Issue
	if _, ok := attrString(body, "web_acl_id", ctx); !ok {
		issues = append(issues, newIssue("tf-cloudfront-no-waf", "HIGH", path, line,
			"CloudFront distribution has no WAF association", resType+"."+resName))
	}
	if findBlockByType(body, "logging_config") == nil {
		issues = append(issues, newIssue("tf-cloudfront-no-logging", "MEDIUM", path, line,
			"CloudFront distribution does not have access logging configured", resType+"."+resName))
	}
	return issues
}

func checkCloudFrontTLS(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_cloudfront_distribution" {
		return nil
	}
	var issues []model.Issue
	if vc := findBlockByType(body, "viewer_certificate"); vc != nil {
		if v, ok := attrString(vc.Body, "minimum_protocol_version", ctx); !ok || !strings.HasPrefix(v, "TLSv1.2") {
			issues = append(issues, newIssue("tf-cloudfront-weak-tls", "MEDIUM", path, line,
				"CloudFront distribution does not enforce TLSv1.2+", resType+"."+resName))
		}
	}
	behaviors := []*hclsyntax.Block{}
	if b := findBlockByType(body, "default_cache_behavior"); b != nil {
		behaviors = append(behaviors, b)
	}
	for _, b := range body.Blocks {
		if b.Type == "ordered_cache_behavior" {
			behaviors = append(behaviors, b)
		}
	}
	for _, b := range behaviors {
		if p, ok := attrString(b.Body, "viewer_protocol_policy", ctx); ok && p == "allow-all" {
			issues = append(issues, newIssue("tf-cloudfront-plain-http", "HIGH", path, line,
				"CloudFront cache behavior allows plain HTTP (viewer_protocol_policy = \"allow-all\")", resType+"."+resName))
			break
		}
	}
	return issues
}

func checkEKSCluster(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_eks_cluster" {
		return nil
	}
	var issues []model.Issue
	vc := findBlockByType(body, "vpc_config")
	if vc == nil {
		issues = append(issues, newIssue("tf-eks-public-endpoint", "HIGH", path, line,
			"EKS cluster API server endpoint is publicly accessible (no vpc_config block)", resType+"."+resName))
	} else if pub, ok := attrBool(vc.Body, "endpoint_public_access", ctx); !ok || pub {
		issues = append(issues, newIssue("tf-eks-public-endpoint", "HIGH", path, line,
			"EKS cluster API server endpoint is publicly accessible", resType+"."+resName))
	}
	if _, ok := body.Attributes["enabled_cluster_log_types"]; !ok {
		issues = append(issues, newIssue("tf-eks-no-control-plane-logging", "LOW", path, line,
			"EKS cluster does not have control plane logging enabled", resType+"."+resName))
	}
	return issues
}

func checkCloudTrail(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_cloudtrail" {
		return nil
	}
	var issues []model.Issue
	if v, ok := attrBool(body, "enable_log_file_validation", ctx); !ok || !v {
		issues = append(issues, newIssue("tf-cloudtrail-no-log-validation", "MEDIUM", path, line,
			"CloudTrail trail does not have log file validation enabled", resType+"."+resName))
	}
	if v, ok := attrBool(body, "is_multi_region_trail", ctx); !ok || !v {
		issues = append(issues, newIssue("tf-cloudtrail-not-multi-region", "LOW", path, line,
			"CloudTrail trail is not multi-region", resType+"."+resName))
	}
	if _, ok := attrString(body, "kms_key_id", ctx); !ok {
		issues = append(issues, newIssue("tf-cloudtrail-not-cmk", "LOW", path, line,
			"CloudTrail trail is not encrypted with a customer-managed key", resType+"."+resName))
	}
	return issues
}

func checkGuardDuty(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "aws_guardduty_detector" {
		return nil
	}
	if v, ok := attrBool(body, "enable", ctx); ok && !v {
		return []model.Issue{newIssue("tf-guardduty-disabled", "HIGH", path, line,
			"GuardDuty detector is explicitly disabled", resType+"."+resName)}
	}
	return nil
}

// --- HCL helpers ---

func findBlockByType(body *hclsyntax.Body, t string) *hclsyntax.Block {
	for _, b := range body.Blocks {
		if b.Type == t {
			return b
		}
	}
	return nil
}

// attrRefName returns the resource-local name referenced by attrName when
// its expression is (or contains) a traversal rooted at wantType, e.g.
// `bucket = aws_s3_bucket.data.id` with wantType "aws_s3_bucket" -> "data".
func attrRefName(body *hclsyntax.Body, attrName, wantType string) (string, bool) {
	attr, ok := body.Attributes[attrName]
	if !ok {
		return "", false
	}
	for _, t := range attr.Expr.Variables() {
		if len(t) < 2 {
			continue
		}
		root, ok := t[0].(hcl.TraverseRoot)
		if !ok || root.Name != wantType {
			continue
		}
		if a, ok := t[1].(hcl.TraverseAttr); ok {
			return a.Name, true
		}
	}
	return "", false
}

func attrString(body *hclsyntax.Body, name string, ctx *hcl.EvalContext) (string, bool) {
	attr, ok := body.Attributes[name]
	if !ok {
		return "", false
	}
	val, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() || val.Type() != cty.String {
		return "", false
	}
	return val.AsString(), true
}

func attrBool(body *hclsyntax.Body, name string, ctx *hcl.EvalContext) (bool, bool) {
	attr, ok := body.Attributes[name]
	if !ok {
		return false, false
	}
	val, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() || val.Type() != cty.Bool {
		return false, false
	}
	return val.True(), true
}

func attrNumber(body *hclsyntax.Body, name string, ctx *hcl.EvalContext) (float64, bool) {
	attr, ok := body.Attributes[name]
	if !ok {
		return 0, false
	}
	val, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() || val.Type() != cty.Number {
		return 0, false
	}
	f, _ := val.AsBigFloat().Float64()
	return f, true
}
