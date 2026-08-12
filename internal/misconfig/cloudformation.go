package misconfig

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/colibrisec/ojo/internal/model"
)

// CloudFormation templates come in two shapes -- YAML with short-form
// intrinsic-function tags (!Ref, !GetAtt, !Sub, ...) or JSON with the
// equivalent long form ({"Ref": ...}, {"Fn::GetAtt": ...}, ...). Both are
// normalized into cfnNode so checks only need to be written once. Anything
// that isn't a literal (an intrinsic function call, in either shape) comes
// through as cfnNode{kind: cfnUnknown}, the same "can't tell" treatment the
// Terraform checks give an unresolvable expression.

type cfnKind int

const (
	cfnUnknown cfnKind = iota
	cfnString
	cfnBool
	cfnNumber
	cfnNull
	cfnList
	cfnMap
)

type cfnNode struct {
	kind cfnKind
	str  string
	b    bool
	num  float64
	line int
	list []cfnNode
	m    map[string]cfnNode
}

func (n cfnNode) get(key string) (cfnNode, bool) {
	if n.kind != cfnMap {
		return cfnNode{}, false
	}
	v, ok := n.m[key]
	return v, ok
}

func (n cfnNode) getString(key string) (string, bool) {
	v, ok := n.get(key)
	if !ok || v.kind != cfnString {
		return "", false
	}
	return v.str, true
}

func (n cfnNode) getBool(key string) (bool, bool) {
	v, ok := n.get(key)
	if !ok || v.kind != cfnBool {
		return false, false
	}
	return v.b, true
}

// containsString reports whether n -- a literal string, or a list
// containing one -- equals target. Used for CFN properties that accept
// either a single value or a list (IAM policy Action/Resource, etc.).
func (n cfnNode) containsString(target string) bool {
	switch n.kind {
	case cfnString:
		return n.str == target
	case cfnList:
		for _, item := range n.list {
			if item.kind == cfnString && item.str == target {
				return true
			}
		}
	}
	return false
}

var yamlKnownTags = map[string]bool{
	"": true, "!!str": true, "!!bool": true, "!!int": true, "!!float": true,
	"!!null": true, "!!map": true, "!!seq": true, "!!binary": true, "!!timestamp": true,
}

func cfnFromYAML(n *yaml.Node) cfnNode {
	if n == nil {
		return cfnNode{kind: cfnUnknown}
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return cfnNode{kind: cfnUnknown}
		}
		return cfnFromYAML(n.Content[0])
	}
	if n.Kind == yaml.AliasNode {
		return cfnFromYAML(n.Alias)
	}
	if !yamlKnownTags[n.Tag] {
		return cfnNode{kind: cfnUnknown, line: n.Line} // !Ref, !GetAtt, !Sub, !If, ...
	}
	switch n.Kind {
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!bool":
			return cfnNode{kind: cfnBool, b: n.Value == "true", line: n.Line}
		case "!!int", "!!float":
			f, _ := strconv.ParseFloat(n.Value, 64)
			return cfnNode{kind: cfnNumber, num: f, line: n.Line}
		case "!!null":
			return cfnNode{kind: cfnNull, line: n.Line}
		default:
			return cfnNode{kind: cfnString, str: n.Value, line: n.Line}
		}
	case yaml.SequenceNode:
		list := make([]cfnNode, 0, len(n.Content))
		for _, c := range n.Content {
			list = append(list, cfnFromYAML(c))
		}
		return cfnNode{kind: cfnList, list: list, line: n.Line}
	case yaml.MappingNode:
		m := make(map[string]cfnNode, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			m[n.Content[i].Value] = cfnFromYAML(n.Content[i+1])
		}
		return cfnNode{kind: cfnMap, m: m, line: n.Line}
	default:
		return cfnNode{kind: cfnUnknown, line: n.Line}
	}
}

func cfnFromJSON(v any) cfnNode {
	switch t := v.(type) {
	case string:
		return cfnNode{kind: cfnString, str: t}
	case bool:
		return cfnNode{kind: cfnBool, b: t}
	case float64:
		return cfnNode{kind: cfnNumber, num: t}
	case nil:
		return cfnNode{kind: cfnNull}
	case []any:
		list := make([]cfnNode, 0, len(t))
		for _, item := range t {
			list = append(list, cfnFromJSON(item))
		}
		return cfnNode{kind: cfnList, list: list}
	case map[string]any:
		// A single-key object like {"Ref": "X"} or {"Fn::GetAtt": [...]} is
		// CFN's JSON intrinsic-function form -- indistinguishable from a
		// literal nested object without knowing every intrinsic name, so
		// treat any Ref/Fn::*/Condition key the same as an unresolvable
		// YAML tag.
		if len(t) == 1 {
			for k := range t {
				if k == "Ref" || k == "Condition" || strings.HasPrefix(k, "Fn::") {
					return cfnNode{kind: cfnUnknown}
				}
			}
		}
		m := make(map[string]cfnNode, len(t))
		for k, val := range t {
			m[k] = cfnFromJSON(val)
		}
		return cfnNode{kind: cfnMap, m: m}
	default:
		return cfnNode{kind: cfnUnknown}
	}
}

// looksLikeCloudFormation guards against false-triggering on arbitrary
// YAML/JSON that happens to have a top-level "Resources" key.
func looksLikeCloudFormation(resources cfnNode) bool {
	for _, r := range resources.m {
		if t, ok := r.getString("Type"); ok {
			if strings.HasPrefix(t, "AWS::") || strings.HasPrefix(t, "Alexa::") || strings.HasPrefix(t, "Custom::") {
				return true
			}
		}
	}
	return false
}

func scanCloudFormation(path string) ([]model.Issue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var root cfnNode
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && trimmed[0] == '{' {
		var raw any
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, nil // ponytail: not valid JSON, skip rather than fail the scan
		}
		root = cfnFromJSON(raw)
	} else {
		var node yaml.Node
		if err := yaml.Unmarshal(data, &node); err != nil || len(node.Content) == 0 {
			return nil, nil
		}
		root = cfnFromYAML(&node)
	}

	resources, ok := root.get("Resources")
	if !ok || resources.kind != cfnMap || !looksLikeCloudFormation(resources) {
		return nil, nil
	}

	var issues []model.Issue
	for name, res := range resources.m {
		resType, ok := res.getString("Type")
		if !ok {
			continue
		}
		props, _ := res.get("Properties")
		line := res.line
		if line == 0 {
			line = 1
		}
		for _, check := range cloudformationChecks {
			issues = append(issues, check(resType, name, path, line, props)...)
		}
	}
	return issues, nil
}

type cfnCheck func(resType, resName, path string, line int, props cfnNode) []model.Issue

var cloudformationChecks = []cfnCheck{
	checkCFNS3Bucket,
	checkCFNSecurityGroup,
	checkCFNRDSInstance,
	checkCFNIAMPolicy,
	checkCFNIMDSv2,
	checkCFNLoadBalancerScheme,
	checkCFNKMSRotation,
	checkCFNCloudTrail,
	checkCFNDynamoDBPITR,
	checkCFNECR,
}

func checkCFNS3Bucket(resType, resName, path string, line int, props cfnNode) []model.Issue {
	if resType != "AWS::S3::Bucket" {
		return nil
	}
	var issues []model.Issue
	if ac, ok := props.getString("AccessControl"); ok {
		switch ac {
		case "PublicRead", "PublicReadWrite", "AuthenticatedRead":
			issues = append(issues, newIssue("cfn-s3-public-acl", "CRITICAL", path, line,
				"S3 bucket has a public ACL", resName+" AccessControl = "+ac))
		}
	}
	if _, ok := props.get("BucketEncryption"); !ok {
		issues = append(issues, newIssue("cfn-s3-unencrypted", "MEDIUM", path, line,
			"S3 bucket has no BucketEncryption configured", resName))
	}
	versioned := false
	if vc, ok := props.get("VersioningConfiguration"); ok {
		if status, ok := vc.getString("Status"); ok && status == "Enabled" {
			versioned = true
		}
	}
	if !versioned {
		issues = append(issues, newIssue("cfn-s3-versioning-disabled", "MEDIUM", path, line,
			"S3 bucket does not have versioning enabled", resName))
	}
	if pab, ok := props.get("PublicAccessBlockConfiguration"); !ok {
		issues = append(issues, newIssue("cfn-s3-missing-public-access-block", "HIGH", path, line,
			"S3 bucket has no PublicAccessBlockConfiguration", resName))
	} else {
		complete := true
		for _, key := range []string{"BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"} {
			if v, ok := pab.getBool(key); !ok || !v {
				complete = false
			}
		}
		if !complete {
			issues = append(issues, newIssue("cfn-s3-public-access-block-incomplete", "HIGH", path, line,
				"S3 bucket's PublicAccessBlockConfiguration does not block all public access", resName))
		}
	}
	return issues
}

func checkCFNSecurityGroup(resType, resName, path string, line int, props cfnNode) []model.Issue {
	var issues []model.Issue
	switch resType {
	case "AWS::EC2::SecurityGroup":
		if ing, ok := props.get("SecurityGroupIngress"); ok {
			issues = append(issues, cfnSGRuleIssues(ing, "ingress", resName, path, line)...)
		}
		if eg, ok := props.get("SecurityGroupEgress"); ok {
			issues = append(issues, cfnSGRuleIssues(eg, "egress", resName, path, line)...)
		}
	case "AWS::EC2::SecurityGroupIngress":
		issues = append(issues, cfnSGRuleIssues(cfnNode{kind: cfnList, list: []cfnNode{props}}, "ingress", resName, path, line)...)
	case "AWS::EC2::SecurityGroupEgress":
		issues = append(issues, cfnSGRuleIssues(cfnNode{kind: cfnList, list: []cfnNode{props}}, "egress", resName, path, line)...)
	}
	return issues
}

func cfnSGRuleIssues(rules cfnNode, kind, resName, path string, line int) []model.Issue {
	if rules.kind != cfnList {
		return nil
	}
	ruleID := "cfn-security-group-open-ingress"
	title := "Security group allows ingress from 0.0.0.0/0"
	if kind == "egress" {
		ruleID = "cfn-security-group-open-egress"
		title = "Security group allows unrestricted egress to 0.0.0.0/0"
	}
	for _, rule := range rules.list {
		if cidr, ok := rule.getString("CidrIp"); ok && cidr == "0.0.0.0/0" {
			return []model.Issue{newIssue(ruleID, "CRITICAL", path, line, title, resName)}
		}
		if cidr, ok := rule.getString("CidrIpv6"); ok && cidr == "::/0" {
			return []model.Issue{newIssue(ruleID, "CRITICAL", path, line, title, resName)}
		}
	}
	return nil
}

func checkCFNRDSInstance(resType, resName, path string, line int, props cfnNode) []model.Issue {
	if resType != "AWS::RDS::DBInstance" {
		return nil
	}
	var issues []model.Issue
	if v, ok := props.getBool("StorageEncrypted"); !ok || !v {
		issues = append(issues, newIssue("cfn-rds-unencrypted", "HIGH", path, line,
			"RDS instance is not encrypted", resName))
	}
	if v, ok := props.getBool("PubliclyAccessible"); ok && v {
		issues = append(issues, newIssue("cfn-rds-publicly-accessible", "HIGH", path, line,
			"RDS instance is publicly accessible", resName))
	}
	return issues
}

func checkCFNIAMPolicy(resType, resName, path string, line int, props cfnNode) []model.Issue {
	if resType != "AWS::IAM::Policy" && resType != "AWS::IAM::ManagedPolicy" {
		return nil
	}
	doc, ok := props.get("PolicyDocument")
	if !ok {
		return nil
	}
	stmts, ok := doc.get("Statement")
	if !ok {
		return nil
	}
	if stmts.kind == cfnMap {
		stmts = cfnNode{kind: cfnList, list: []cfnNode{stmts}}
	}
	if stmts.kind != cfnList {
		return nil
	}
	for _, s := range stmts.list {
		effect, _ := s.getString("Effect")
		action, hasAction := s.get("Action")
		resource, hasResource := s.get("Resource")
		if effect == "Allow" && hasAction && hasResource && action.containsString("*") && resource.containsString("*") {
			return []model.Issue{newIssue("cfn-iam-wildcard-policy", "CRITICAL", path, line,
				"IAM policy grants Action=* on Resource=*", resName)}
		}
	}
	return nil
}

func checkCFNIMDSv2(resType, resName, path string, line int, props cfnNode) []model.Issue {
	var mo cfnNode
	var ok bool
	switch resType {
	case "AWS::EC2::Instance":
		mo, ok = props.get("MetadataOptions")
	case "AWS::EC2::LaunchTemplate":
		if data, dataOk := props.get("LaunchTemplateData"); dataOk {
			mo, ok = data.get("MetadataOptions")
		}
	default:
		return nil
	}
	if !ok {
		return []model.Issue{newIssue("cfn-imdsv1-enabled", "HIGH", path, line,
			"Instance metadata service allows IMDSv1 (no MetadataOptions)", resName)}
	}
	if tokens, ok := mo.getString("HttpTokens"); !ok || tokens != "required" {
		return []model.Issue{newIssue("cfn-imdsv1-enabled", "HIGH", path, line,
			"Instance metadata service allows IMDSv1 (HttpTokens != \"required\")", resName)}
	}
	return nil
}

func checkCFNLoadBalancerScheme(resType, resName, path string, line int, props cfnNode) []model.Issue {
	if resType != "AWS::ElasticLoadBalancingV2::LoadBalancer" {
		return nil
	}
	if scheme, ok := props.getString("Scheme"); !ok || scheme != "internal" {
		return []model.Issue{newIssue("cfn-lb-internet-facing", "HIGH", path, line,
			"Load balancer is internet-facing", resName)}
	}
	return nil
}

func checkCFNKMSRotation(resType, resName, path string, line int, props cfnNode) []model.Issue {
	if resType != "AWS::KMS::Key" {
		return nil
	}
	if v, ok := props.getBool("EnableKeyRotation"); !ok || !v {
		return []model.Issue{newIssue("cfn-kms-rotation-disabled", "MEDIUM", path, line,
			"KMS key does not have automatic rotation enabled", resName)}
	}
	return nil
}

func checkCFNCloudTrail(resType, resName, path string, line int, props cfnNode) []model.Issue {
	if resType != "AWS::CloudTrail::Trail" {
		return nil
	}
	var issues []model.Issue
	if v, ok := props.getBool("EnableLogFileValidation"); !ok || !v {
		issues = append(issues, newIssue("cfn-cloudtrail-no-log-validation", "MEDIUM", path, line,
			"CloudTrail trail does not have log file validation enabled", resName))
	}
	if v, ok := props.getBool("IsMultiRegionTrail"); !ok || !v {
		issues = append(issues, newIssue("cfn-cloudtrail-not-multi-region", "LOW", path, line,
			"CloudTrail trail is not multi-region", resName))
	}
	return issues
}

func checkCFNDynamoDBPITR(resType, resName, path string, line int, props cfnNode) []model.Issue {
	if resType != "AWS::DynamoDB::Table" {
		return nil
	}
	if spec, ok := props.get("PointInTimeRecoverySpecification"); ok {
		if v, ok := spec.getBool("PointInTimeRecoveryEnabled"); ok && v {
			return nil
		}
	}
	return []model.Issue{newIssue("cfn-dynamodb-pitr-disabled", "MEDIUM", path, line,
		"DynamoDB table does not have point-in-time recovery enabled", resName)}
}

func checkCFNECR(resType, resName, path string, line int, props cfnNode) []model.Issue {
	if resType != "AWS::ECR::Repository" {
		return nil
	}
	if v, ok := props.getString("ImageTagMutability"); !ok || v != "IMMUTABLE" {
		return []model.Issue{newIssue("cfn-ecr-tag-mutable", "HIGH", path, line,
			"ECR repository allows mutable image tags", resName)}
	}
	return nil
}
