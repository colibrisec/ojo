package misconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScan(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Dockerfile", "FROM ubuntu\nENV DB_PASSWORD=hunter2\nADD ./app.tar.gz /app\n")
	write(t, dir, "pod.yaml", "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n    - name: web\n      securityContext:\n        privileged: true\n")
	write(t, dir, "main.tf", `resource "aws_s3_bucket" "data" {
  acl = "public-read"
}
`)

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"dockerfile-root-user":     false,
		"dockerfile-latest-tag":    false,
		"dockerfile-secret-env":    false,
		"k8s-host-network":         false,
		"k8s-privileged-container": false,
		"tf-s3-public-acl":         false,
	}
	for _, i := range issues {
		if _, ok := want[i.RuleID]; ok {
			want[i.RuleID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected rule %s to fire, got issues: %+v", id, issues)
		}
	}
}

func TestTerraformChecksExpanded(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "main.tf", `
resource "aws_security_group" "web" {
  egress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "app" {
  ami = "ami-123"
}

resource "aws_s3_bucket" "data" {
  bucket = "My_Bad_Bucket_Name"
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Suspended"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket              = aws_s3_bucket.data.id
  block_public_acls   = true
  block_public_policy = false
}

resource "aws_ecr_repository" "app" {
  name = "app"
}

resource "aws_lb" "app" {
  load_balancer_type = "application"
}

resource "aws_iam_user_policy" "admin" {
  user   = "bob"
  policy = "{}"
}

resource "aws_kms_key" "app" {
}
`)

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"tf-security-group-open-egress":         false,
		"tf-security-group-rule-no-description": false,
		"tf-imdsv1-enabled":                     false,
		"tf-s3-bucket-name-not-dns-compliant":   false,
		"tf-s3-versioning-disabled":             false,
		"tf-s3-logging-disabled":                false,
		"tf-s3-unencrypted":                     false,
		"tf-s3-public-access-block-incomplete":  false,
		"tf-ecr-tag-mutable":                    false,
		"tf-ecr-not-cmk-encrypted":              false,
		"tf-lb-internet-facing":                 false,
		"tf-alb-invalid-headers-allowed":        false,
		"tf-iam-policy-attached-to-user":        false,
		"tf-kms-rotation-disabled":              false,
	}
	for _, i := range issues {
		if _, ok := want[i.RuleID]; ok {
			want[i.RuleID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected rule %s to fire, got issues: %+v", id, issues)
		}
	}
}

func TestTerraformCrossFileAndVariableResolution(t *testing.T) {
	dir := t.TempDir()
	// Bucket in one file, its protections split across two others -- proves
	// same-directory correlation, not just same-file.
	write(t, dir, "bucket.tf", `
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}
`)
	write(t, dir, "bucket_versioning.tf", `
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}
`)
	write(t, dir, "bucket_protections.tf", `
resource "aws_s3_bucket_logging" "data" {
  bucket = aws_s3_bucket.data.id
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`)
	// A var/local-driven security group rule -- should resolve to the real
	// (secure) value instead of being flagged as "can't tell".
	write(t, dir, "sg.tf", `
variable "open_cidr" {
  default = ["10.0.0.0/8"]
}

locals {
  ingress_cidrs = var.open_cidr
}

resource "aws_security_group" "web" {
  ingress {
    description = "internal only"
    cidr_blocks = local.ingress_cidrs
  }
}
`)

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	dontWant := map[string]bool{
		"tf-s3-versioning-disabled":             true,
		"tf-s3-logging-disabled":                true,
		"tf-s3-unencrypted":                     true,
		"tf-s3-missing-public-access-block":     true,
		"tf-s3-public-access-block-incomplete":  true,
		"tf-security-group-open-ingress":        true,
		"tf-security-group-rule-no-description": true,
	}
	for _, i := range issues {
		if dontWant[i.RuleID] {
			t.Errorf("rule %s should not have fired (cross-file correlation / variable resolution should have resolved it), got issues: %+v", i.RuleID, issues)
		}
	}
}

func TestTerraformChecksRound2(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "main.tf", `
resource "aws_vpc" "main" {
}

resource "aws_eks_cluster" "app" {
  name = "app"
}

resource "aws_cloudtrail" "app" {
  name = "app"
}

resource "aws_redshift_cluster" "app" {
  publicly_accessible = true
}

resource "aws_efs_file_system" "app" {
}

resource "aws_dynamodb_table" "app" {
}

resource "aws_ecs_task_definition" "app" {
  container_definitions = "[{\"privileged\": true}]"
}

resource "aws_lambda_function_url" "app" {
  authorization_type = "NONE"
}

resource "aws_iam_account_password_policy" "default" {
  minimum_password_length = 8
}
`)

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"tf-vpc-no-flow-log":              false,
		"tf-eks-public-endpoint":          false,
		"tf-eks-no-control-plane-logging": false,
		"tf-cloudtrail-no-log-validation": false,
		"tf-redshift-unencrypted":         false,
		"tf-redshift-publicly-accessible": false,
		"tf-efs-unencrypted":              false,
		"tf-dynamodb-pitr-disabled":       false,
		"tf-ecs-privileged-container":     false,
		"tf-lambda-function-url-no-auth":  false,
		"tf-iam-weak-password-policy":     false,
	}
	for _, i := range issues {
		if _, ok := want[i.RuleID]; ok {
			want[i.RuleID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected rule %s to fire, got issues: %+v", id, issues)
		}
	}
}

func TestTerraformChecksAzure(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "main.tf", `
resource "azurerm_storage_account" "app" {
  enable_https_traffic_only = false
  min_tls_version            = "TLS1_0"
}

resource "azurerm_storage_container" "app" {
  container_access_type = "blob"
}

resource "azurerm_network_security_rule" "ssh" {
  direction              = "Inbound"
  access                 = "Allow"
  source_address_prefix  = "*"
}

resource "azurerm_key_vault" "app" {
}

resource "azurerm_mssql_server" "app" {
}

resource "azurerm_kubernetes_cluster" "app" {
}

resource "azurerm_linux_web_app" "app" {
}

resource "azurerm_redis_cache" "app" {
  enable_non_ssl_port = true
}
`)

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"tf-azure-storage-insecure-transport":   false,
		"tf-azure-storage-weak-tls":             false,
		"tf-azure-storage-container-public":     false,
		"tf-azure-nsg-open-inbound":             false,
		"tf-azure-keyvault-no-purge-protection": false,
		"tf-azure-sql-public-access":            false,
		"tf-azure-aks-public-api":               false,
		"tf-azure-appservice-http-allowed":      false,
		"tf-azure-redis-non-ssl":                false,
	}
	for _, i := range issues {
		if _, ok := want[i.RuleID]; ok {
			want[i.RuleID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected rule %s to fire, got issues: %+v", id, issues)
		}
	}
}

func TestTerraformChecksGCP(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "main.tf", `
resource "google_storage_bucket" "app" {
}

resource "google_storage_bucket_iam_member" "public" {
  member = "allUsers"
  role   = "roles/storage.objectViewer"
}

resource "google_compute_firewall" "open" {
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
  }
}

resource "google_compute_instance" "app" {
  network_interface {
    access_config {
    }
  }
}

resource "google_sql_database_instance" "app" {
  settings {
    ip_configuration {
      ipv4_enabled = true
    }
  }
}

resource "google_kms_crypto_key" "app" {
}

resource "google_container_cluster" "app" {
}

resource "google_pubsub_topic" "app" {
}
`)

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"tf-gcp-gcs-no-uniform-access":      false,
		"tf-gcp-gcs-no-versioning":          false,
		"tf-gcp-iam-public-member":          false,
		"tf-gcp-firewall-open-ingress":      false,
		"tf-gcp-compute-no-shielded-vm":     false,
		"tf-gcp-compute-public-ip":          false,
		"tf-gcp-cloudsql-no-backups":        false,
		"tf-gcp-cloudsql-public-ip":         false,
		"tf-gcp-cloudsql-ssl-not-required":  false,
		"tf-gcp-kms-no-rotation":            false,
		"tf-gcp-gke-not-private":            false,
		"tf-gcp-gke-no-authorized-networks": false,
		"tf-gcp-gke-no-network-policy":      false,
		"tf-gcp-pubsub-not-cmek":            false,
	}
	for _, i := range issues {
		if _, ok := want[i.RuleID]; ok {
			want[i.RuleID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected rule %s to fire, got issues: %+v", id, issues)
		}
	}
}

func TestCloudFormationYAML(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "template.yaml", `
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
      BucketName: !Sub 'my-${AWS::StackName}-bucket'
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - CidrIp: 0.0.0.0/0
          FromPort: !Ref SshPort
          ToPort: 22
          IpProtocol: tcp
  DB:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: false
      PubliclyAccessible: true
  Repo:
    Type: AWS::ECR::Repository
    Properties:
      ImageTagMutability: MUTABLE
`)

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"cfn-s3-public-acl":                  false,
		"cfn-s3-unencrypted":                 false,
		"cfn-s3-versioning-disabled":         false,
		"cfn-s3-missing-public-access-block": false,
		"cfn-security-group-open-ingress":    false,
		"cfn-rds-unencrypted":                false,
		"cfn-rds-publicly-accessible":        false,
		"cfn-ecr-tag-mutable":                false,
	}
	for _, i := range issues {
		if _, ok := want[i.RuleID]; ok {
			want[i.RuleID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected rule %s to fire, got issues: %+v", id, issues)
		}
	}
}

func TestCloudFormationJSON(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "template.json", `{
  "Resources": {
    "Key": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "EnableKeyRotation": false
      }
    },
    "Policy": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "PolicyDocument": {
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "*",
              "Resource": "*"
            }
          ]
        }
      }
    },
    "Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "ImageId": { "Ref": "SomeAmi" }
      }
    }
  }
}`)

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"cfn-kms-rotation-disabled": false,
		"cfn-iam-wildcard-policy":   false,
		"cfn-imdsv1-enabled":        false,
	}
	for _, i := range issues {
		if _, ok := want[i.RuleID]; ok {
			want[i.RuleID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected rule %s to fire, got issues: %+v", id, issues)
		}
	}
}

func TestCloudFormationIgnoresNonCFNFiles(t *testing.T) {
	dir := t.TempDir()
	// Has a top-level "Resources" key, but no resource Type looks like
	// AWS::/Alexa::/Custom:: -- must not be mistaken for CloudFormation.
	write(t, dir, "config.yaml", `
Resources:
  limits:
    cpu: 2
    memory: 4Gi
`)
	write(t, dir, "package.json", `{"name": "not-cloudformation", "version": "1.0.0"}`)

	issues, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range issues {
		if strings.HasPrefix(i.RuleID, "cfn-") {
			t.Errorf("non-CloudFormation file should not have produced a cfn- issue, got: %+v", i)
		}
	}
}

func TestDockerfileHealthcheckPerStage(t *testing.T) {
	// Multi-stage build: HEALTHCHECK in an earlier stage must not suppress
	// dockerfile-no-healthcheck for the final stage, and HEALTHCHECK NONE
	// explicitly disables it rather than counting as "has one".
	instrs := parseDockerfile([]byte(
		"FROM builder AS build\n" +
			"HEALTHCHECK CMD curl -f http://localhost/ || exit 1\n" +
			"USER appuser\n" +
			"FROM scratch\n" +
			"COPY --from=build /app /app\n" +
			"HEALTHCHECK NONE\n",
	))
	issues := dockerfileChecks(instrs, "Dockerfile")

	foundNoHealthcheck := false
	for _, i := range issues {
		if i.RuleID == "dockerfile-no-healthcheck" {
			foundNoHealthcheck = true
		}
	}
	if !foundNoHealthcheck {
		t.Errorf("expected dockerfile-no-healthcheck to fire (final stage has HEALTHCHECK NONE, earlier stage's HEALTHCHECK shouldn't count), got: %+v", issues)
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
