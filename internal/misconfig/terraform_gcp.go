package misconfig

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/colibrisec/ojo/internal/model"
)

// GCP (google provider) checks. Same resourceCheck shape, same helpers
// (attrString/attrBool/findBlockByType) as the AWS checks in terraform.go.

var gcpResourceChecks = []resourceCheck{
	checkGCPStorageBucket,
	checkGCPPublicIAMBinding,
	checkGCPFirewall,
	checkGCPComputeInstance,
	checkGCPCloudSQL,
	checkGCPKMSRotation,
	checkGCPGKECluster,
	checkGCPPubSubEncryption,
}

func checkGCPStorageBucket(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "google_storage_bucket" {
		return nil
	}
	var issues []model.Issue
	if v, ok := attrBool(body, "uniform_bucket_level_access", ctx); !ok || !v {
		issues = append(issues, newIssue("tf-gcp-gcs-no-uniform-access", "MEDIUM", path, line,
			"GCS bucket does not enforce uniform bucket-level access", resType+"."+resName))
	}
	versioned := false
	if v := findBlockByType(body, "versioning"); v != nil {
		if enabled, ok := attrBool(v.Body, "enabled", ctx); ok && enabled {
			versioned = true
		}
	}
	if !versioned {
		issues = append(issues, newIssue("tf-gcp-gcs-no-versioning", "LOW", path, line,
			"GCS bucket does not have versioning enabled", resType+"."+resName))
	}
	return issues
}

// checkGCPPublicIAMBinding flags an IAM binding/member granting access to
// allUsers/allAuthenticatedUsers -- public access to a GCP project, bucket,
// or other resource, regardless of which role is granted.
func checkGCPPublicIAMBinding(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	switch resType {
	case "google_project_iam_binding", "google_storage_bucket_iam_binding", "google_project_iam_member", "google_storage_bucket_iam_member":
	default:
		return nil
	}
	members := []string{}
	if m, ok := attrString(body, "member", ctx); ok {
		members = append(members, m)
	}
	if attr, ok := body.Attributes["members"]; ok {
		if val, diags := attr.Expr.Value(ctx); !diags.HasErrors() && val.CanIterateElements() {
			for it := val.ElementIterator(); it.Next(); {
				_, v := it.Element()
				if v.Type().FriendlyName() == "string" {
					members = append(members, v.AsString())
				}
			}
		}
	}
	for _, m := range members {
		if m == "allUsers" || m == "allAuthenticatedUsers" {
			return []model.Issue{newIssue("tf-gcp-iam-public-member", "CRITICAL", path, line,
				"IAM binding grants access to "+m, resType+"."+resName)}
		}
	}
	return nil
}

func checkGCPFirewall(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "google_compute_firewall" {
		return nil
	}
	if findBlockByType(body, "allow") == nil {
		return nil // deny-only rule, or no rule body we can evaluate
	}
	if !listAttrContainsOpenCIDR(body, ctx, "source_ranges") {
		return nil
	}
	return []model.Issue{newIssue("tf-gcp-firewall-open-ingress", "CRITICAL", path, line,
		"Firewall rule allows unrestricted ingress from 0.0.0.0/0", resType+"."+resName)}
}

func checkGCPComputeInstance(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "google_compute_instance" && resType != "google_compute_instance_template" {
		return nil
	}
	var issues []model.Issue
	if findBlockByType(body, "shielded_instance_config") == nil {
		issues = append(issues, newIssue("tf-gcp-compute-no-shielded-vm", "LOW", path, line,
			"Compute instance does not have Shielded VM features enabled", resType+"."+resName))
	}
	for _, ni := range body.Blocks {
		if ni.Type != "network_interface" {
			continue
		}
		if findBlockByType(ni.Body, "access_config") != nil {
			issues = append(issues, newIssue("tf-gcp-compute-public-ip", "MEDIUM", path, line,
				"Compute instance has a public IP address", resType+"."+resName))
			break
		}
	}
	if sa := findBlockByType(body, "service_account"); sa != nil {
		if attr, ok := sa.Body.Attributes["scopes"]; ok {
			if val, diags := attr.Expr.Value(ctx); !diags.HasErrors() && val.CanIterateElements() {
				for it := val.ElementIterator(); it.Next(); {
					_, v := it.Element()
					if v.Type().FriendlyName() == "string" && strings.Contains(v.AsString(), "cloud-platform") {
						issues = append(issues, newIssue("tf-gcp-compute-broad-scope", "MEDIUM", path, line,
							"Compute instance service account has the overly broad cloud-platform scope", resType+"."+resName))
						break
					}
				}
			}
		}
	}
	return issues
}

func checkGCPCloudSQL(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "google_sql_database_instance" {
		return nil
	}
	settings := findBlockByType(body, "settings")
	if settings == nil {
		return nil
	}
	var issues []model.Issue
	if bc := findBlockByType(settings.Body, "backup_configuration"); bc == nil {
		issues = append(issues, newIssue("tf-gcp-cloudsql-no-backups", "MEDIUM", path, line,
			"Cloud SQL instance does not have backups enabled", resType+"."+resName))
	} else if enabled, ok := attrBool(bc.Body, "enabled", ctx); !ok || !enabled {
		issues = append(issues, newIssue("tf-gcp-cloudsql-no-backups", "MEDIUM", path, line,
			"Cloud SQL instance does not have backups enabled", resType+"."+resName))
	}
	if ipc := findBlockByType(settings.Body, "ip_configuration"); ipc != nil {
		if v, ok := attrBool(ipc.Body, "ipv4_enabled", ctx); !ok || v {
			issues = append(issues, newIssue("tf-gcp-cloudsql-public-ip", "HIGH", path, line,
				"Cloud SQL instance has a public IP address", resType+"."+resName))
		}
		if v, ok := attrBool(ipc.Body, "require_ssl", ctx); !ok || !v {
			issues = append(issues, newIssue("tf-gcp-cloudsql-ssl-not-required", "MEDIUM", path, line,
				"Cloud SQL instance does not require SSL connections", resType+"."+resName))
		}
	}
	return issues
}

func checkGCPKMSRotation(resType, resName, path string, line int, body *hclsyntax.Body, _ *hcl.EvalContext) []model.Issue {
	if resType != "google_kms_crypto_key" {
		return nil
	}
	if _, ok := body.Attributes["rotation_period"]; !ok {
		return []model.Issue{newIssue("tf-gcp-kms-no-rotation", "MEDIUM", path, line,
			"KMS key does not have automatic rotation configured", resType+"."+resName)}
	}
	return nil
}

func checkGCPGKECluster(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "google_container_cluster" {
		return nil
	}
	var issues []model.Issue
	if findBlockByType(body, "private_cluster_config") == nil {
		issues = append(issues, newIssue("tf-gcp-gke-not-private", "HIGH", path, line,
			"GKE cluster does not have private nodes/endpoint configured", resType+"."+resName))
	}
	if findBlockByType(body, "master_authorized_networks_config") == nil {
		issues = append(issues, newIssue("tf-gcp-gke-no-authorized-networks", "MEDIUM", path, line,
			"GKE cluster API server has no authorized network restriction", resType+"."+resName))
	}
	if np := findBlockByType(body, "network_policy"); np == nil {
		issues = append(issues, newIssue("tf-gcp-gke-no-network-policy", "LOW", path, line,
			"GKE cluster does not have network policy enabled", resType+"."+resName))
	} else if enabled, ok := attrBool(np.Body, "enabled", ctx); !ok || !enabled {
		issues = append(issues, newIssue("tf-gcp-gke-no-network-policy", "LOW", path, line,
			"GKE cluster does not have network policy enabled", resType+"."+resName))
	}
	if v, ok := attrBool(body, "enable_legacy_abac", ctx); ok && v {
		issues = append(issues, newIssue("tf-gcp-gke-legacy-abac", "MEDIUM", path, line,
			"GKE cluster has legacy ABAC authorization enabled", resType+"."+resName))
	}
	return issues
}

func checkGCPPubSubEncryption(resType, resName, path string, line int, body *hclsyntax.Body, _ *hcl.EvalContext) []model.Issue {
	if resType != "google_pubsub_topic" {
		return nil
	}
	if _, ok := body.Attributes["kms_key_name"]; !ok {
		return []model.Issue{newIssue("tf-gcp-pubsub-not-cmek", "LOW", path, line,
			"Pub/Sub topic is not encrypted with a customer-managed key", resType+"."+resName)}
	}
	return nil
}
