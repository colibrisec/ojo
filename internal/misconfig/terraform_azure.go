package misconfig

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/colibrisec/ojo/internal/model"
)

// Azure (azurerm provider) checks. Same resourceCheck shape, same helpers
// (attrString/attrBool/findBlockByType) as the AWS checks in terraform.go.

var azureResourceChecks = []resourceCheck{
	checkAzureStorageAccount,
	checkAzureStorageContainerPublicAccess,
	checkAzureNSGRules,
	checkAzureKeyVault,
	checkAzureSQLServer,
	checkAzurePostgreSQL,
	checkAzureAKS,
	checkAzureAppService,
	checkAzureACR,
	checkAzureCosmosDB,
	checkAzureRedis,
}

func checkAzureStorageAccount(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "azurerm_storage_account" {
		return nil
	}
	var issues []model.Issue

	// Provider renamed enable_https_traffic_only -> https_traffic_only_enabled.
	httpsOnly, ok := attrBool(body, "https_traffic_only_enabled", ctx)
	if !ok {
		httpsOnly, ok = attrBool(body, "enable_https_traffic_only", ctx)
	}
	if !ok || !httpsOnly {
		issues = append(issues, newIssue("tf-azure-storage-insecure-transport", "HIGH", path, line,
			"Storage account allows plain HTTP traffic", resType+"."+resName))
	}

	if v, ok := attrString(body, "min_tls_version", ctx); !ok || v != "TLS1_2" {
		issues = append(issues, newIssue("tf-azure-storage-weak-tls", "MEDIUM", path, line,
			"Storage account allows TLS versions older than 1.2", resType+"."+resName))
	}

	// Provider renamed allow_blob_public_access -> allow_nested_items_to_be_public.
	pub, ok := attrBool(body, "allow_nested_items_to_be_public", ctx)
	if !ok {
		pub, ok = attrBool(body, "allow_blob_public_access", ctx)
	}
	if ok && pub {
		issues = append(issues, newIssue("tf-azure-storage-public-blob-access", "HIGH", path, line,
			"Storage account allows public access to blob containers", resType+"."+resName))
	}

	if nr := findBlockByType(body, "network_rules"); nr != nil {
		if def, ok := attrString(nr.Body, "default_action", ctx); ok && def == "Allow" {
			issues = append(issues, newIssue("tf-azure-storage-network-open", "MEDIUM", path, line,
				"Storage account network rules default to Allow, permitting access from any network", resType+"."+resName))
		}
	}

	return issues
}

func checkAzureStorageContainerPublicAccess(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "azurerm_storage_container" {
		return nil
	}
	if v, ok := attrString(body, "container_access_type", ctx); ok && v != "private" {
		return []model.Issue{newIssue("tf-azure-storage-container-public", "HIGH", path, line,
			"Storage container allows anonymous/public access", resType+"."+resName+" container_access_type = \""+v+"\"")}
	}
	return nil
}

func checkAzureNSGRules(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	var issues []model.Issue
	switch resType {
	case "azurerm_network_security_group":
		for _, b := range body.Blocks {
			if b.Type == "security_rule" {
				if issue, ok := azureNSGRuleOpen(b.Body, resType, resName, path, line, ctx); ok {
					issues = append(issues, issue)
				}
			}
		}
	case "azurerm_network_security_rule":
		if issue, ok := azureNSGRuleOpen(body, resType, resName, path, line, ctx); ok {
			issues = append(issues, issue)
		}
	}
	return issues
}

func azureNSGRuleOpen(body *hclsyntax.Body, resType, resName, path string, line int, ctx *hcl.EvalContext) (model.Issue, bool) {
	direction, _ := attrString(body, "direction", ctx)
	access, _ := attrString(body, "access", ctx)
	if direction != "Inbound" || access != "Allow" {
		return model.Issue{}, false
	}
	src, ok := attrString(body, "source_address_prefix", ctx)
	if !ok || (src != "*" && src != "0.0.0.0/0" && src != "Internet" && src != "Any") {
		return model.Issue{}, false
	}
	return newIssue("tf-azure-nsg-open-inbound", "CRITICAL", path, line,
		"Network security rule allows unrestricted inbound access", resType+"."+resName), true
}

func checkAzureKeyVault(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "azurerm_key_vault" {
		return nil
	}
	var issues []model.Issue
	if v, ok := attrBool(body, "purge_protection_enabled", ctx); !ok || !v {
		issues = append(issues, newIssue("tf-azure-keyvault-no-purge-protection", "MEDIUM", path, line,
			"Key Vault does not have purge protection enabled", resType+"."+resName))
	}
	if nr := findBlockByType(body, "network_acls"); nr != nil {
		if def, ok := attrString(nr.Body, "default_action", ctx); ok && def == "Allow" {
			issues = append(issues, newIssue("tf-azure-keyvault-network-open", "MEDIUM", path, line,
				"Key Vault network ACLs default to Allow, permitting access from any network", resType+"."+resName))
		}
	}
	return issues
}

func checkAzureSQLServer(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "azurerm_mssql_server" && resType != "azurerm_sql_server" {
		return nil
	}
	var issues []model.Issue
	if v, ok := attrBool(body, "public_network_access_enabled", ctx); !ok || v {
		issues = append(issues, newIssue("tf-azure-sql-public-access", "HIGH", path, line,
			"SQL server allows public network access", resType+"."+resName))
	}
	if v, ok := attrString(body, "minimum_tls_version", ctx); !ok || (v != "1.2" && v != "TLS1_2") {
		issues = append(issues, newIssue("tf-azure-sql-weak-tls", "MEDIUM", path, line,
			"SQL server allows TLS versions older than 1.2", resType+"."+resName))
	}
	return issues
}

func checkAzurePostgreSQL(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "azurerm_postgresql_server" && resType != "azurerm_mysql_server" {
		return nil
	}
	if v, ok := attrBool(body, "ssl_enforcement_enabled", ctx); !ok || !v {
		return []model.Issue{newIssue("tf-azure-db-ssl-disabled", "HIGH", path, line,
			"Database server does not enforce SSL", resType+"."+resName)}
	}
	return nil
}

func checkAzureAKS(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "azurerm_kubernetes_cluster" {
		return nil
	}
	var issues []model.Issue
	if v, ok := attrBool(body, "private_cluster_enabled", ctx); !ok || !v {
		issues = append(issues, newIssue("tf-azure-aks-public-api", "HIGH", path, line,
			"AKS cluster API server is publicly accessible", resType+"."+resName))
	}
	if findBlockByType(body, "network_profile") == nil {
		issues = append(issues, newIssue("tf-azure-aks-no-network-policy", "LOW", path, line,
			"AKS cluster has no network_profile (no network policy) configured", resType+"."+resName))
	}
	return issues
}

func checkAzureAppService(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	switch resType {
	case "azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app":
	default:
		return nil
	}
	var issues []model.Issue
	if v, ok := attrBool(body, "https_only", ctx); !ok || !v {
		issues = append(issues, newIssue("tf-azure-appservice-http-allowed", "HIGH", path, line,
			"App Service does not enforce HTTPS only", resType+"."+resName))
	}
	if sc := findBlockByType(body, "site_config"); sc != nil {
		if v, ok := attrString(sc.Body, "minimum_tls_version", ctx); ok && v != "1.2" {
			issues = append(issues, newIssue("tf-azure-appservice-weak-tls", "MEDIUM", path, line,
				"App Service allows TLS versions older than 1.2", resType+"."+resName))
		}
	}
	return issues
}

func checkAzureACR(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "azurerm_container_registry" {
		return nil
	}
	var issues []model.Issue
	if v, ok := attrBool(body, "public_network_access_enabled", ctx); !ok || v {
		issues = append(issues, newIssue("tf-azure-acr-public-access", "MEDIUM", path, line,
			"Container registry allows public network access", resType+"."+resName))
	}
	if v, ok := attrBool(body, "admin_enabled", ctx); ok && v {
		issues = append(issues, newIssue("tf-azure-acr-admin-enabled", "MEDIUM", path, line,
			"Container registry has admin (shared-key) access enabled", resType+"."+resName))
	}
	return issues
}

func checkAzureCosmosDB(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "azurerm_cosmosdb_account" {
		return nil
	}
	if v, ok := attrBool(body, "public_network_access_enabled", ctx); !ok || v {
		return []model.Issue{newIssue("tf-azure-cosmosdb-public-access", "MEDIUM", path, line,
			"Cosmos DB account allows public network access", resType+"."+resName)}
	}
	return nil
}

func checkAzureRedis(resType, resName, path string, line int, body *hclsyntax.Body, ctx *hcl.EvalContext) []model.Issue {
	if resType != "azurerm_redis_cache" {
		return nil
	}
	var issues []model.Issue
	if v, ok := attrBool(body, "enable_non_ssl_port", ctx); ok && v {
		issues = append(issues, newIssue("tf-azure-redis-non-ssl", "HIGH", path, line,
			"Redis cache allows non-SSL connections", resType+"."+resName))
	}
	if v, ok := attrString(body, "minimum_tls_version", ctx); ok && v != "1.2" {
		issues = append(issues, newIssue("tf-azure-redis-weak-tls", "MEDIUM", path, line,
			"Redis cache allows TLS versions older than 1.2", resType+"."+resName))
	}
	return issues
}
