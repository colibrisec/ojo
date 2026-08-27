package misconfig

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
)

// MCP server configs (Claude Desktop/Code, Cursor, and Windsurf's
// "mcpServers" convention; VS Code's "servers" convention) declare how an
// MCP server process gets launched or connected to. Same shape every time
// regardless of which tool wrote the file, so one parser covers them all.
// Description/AutoApprove/AlwaysAllow aren't part of every client's schema --
// zero value when absent is a correct "nothing to check" for each of them.
type mcpServer struct {
	Command     string            `json:"command"`
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env"`
	URL         string            `json:"url"`
	Description string            `json:"description"`
	AutoApprove []string          `json:"autoApprove"`
	AlwaysAllow []string          `json:"alwaysAllow"`
}

// looksLikeMCPConfig guards a generic .json file against false-triggering,
// the same role looksLikeCloudFormation plays for CFN templates. "mcpServers"
// is the dominant key name; VS Code's "servers" is common enough on its own
// (e.g. a plain HTTP server list) that it's only trusted when the file's own
// basename also says "mcp" -- deliberately not the full path, since an
// ancestor directory (a repo checkout, a temp dir) saying "mcp" for an
// unrelated reason shouldn't widen the match.
func looksLikeMCPConfig(raw map[string]json.RawMessage, path string) map[string]mcpServer {
	key := "mcpServers"
	if _, ok := raw[key]; !ok {
		key = "servers"
		if _, ok := raw[key]; !ok || !strings.Contains(strings.ToLower(filepath.Base(path)), "mcp") {
			return nil
		}
	}
	var servers map[string]mcpServer
	if json.Unmarshal(raw[key], &servers) != nil {
		return nil
	}
	return servers
}

func scanMCPConfig(path string) ([]model.Issue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil // ponytail: not valid JSON, skip rather than fail the scan
	}
	servers := looksLikeMCPConfig(raw, path)

	var issues []model.Issue
	for name, srv := range servers {
		issues = append(issues, mcpServerChecks(name, srv, path)...)
	}
	return issues, nil
}

func mcpServerChecks(name string, srv mcpServer, path string) []model.Issue {
	var issues []model.Issue
	if spec, ok := mcpUnpinnedLauncher(srv.Command, srv.Args); ok {
		issues = append(issues, newIssue("mcp-unpinned-launcher", "MEDIUM", path, 1,
			"MCP server launches an unpinned remote package",
			name+": "+srv.Command+" ... "+spec+" (no version pin -- a compromised/typosquatted release is fetched silently on every launch)"))
	}
	if mcpUsesShellWrapper(srv.Command) {
		issues = append(issues, newIssue("mcp-shell-wrapper", "MEDIUM", path, 1,
			"MCP server is launched through a shell wrapper instead of directly",
			name+": "+srv.Command+" "+strings.Join(srv.Args, " ")))
	}
	if srv.URL != "" && strings.HasPrefix(srv.URL, "http://") && !mcpIsLocalhost(srv.URL) {
		issues = append(issues, newIssue("mcp-plaintext-transport", "HIGH", path, 1,
			"MCP server URL uses plaintext HTTP instead of HTTPS",
			name+": "+srv.URL))
	}
	if srv.Description != "" && hasInjectionLanguage(srv.Description) {
		issues = append(issues, newIssue("mcp-prompt-injection-language", "MEDIUM", path, 1,
			"MCP server description contains known prompt-injection phrasing (possible tool poisoning)",
			name+": "+srv.Description))
	}
	if r, ok := findHiddenUnicode(srv.Description + " " + srv.Command + " " + strings.Join(srv.Args, " ") + " " + srv.URL); ok {
		issues = append(issues, newIssue("mcp-hidden-unicode", "HIGH", path, 1,
			"MCP server config contains a hidden/invisible Unicode character",
			name+": U+"+unicodeCodepoint(r)))
	}
	if mcpAutoApprovesAll(srv) {
		issues = append(issues, newIssue("mcp-auto-approve-wildcard", "MEDIUM", path, 1,
			"MCP server auto-approves every tool call with no user confirmation",
			name+": autoApprove/alwaysAllow includes \"*\""))
	}
	if srv.URL != "" {
		issues = append(issues, newIssue("mcp-remote-server-unpinned", "LOW", path, 1,
			"MCP server is a remote endpoint whose behavior this config can't pin",
			name+": "+srv.URL+" (a remote server can change what it does at any time without a local config change -- review periodically, the classic MCP \"rug pull\" risk)"))
	}
	if envName, ok := mcpCrossOriginCredential(srv); ok {
		issues = append(issues, newIssue("mcp-cross-origin-credential", "MEDIUM", path, 1,
			"MCP server holds a credential for a vendor its own launch source doesn't reference",
			name+": "+envName+" doesn't obviously match "+orDefault(srv.Command, srv.URL)))
	}
	return issues
}

// A wildcard in autoApprove/alwaysAllow means every tool call, present or
// added later, runs without the user ever seeing it.
func mcpAutoApprovesAll(srv mcpServer) bool {
	for _, t := range append(append([]string{}, srv.AutoApprove...), srv.AlwaysAllow...) {
		if strings.TrimSpace(t) == "*" {
			return true
		}
	}
	return false
}

// mcpVendorKeywords maps a short vendor keyword (matched against an env var
// name) to substrings expected somewhere in that vendor's own package name
// or hostname. A small, curated table of well-known providers -- not a
// general vendor-detection system, and a legitimate multi-service wrapper
// server will trip this; treat it as "worth a look," not "confirmed."
var mcpVendorKeywords = map[string][]string{
	"github":    {"github"},
	"gitlab":    {"gitlab"},
	"aws":       {"aws", "amazon"},
	"gcp":       {"google", "gcp"},
	"azure":     {"azure", "microsoft"},
	"slack":     {"slack"},
	"stripe":    {"stripe"},
	"openai":    {"openai"},
	"anthropic": {"anthropic", "claude"},
	"docker":    {"docker"},
}

func mcpCrossOriginCredential(srv mcpServer) (string, bool) {
	origin := strings.ToLower(srv.Command + " " + strings.Join(srv.Args, " ") + " " + srv.URL)
	for envName := range srv.Env {
		lower := strings.ToLower(envName)
		for vendor, hints := range mcpVendorKeywords {
			if !strings.Contains(lower, vendor) {
				continue
			}
			related := false
			for _, h := range hints {
				if strings.Contains(origin, h) {
					related = true
					break
				}
			}
			if !related {
				return envName, true
			}
		}
	}
	return "", false
}

// mcpRemoteLaunchers run-and-fetch a package by name on every invocation,
// unlike a locally installed binary -- the launcher itself is trusted, but
// what it fetches is only as trustworthy as the version pin on the package.
var mcpRemoteLaunchers = map[string]bool{
	"npx": true, "npx.cmd": true, "bunx": true, "uvx": true, "pipx": true,
}

func mcpUnpinnedLauncher(command string, args []string) (string, bool) {
	if !mcpRemoteLaunchers[strings.ToLower(filepath.Base(command))] {
		return "", false
	}
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue // flag, not the package spec
		}
		if mcpIsPinned(a) {
			return "", false
		}
		return a, true
	}
	return "", false
}

// mcpIsPinned reports whether a package spec carries an explicit version:
// pip/uvx style ("pkg==1.2.3") or npm style ("pkg@1.2.3" / "@scope/pkg@1.2.3"
// -- a scoped package's leading "@" doesn't count, only one appearing after
// it does).
func mcpIsPinned(spec string) bool {
	if strings.Contains(spec, "==") {
		return true
	}
	rest := strings.TrimPrefix(spec, "@")
	return strings.Contains(rest, "@")
}

var mcpShellCommands = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true,
	"cmd": true, "cmd.exe": true, "powershell": true, "powershell.exe": true, "pwsh": true,
}

// A shell wrapper's real command lives inside an opaque "-c"/"/c" string
// argument instead of being visible as command+args.
func mcpUsesShellWrapper(command string) bool {
	return mcpShellCommands[strings.ToLower(filepath.Base(command))]
}

func mcpIsLocalhost(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}
