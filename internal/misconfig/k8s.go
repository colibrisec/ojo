package misconfig

import (
	"bytes"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/colibrisec/ojo/internal/model"
)

func scanK8sManifest(path string) ([]model.Issue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var issues []model.Issue
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			break // EOF or a non-YAML/malformed doc; stop rather than fail the whole scan
		}
		if doc["apiVersion"] == nil || doc["kind"] == nil {
			continue
		}
		issues = append(issues, k8sChecks(doc, path)...)
	}
	return issues, nil
}

func k8sChecks(doc map[string]any, path string) []model.Issue {
	var issues []model.Issue

	for _, hostField := range []struct{ key, rule string }{
		{"hostNetwork", "k8s-host-network"},
		{"hostPID", "k8s-host-pid"},
		{"hostIPC", "k8s-host-ipc"},
	} {
		if b, ok := findBool(doc, hostField.key); ok && b {
			issues = append(issues, newIssue(hostField.rule, "HIGH", path, 1,
				hostField.key+" is enabled", hostField.key+": true grants the pod access to the host namespace"))
		}
	}

	for _, pc := range findContainers(doc) {
		c := pc.container
		name, _ := c["name"].(string)
		sc, _ := c["securityContext"].(map[string]any)
		podSC, _ := pc.pod["securityContext"].(map[string]any)
		nonRoot := runsAsNonRoot(sc, podSC)

		if sc != nil {
			if v, ok := sc["privileged"].(bool); ok && v {
				issues = append(issues, newIssue("k8s-privileged-container", "CRITICAL", path, 1,
					"Container runs privileged", "container "+name+" has securityContext.privileged: true"))
			}
			if v, ok := sc["allowPrivilegeEscalation"].(bool); !ok || v {
				issues = append(issues, newIssue("k8s-allow-privilege-escalation", "MEDIUM", path, 1,
					"allowPrivilegeEscalation not explicitly disabled", "container "+name))
			}
			if !nonRoot {
				issues = append(issues, newIssue("k8s-run-as-root", "MEDIUM", path, 1,
					"runAsNonRoot not explicitly set to true", "container "+name))
			}
		} else if !nonRoot {
			issues = append(issues, newIssue("k8s-run-as-root", "MEDIUM", path, 1,
				"No securityContext set (runs as root by default)", "container "+name))
		}

		resources, _ := c["resources"].(map[string]any)
		if resources == nil || resources["limits"] == nil {
			issues = append(issues, newIssue("k8s-missing-resource-limits", "LOW", path, 1,
				"Container has no resource limits", "container "+name+" can consume unbounded CPU/memory"))
		}
	}
	return issues
}

func findBool(v any, key string) (bool, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return false, false
	}
	if raw, ok := m[key]; ok {
		if b, ok := raw.(bool); ok {
			return b, true
		}
	}
	for _, val := range m {
		if b, ok := findBool(val, key); ok {
			return b, true
		}
	}
	return false, false
}

type podContainer struct {
	container map[string]any
	pod       map[string]any // the spec holding the containers list
}

// runsAsNonRoot applies Kubernetes' precedence: a container-level
// runAsNonRoot/runAsUser overrides the pod-level one. A non-zero runAsUser
// also means the process isn't root.
func runsAsNonRoot(container, pod map[string]any) bool {
	effective := func(key string) (any, bool) {
		if v, ok := container[key]; ok {
			return v, true
		}
		v, ok := pod[key]
		return v, ok
	}
	if v, ok := effective("runAsNonRoot"); ok {
		if b, _ := v.(bool); b {
			return true
		}
	}
	if v, ok := effective("runAsUser"); ok {
		if uid, ok := v.(int); ok && uid > 0 {
			return true
		}
	}
	return false
}

// findContainers collects every element of any "containers"/"initContainers" list anywhere in doc,
// paired with the map that holds that list (the pod spec).
func findContainers(v any) []podContainer {
	var out []podContainer
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if k == "containers" || k == "initContainers" {
				if list, ok := val.([]any); ok {
					for _, item := range list {
						if c, ok := item.(map[string]any); ok {
							out = append(out, podContainer{container: c, pod: t})
						}
					}
					continue
				}
			}
			out = append(out, findContainers(val)...)
		}
	case []any:
		for _, item := range t {
			out = append(out, findContainers(item)...)
		}
	}
	return out
}
