package cli

import "testing"

func TestRoot_HasBothSubcommands(t *testing.T) {
	root := Root()
	names := map[string]bool{}
	for _, c := range root.Commands() {
		names[c.Name()] = true
	}
	if !names["fs"] || !names["image"] {
		t.Errorf("expected fs and image subcommands, got %v", names)
	}
}
