package quality

import (
	"io/fs"
	"os"
	"strings"

	gts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"

	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/walk"
)

var javaLang = grammars.JavaLanguage()

// javaSpec: Java's grammar wraps both "case X:" and "default:" in the same
// switch_label node type (unlike JS's distinct switch_case/switch_default)
// — caseLabelType handles that with a text-prefix check instead of a plain
// type-name match, verified directly against a real parse tree first.
var javaSpec = tsLangSpec{
	funcTypes:     map[string]bool{"method_declaration": true, "constructor_declaration": true, "lambda_expression": true},
	branchTypes:   map[string]bool{"if_statement": true, "for_statement": true, "while_statement": true, "catch_clause": true, "ternary_expression": true},
	nestTypes:     map[string]bool{"if_statement": true, "for_statement": true, "while_statement": true, "switch_expression": true, "try_statement": true},
	binaryTypes:   map[string]bool{"binary_expression": true},
	logicalOps:    map[string]bool{"&&": true, "||": true},
	caseLabelType: "switch_label",
}

func scanJava(root string) ([]model.Issue, error) {
	var issues []model.Issue
	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		if !strings.HasSuffix(path, ".java") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		tree, err := gts.NewParser(javaLang).Parse(src)
		if err != nil {
			return nil // ponytail: skip files that don't parse, don't fail the whole scan
		}
		for _, m := range tsMeasureFuncs(tree.RootNode(), javaLang, javaSpec, src, path) {
			issues = append(issues, m.issues()...)
		}
		return nil
	})
	return issues, err
}
