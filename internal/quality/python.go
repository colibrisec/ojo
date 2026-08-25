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

var pyLang = grammars.PythonLanguage()

// pySpec: Python's "and"/"or" have their own dedicated boolean_operator
// node type (distinct from comparison_operator and arithmetic
// binary_operator), so unlike the other four languages there's no
// operator-overloaded binaryTypes/logicalOps check needed at all.
var pySpec = tsLangSpec{
	funcTypes:   map[string]bool{"function_definition": true, "lambda": true},
	branchTypes: map[string]bool{"if_statement": true, "elif_clause": true, "for_statement": true, "while_statement": true, "except_clause": true, "conditional_expression": true, "boolean_operator": true},
	nestTypes:   map[string]bool{"if_statement": true, "for_statement": true, "while_statement": true, "try_statement": true},
}

func scanPython(root string) ([]model.Issue, error) {
	var issues []model.Issue
	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		if !strings.HasSuffix(path, ".py") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		tree, err := gts.NewParser(pyLang).Parse(src)
		if err != nil {
			return nil // ponytail: skip files that don't parse, don't fail the whole scan
		}
		for _, m := range tsMeasureFuncs(tree.RootNode(), pyLang, pySpec, src, path) {
			issues = append(issues, m.issues()...)
		}
		return nil
	})
	return issues, err
}
