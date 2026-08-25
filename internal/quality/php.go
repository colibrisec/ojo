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

var phpLang = grammars.PhpLanguage()

var phpSpec = tsLangSpec{
	funcTypes:   map[string]bool{"function_definition": true, "method_declaration": true, "anonymous_function": true, "arrow_function": true},
	branchTypes: map[string]bool{"if_statement": true, "else_if_clause": true, "for_statement": true, "while_statement": true, "case_statement": true, "catch_clause": true, "conditional_expression": true},
	nestTypes:   map[string]bool{"if_statement": true, "for_statement": true, "while_statement": true, "switch_statement": true, "try_statement": true},
	binaryTypes: map[string]bool{"binary_expression": true},
	logicalOps:  map[string]bool{"&&": true, "||": true, "and": true, "or": true},
}

func scanPHP(root string) ([]model.Issue, error) {
	var issues []model.Issue
	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		if !strings.HasSuffix(path, ".php") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		tree, err := gts.NewParser(phpLang).Parse(src)
		if err != nil {
			return nil // ponytail: skip files that don't parse, don't fail the whole scan
		}
		for _, m := range tsMeasureFuncs(tree.RootNode(), phpLang, phpSpec, src, path) {
			issues = append(issues, m.issues()...)
		}
		return nil
	})
	return issues, err
}
