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

var (
	jsLang  = grammars.JavascriptLanguage()
	tsLang  = grammars.TypescriptLanguage()
	tsxLang = grammars.TsxLanguage()
)

// jsSpec is shared across all three grammars (js/ts/tsx) — the relevant
// node type names are identical across them, same fact internal/sast's
// mustTriQuery relies on.
var jsSpec = tsLangSpec{
	funcTypes:   map[string]bool{"function_declaration": true, "function_expression": true, "arrow_function": true, "method_definition": true, "generator_function_declaration": true, "generator_function": true},
	branchTypes: map[string]bool{"if_statement": true, "for_statement": true, "while_statement": true, "switch_case": true, "catch_clause": true, "ternary_expression": true},
	nestTypes:   map[string]bool{"if_statement": true, "for_statement": true, "while_statement": true, "switch_statement": true, "try_statement": true},
	binaryTypes: map[string]bool{"binary_expression": true},
	logicalOps:  map[string]bool{"&&": true, "||": true},
}

// jsLangForPath mirrors internal/sast's own extension-to-grammar mapping.
func jsLangForPath(path string) *gts.Language {
	switch {
	case strings.HasSuffix(path, ".tsx"):
		return tsxLang
	case strings.HasSuffix(path, ".ts"), strings.HasSuffix(path, ".mts"), strings.HasSuffix(path, ".cts"):
		return tsLang
	case strings.HasSuffix(path, ".js"), strings.HasSuffix(path, ".jsx"), strings.HasSuffix(path, ".mjs"), strings.HasSuffix(path, ".cjs"):
		return jsLang
	default:
		return nil
	}
}

func scanJS(root string) ([]model.Issue, error) {
	var issues []model.Issue
	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		lang := jsLangForPath(path)
		if lang == nil {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		tree, err := gts.NewParser(lang).Parse(src)
		if err != nil {
			return nil // ponytail: skip files that don't parse, don't fail the whole scan
		}
		for _, m := range tsMeasureFuncs(tree.RootNode(), lang, jsSpec, src, path) {
			issues = append(issues, m.issues()...)
		}
		return nil
	})
	return issues, err
}
