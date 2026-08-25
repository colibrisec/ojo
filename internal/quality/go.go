package quality

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"

	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/walk"
)

func scanGo(root string) ([]model.Issue, error) {
	var issues []model.Issue
	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil // ponytail: skip files that don't parse, don't fail the whole scan
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch fn := n.(type) {
			case *ast.FuncDecl:
				if fn.Body != nil {
					issues = append(issues, measureGoFunc(fn.Name.Name, fn.Type.Params, fn.Body, fset, path).issues()...)
				}
			case *ast.FuncLit:
				issues = append(issues, measureGoFunc("func literal", fn.Type.Params, fn.Body, fset, path).issues()...)
			}
			return true
		})
		return nil
	})
	return issues, err
}

func measureGoFunc(name string, params *ast.FieldList, body *ast.BlockStmt, fset *token.FileSet, path string) funcMetrics {
	return funcMetrics{
		name:       name,
		file:       path,
		startLine:  fset.Position(body.Pos()).Line,
		endLine:    fset.Position(body.End()).Line,
		params:     goParamCount(params),
		nesting:    goNestingDepth(body),
		complexity: goComplexity(body),
	}
}

func goParamCount(params *ast.FieldList) int {
	if params == nil {
		return 0
	}
	n := 0
	for _, f := range params.List {
		if len(f.Names) == 0 {
			n++ // unnamed parameter (e.g. interface method signature) is still one slot
			continue
		}
		n += len(f.Names)
	}
	return n
}

// goComplexity is McCabe complexity: 1 + one per decision point anywhere in
// body, regardless of nesting (unlike goNestingDepth, complexity doesn't
// care how deep a branch is, only that it exists).
func goComplexity(body *ast.BlockStmt) int {
	complexity := 1
	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.IfStmt:
			complexity++
		case *ast.ForStmt:
			complexity++
		case *ast.RangeStmt:
			complexity++
		case *ast.CaseClause:
			complexity++
		case *ast.CommClause:
			complexity++
		case *ast.BinaryExpr:
			if v.Op == token.LAND || v.Op == token.LOR {
				complexity++
			}
		}
		return true
	})
	return complexity
}

// goNestingDepth is the max depth of nested control-flow blocks
// (if/for/range/switch/select) within body — a different question from
// complexity: a function with 10 sibling ifs has high complexity but
// nesting depth 1; one if inside a for inside an if has nesting depth 3
// regardless of how many decision points that is in total.
func goNestingDepth(body *ast.BlockStmt) int {
	max := 0
	var walkNode func(n ast.Node, depth int)
	walkNode = func(n ast.Node, depth int) {
		if depth > max {
			max = depth
		}
		ast.Inspect(n, func(child ast.Node) bool {
			if child == n {
				return true // don't re-enter the node walkNode was called with
			}
			switch child.(type) {
			case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
				walkNode(child, depth+1)
				return false // walkNode's own Inspect call handles this subtree
			}
			return true
		})
	}
	walkNode(body, 0)
	return max
}
