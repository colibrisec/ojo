package sast

import "go/ast"

// Intraprocedural taint tracking for Go: within a single function body,
// track which local variables derive (directly or through concatenation/
// Sprintf/further assignment) from a known-tainted source, so sink rules can
// see through `next := r.URL.Query().Get("next")` rather than only matching
// r/req/request literally at the call site.
//
// ponytail ceiling: linear pass over the function body in AST order, not a
// real CFG — a taint assigned inside an `if` still taints for the rest of
// the function on every later read, even on paths where that branch didn't
// execute. Two passes handle a var tainted via another var assigned later
// in a shadowing/reordered chain; anything needing more than that (loops
// re-tainting across iterations, taint through function calls/returns,
// field-sensitivity beyond the fixed source list) isn't modeled. Good
// enough to kill the "request data hidden behind one local variable" false
// negative documented as the #1 ceiling in docs/guide/scanner/sast.md;
// not a dataflow engine.

// forEachGoFuncBody calls visit once per function body in f — each
// top-level FuncDecl and each FuncLit (closures get their own taint scope,
// not their enclosing function's).
func forEachGoFuncBody(f *ast.File, visit func(*ast.BlockStmt)) {
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.FuncDecl:
			if v.Body != nil {
				visit(v.Body)
			}
		case *ast.FuncLit:
			if v.Body != nil {
				visit(v.Body)
			}
		}
		return true
	})
}

// inspectWithinFunc is ast.Inspect over body that stops at nested function
// literals, so a rule scanning one function's sinks doesn't also re-report
// sinks inside a closure that gets its own separate forEachGoFuncBody call.
func inspectWithinFunc(body *ast.BlockStmt, fn func(ast.Node) bool) {
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		return fn(n)
	})
}

// goTaintEnv returns the set of local variable names assigned (directly or
// transitively) from tainted input somewhere in body.
func goTaintEnv(body *ast.BlockStmt) map[string]bool {
	env := map[string]bool{}
	for range 2 { // second pass catches vars tainted via a var assigned later in source order
		inspectWithinFunc(body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, rhs := range assign.Rhs {
				if i >= len(assign.Lhs) {
					continue
				}
				lhs, ok := assign.Lhs[i].(*ast.Ident)
				if !ok {
					continue
				}
				if goExprTainted(rhs, env) {
					env[lhs.Name] = true
				}
			}
			return true
		})
	}
	return env
}

// goExprTainted reports whether e evaluates from tainted input: rooted at
// r/req/request (goRootedAtRequest), an os.Getenv/os.LookupEnv call, a
// variable already known-tainted, or built from any of those via
// concatenation/fmt.Sprintf/Sprint.
func goExprTainted(e ast.Expr, env map[string]bool) bool {
	if goRootedAtRequest(e) || goIsEnvSource(e) {
		return true
	}
	switch v := e.(type) {
	case *ast.Ident:
		return env[v.Name]
	case *ast.BinaryExpr:
		return goExprTainted(v.X, env) || goExprTainted(v.Y, env)
	case *ast.CallExpr:
		for _, arg := range v.Args {
			if goExprTainted(arg, env) {
				return true
			}
		}
		return false
	case *ast.ParenExpr:
		return goExprTainted(v.X, env)
	default:
		return false
	}
}

func goIsEnvSource(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "os" && (sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv")
}
