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

// goCurrentParamSeed holds this file's precomputed same-file interprocedural
// parameter taint seeds (see goComputeParamSeed), keyed by function body —
// set once per file by Scan before that file's rules run, consulted
// transparently by goTaintEnv so none of rules.go's six call sites need to
// change.
//
// ponytail: file-scoped global, relies on Scan processing one file at a
// time sequentially — would need a per-goroutine/per-call context instead
// if file scanning is ever parallelized.
var goCurrentParamSeed map[*ast.BlockStmt]map[string]bool

// goTaintEnv returns the set of local variable names assigned (directly or
// transitively) from tainted input somewhere in body.
func goTaintEnv(body *ast.BlockStmt) map[string]bool {
	return goTaintEnvWithSeed(body, goCurrentParamSeed[body])
}

// goTaintEnvWithSeed is goTaintEnv's actual implementation, taking an
// explicit initial taint set instead of consulting the package-level
// goCurrentParamSeed — used by goComputeParamSeed itself, which needs to
// build each round's per-function env from its own in-progress seed map.
func goTaintEnvWithSeed(body *ast.BlockStmt, seed map[string]bool) map[string]bool {
	env := map[string]bool{}
	for name := range seed {
		env[name] = true
	}
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

// goInterprocFuncInfo captures one same-file, top-level free function's
// positional parameter names and body — used to build a same-file call
// graph. Free functions only, no methods: a Go method call needs the
// receiver's concrete type resolved to know which method it targets, the
// same "flag the candidate, not type-verified" line every rule in this
// codebase already draws, just applied to call resolution instead of a
// single call site.
type goInterprocFuncInfo struct {
	params []string
	body   *ast.BlockStmt
}

func goBuildFuncRegistry(f *ast.File) map[string]goInterprocFuncInfo {
	reg := map[string]goInterprocFuncInfo{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil {
			continue
		}
		reg[fn.Name.Name] = goInterprocFuncInfo{params: goParamNames(fn.Type.Params), body: fn.Body}
	}
	return reg
}

func goParamNames(params *ast.FieldList) []string {
	if params == nil {
		return nil
	}
	var names []string
	for _, field := range params.List {
		if len(field.Names) == 0 {
			names = append(names, "") // unnamed parameter (interface-style signature): never matches a real taint check
			continue
		}
		for _, n := range field.Names {
			names = append(names, n.Name)
		}
	}
	return names
}

// goComputeParamSeed closes the "sink inside a helper function" gap
// documented at the top of this file: a same-file call graph among free
// functions, iterated a fixed 3 rounds (mirroring goTaintEnv's own
// 2-round bounded-iteration precedent — taint state only ever grows across
// rounds, so a recursive/cyclic call chain just stops improving within the
// round budget instead of looping forever). For each call site passing a
// tainted argument to a same-file free function, the corresponding
// parameter name is seeded as an additional taint source for that
// function's own body — so a sink rule using that parameter directly
// fires at its real location inside the callee, without any change to the
// sink rules themselves.
//
// Deliberately NOT built: return-value taint propagation. goExprTainted's
// CallExpr case already treats *any* call containing a tainted argument as
// tainted overall, regardless of what the callee does with it (pinned by
// TestGoTaintDoesNotCrossFunctionCalls) — a real limitation in the other
// direction (it can't recognize genuine sanitization, so it over-taints),
// but it means return-taint propagation is already covered, more broadly
// than a same-file registry could manage alone (it already works for
// calls this file can't see the body of at all).
func goComputeParamSeed(f *ast.File) map[*ast.BlockStmt]map[string]bool {
	reg := goBuildFuncRegistry(f)
	seed := map[*ast.BlockStmt]map[string]bool{}
	for round := 0; round < 3; round++ {
		for _, info := range reg {
			env := goTaintEnvWithSeed(info.body, seed[info.body])
			inspectWithinFunc(info.body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				callee, ok := reg[id.Name]
				if !ok {
					return true
				}
				for i, arg := range call.Args {
					if i >= len(callee.params) || callee.params[i] == "" || !goExprTainted(arg, env) {
						continue
					}
					if seed[callee.body] == nil {
						seed[callee.body] = map[string]bool{}
					}
					seed[callee.body][callee.params[i]] = true
				}
				return true
			})
		}
	}
	return seed
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
