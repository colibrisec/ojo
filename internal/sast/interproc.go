package sast

import gts "github.com/odvcencio/gotreesitter"

// Same-file interprocedural taint tracking, extending taint_ts.go's
// intraprocedural engine one specific way: closing the "sink inside a
// helper function" false negative documented as this codebase's #1 taint
// ceiling. A tainted argument at a call site to a same-file, name-resolved
// function/unqualified-same-class method seeds that callee's matching
// parameter as an additional taint source for its own body — so a sink
// rule using that parameter directly (not the caller's request object)
// fires at its real location inside the callee, with zero changes to any
// of the ~130 existing sink-rule call sites (they all already go through
// tsTaintEnv, which now folds this seed in transparently).
//
// Deliberately NOT built: return-value taint propagation (helper(tainted)
// making the assigned variable tainted at the call site). Every exprTainted
// function in this package already treats *any* call expression containing
// a tainted argument as tainted overall, regardless of what the callee
// actually does with it (see e.g. TestGoTaintDoesNotCrossFunctionCalls) —
// so that direction is already covered, more broadly than a same-file
// call-graph could manage on its own (it works for calls to functions this
// file can't even see the body of). Building a narrower, registry-based
// version of it here would be strictly less capable, not an improvement.
//
// ponytail ceiling, same shape as everywhere else in this file: resolved
// by name only, not by type — free functions and unqualified same-class
// method calls, not qualified calls (obj.method(x)), since resolving which
// concrete type's method a qualified call targets needs real type
// resolution this project doesn't have. Fixed at 3 rounds, not a real
// fixpoint solver, mirroring tsTaintEnv's own 2-round bounded-iteration
// precedent — the seed only ever grows across rounds (monotonic), so a
// recursive or cyclic call chain just stops improving within the round
// budget instead of looping forever.

// interprocFuncInfo captures one same-file, name-resolved function's
// positional parameter names and body.
type interprocFuncInfo struct {
	params []string
	body   *gts.Node
}

// tsCurrentParamSeed holds this file's precomputed interprocedural
// parameter taint seeds, keyed by function body node — set once per file
// by tsComputeParamSeed before that file's sink rules run, consulted
// transparently by tsTaintEnv. Shared across all five tree-sitter-backed
// languages: each language's own parse produces distinct node pointers,
// and only one file is scanned at a time.
//
// ponytail: file-scoped global, relies on each scanXFile running
// sequentially, not concurrently — would need a per-goroutine/per-call
// context instead if file scanning is ever parallelized.
var tsCurrentParamSeed = map[*gts.Node]map[string]bool{}

// identifierParamName handles Python/JS/Ruby/Java's parameter shapes: a
// plain identifier, or a wrapper (default/optional/splat/rest/typed
// parameter) with the identifier as a named child — verified against a
// real parse tree for every one of those wrapper shapes before writing
// this, not assumed from the simple case alone.
func identifierParamName(p *gts.Node, lang *gts.Language, src []byte) string {
	if p.Type(lang) == "identifier" {
		return string(p.Text(src))
	}
	for _, c := range p.Children() {
		if c.Type(lang) == "identifier" {
			return string(c.Text(src))
		}
	}
	return ""
}

// phpParamName handles PHP's simple_parameter/variadic_parameter shape: a
// variable_name child whose own .Text() already includes the "$" sigil —
// the same key phpAssignInfo/phpExprTainted already use for a plain
// variable, verified against a real parse tree before writing this.
func phpParamName(p *gts.Node, lang *gts.Language, src []byte) string {
	for _, c := range p.Children() {
		if c.Type(lang) == "variable_name" {
			return string(c.Text(src))
		}
	}
	return ""
}

// tsParamNames extracts positional parameter names off a function/method
// definition node's "parameters" field (the same field name every
// tree-sitter grammar here uses, per internal/quality/treesitter.go's own
// verification of the same fact) via the language-specific paramName.
func tsParamNames(def *gts.Node, lang *gts.Language, src []byte, paramName func(*gts.Node, *gts.Language, []byte) string) []string {
	params := def.ChildByFieldName("parameters", lang)
	if params == nil {
		return nil
	}
	var names []string
	for _, p := range params.Children() {
		if !p.IsNamed() {
			continue
		}
		names = append(names, paramName(p, lang, src))
	}
	return names
}

// tsBuildFuncRegistry runs defQuery — the @fname/@def/@body query every
// language already has from its *-insecure-random-for-secrets rule — to
// build a same-file name -> (params, body) map for call-graph resolution.
func tsBuildFuncRegistry(root *gts.Node, lang *gts.Language, src []byte, defQuery *gts.Query, paramName func(*gts.Node, *gts.Language, []byte) string) map[string]interprocFuncInfo {
	reg := map[string]interprocFuncInfo{}
	for _, m := range defQuery.ExecuteNode(root, lang, src) {
		var fname, def, body *gts.Node
		for _, c := range m.Captures {
			switch c.Name {
			case "fname":
				fname = c.Node
			case "def":
				def = c.Node
			case "body":
				body = c.Node
			}
		}
		if fname == nil || def == nil || body == nil {
			continue
		}
		reg[string(fname.Text(src))] = interprocFuncInfo{params: tsParamNames(def, lang, src, paramName), body: body}
	}
	return reg
}

// freeCall is one same-file call site resolved to a plain function name —
// not a qualified/method call (see tsFindFreeCalls).
type freeCall struct {
	callee string
	args   *gts.Node
}

// tsFindFreeCalls runs callQuery over root and returns only the matches
// that are genuinely unqualified: callQuery captures an optional "recv"
// field precisely so a receiver-qualified call (Ruby/Java's "call"/
// "method_invocation" node types are shared between the two shapes) can be
// filtered out here rather than needing negation syntax in the query
// itself — verified directly that the optional-capture-then-nil-check
// technique correctly distinguishes `foo(x)` from `obj.foo(x)`/`this.foo(x)`
// before relying on it.
func tsFindFreeCalls(root *gts.Node, lang *gts.Language, src []byte, callQuery *gts.Query) []freeCall {
	var calls []freeCall
	for _, m := range callQuery.ExecuteNode(root, lang, src) {
		var fn, args, recv *gts.Node
		for _, c := range m.Captures {
			switch c.Name {
			case "fn":
				fn = c.Node
			case "args":
				args = c.Node
			case "recv":
				recv = c.Node
			}
		}
		if fn == nil || args == nil || recv != nil {
			continue
		}
		calls = append(calls, freeCall{callee: string(fn.Text(src)), args: args})
	}
	return calls
}

// tsArgAt returns call.args's i-th positional argument expression, or nil
// if there aren't that many — unwrapping PHP's "argument" wrapper node
// (arguments (argument (expr))) the same way phpExprTainted's own call-case
// already does, since PHP is the one language here whose argument list
// doesn't expose the bare expression as the direct named child.
func tsArgAt(args *gts.Node, lang *gts.Language, i int) *gts.Node {
	if i < 0 || i >= args.NamedChildCount() {
		return nil
	}
	a := args.NamedChild(i)
	if a.Type(lang) == "argument" && a.NamedChildCount() > 0 {
		return a.NamedChild(0)
	}
	return a
}

// tsComputeParamSeed is the actual interprocedural pass: build the
// same-file call graph via tsBuildFuncRegistry/tsFindFreeCalls, then over a
// fixed number of rounds, seed each callee's parameter names with the
// argument positions some call site anywhere in the file passes tainted
// data to (using the calling function's own, possibly already-seeded,
// intraprocedural env). Called once per file by each scanXFile, before
// that file's rules run; the result is stashed in tsCurrentParamSeed for
// tsTaintEnv to consult transparently.
func tsComputeParamSeed(
	root *gts.Node, lang *gts.Language, src []byte, boundary map[string]bool,
	defQuery *gts.Query, callQuery *gts.Query, paramName func(*gts.Node, *gts.Language, []byte) string,
	assignInfo func(*gts.Node, *gts.Language, []byte) (string, *gts.Node, bool),
	exprTainted func(*gts.Node, *gts.Language, []byte, map[string]bool) bool,
) map[*gts.Node]map[string]bool {
	reg := tsBuildFuncRegistry(root, lang, src, defQuery, paramName)
	seed := map[*gts.Node]map[string]bool{}
	for round := 0; round < 3; round++ {
		for _, info := range reg {
			env := tsTaintEnvWithSeed(info.body, lang, src, boundary, assignInfo, exprTainted, seed[info.body])
			for _, call := range tsFindFreeCalls(info.body, lang, src, callQuery) {
				callee, ok := reg[call.callee]
				if !ok {
					continue
				}
				for i, pname := range callee.params {
					if pname == "" {
						continue
					}
					arg := tsArgAt(call.args, lang, i)
					if arg == nil || !exprTainted(arg, lang, src, env) {
						continue
					}
					if seed[callee.body] == nil {
						seed[callee.body] = map[string]bool{}
					}
					seed[callee.body][pname] = true
				}
			}
		}
	}
	return seed
}
