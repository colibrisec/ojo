package sast

import gts "github.com/odvcencio/gotreesitter"

// Shared scaffolding for intraprocedural taint tracking across the
// tree-sitter-backed languages (Python, JS/TS/TSX, PHP, Ruby, Java) — the
// same idea as taint.go's Go-specific version, generalized over a node
// tree instead of go/ast. Verified directly (not assumed, per this
// project's usual rule) that every function/method/lambda/closure node
// across all five grammars exposes its body via a field literally named
// "body", including single-expression arrow/lambda bodies that aren't a
// block at all — so tsEnclosingBody below needs no per-node-type special
// casing.
//
// ponytail ceiling: same as Go's — a linear pass over the function body in
// tree order, not a real CFG (branch-insensitive), and taint doesn't cross
// a function call (a value passed to a helper and returned tainted isn't
// tracked). Each language supplies its own node-shape predicates
// (boundary type set, assignInfo, exprTainted) below in its own file.

// tsWalkWithinScope calls visit on every descendant of n, skipping
// subtrees rooted at a node whose type is in boundary — those get their
// own separate taint scope from their own top-level tsEnclosingBody/
// tsTaintEnv call, so a closure's locals don't leak into the enclosing
// function's env or vice versa.
func tsWalkWithinScope(n *gts.Node, lang *gts.Language, boundary map[string]bool, visit func(*gts.Node)) {
	for _, c := range n.Children() {
		if boundary[c.Type(lang)] {
			continue
		}
		visit(c)
		tsWalkWithinScope(c, lang, boundary, visit)
	}
}

// tsEnclosingBody walks n's ancestors for the nearest node whose type is
// in boundary, and returns its "body" field — nil if n isn't inside one of
// those, or that one has no body (e.g. an abstract/interface method).
func tsEnclosingBody(n *gts.Node, lang *gts.Language, boundary map[string]bool) *gts.Node {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if boundary[p.Type(lang)] {
			return p.ChildByFieldName("body", lang)
		}
	}
	return nil
}

// tsTaintEnv builds the set of local variable names assigned (directly, or
// transitively through a chain of assignments) from tainted input
// somewhere in body. assignInfo pulls (name, rhsExpr, ok) out of an
// assignment-shaped node; exprTainted decides whether a given expression
// evaluates from tainted input given the taint state built so far.
//
// Transparently seeded from tsCurrentParamSeed (see interproc.go) so every
// existing call site — and every sink rule that goes through it — sees a
// same-file interprocedurally-tainted parameter without any change of its
// own: the seed is folded into env before the usual intraprocedural pass
// runs, so a sink using that parameter directly behaves exactly as if the
// parameter had been r/req-rooted to begin with.
func tsTaintEnv(
	body *gts.Node,
	lang *gts.Language,
	src []byte,
	boundary map[string]bool,
	assignInfo func(n *gts.Node, lang *gts.Language, src []byte) (name string, rhs *gts.Node, ok bool),
	exprTainted func(n *gts.Node, lang *gts.Language, src []byte, env map[string]bool) bool,
) map[string]bool {
	return tsTaintEnvWithSeed(body, lang, src, boundary, assignInfo, exprTainted, tsCurrentParamSeed[body])
}

// tsTaintEnvWithSeed is tsTaintEnv's actual implementation, taking an
// explicit initial taint set instead of consulting the package-level
// tsCurrentParamSeed — used by tsComputeParamSeed itself (interproc.go),
// which needs to build each round's per-function env from its own
// in-progress seed map, not the previous file's leftover global state.
func tsTaintEnvWithSeed(
	body *gts.Node,
	lang *gts.Language,
	src []byte,
	boundary map[string]bool,
	assignInfo func(n *gts.Node, lang *gts.Language, src []byte) (name string, rhs *gts.Node, ok bool),
	exprTainted func(n *gts.Node, lang *gts.Language, src []byte, env map[string]bool) bool,
	seed map[string]bool,
) map[string]bool {
	env := map[string]bool{}
	for name := range seed {
		env[name] = true
	}
	if body == nil {
		return env
	}
	for range 2 { // second pass: a var tainted via another var assigned later in source order
		tsWalkWithinScope(body, lang, boundary, func(n *gts.Node) {
			name, rhs, ok := assignInfo(n, lang, src)
			if !ok {
				return
			}
			if exprTainted(rhs, lang, src, env) {
				env[name] = true
			}
		})
	}
	return env
}
