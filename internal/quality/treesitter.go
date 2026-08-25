package quality

import (
	"strings"

	gts "github.com/odvcencio/gotreesitter"
)

// tsLangSpec bundles the per-language node-type facts needed to measure
// functions generically across all five tree-sitter-backed languages —
// one shared engine instead of five near-duplicate ones. Two facts,
// verified directly (not assumed) to be consistent across all five
// grammars before this was written as a single implementation:
//
//   - every function-like node exposes its parameter list via a field
//     literally named "parameters", and NamedChildCount() on that list —
//     which tree-sitter's named/anonymous distinction already excludes
//     punctuation tokens ("(", ",", ")") from — counts parameters
//     correctly with no per-language parameter-node-type enumeration
//     needed at all;
//   - every function-like node exposes its body via a field named "body"
//     (same fact taint_ts.go already relies on) — except a Ruby method
//     with an empty body has no body field at all (no body_statement node
//     gets constructed), handled by falling back to the function node's
//     own span and treating a nil body as zero decision points/nesting.
type tsLangSpec struct {
	funcTypes     map[string]bool // node types that are functions/methods/lambdas/closures
	branchTypes   map[string]bool // node types that are +1 complexity unconditionally
	nestTypes     map[string]bool // node types that are +1 nesting depth (block-level control constructs)
	binaryTypes   map[string]bool // node types also used for arithmetic/comparison — need an operator-field check, can't be in branchTypes directly
	logicalOps    map[string]bool // operator field text values that make a binaryTypes node +1 complexity
	caseLabelType string          // node type (if any) that's shared between "case" and "default" labels and needs a text check to disambiguate (Java only)
}

func tsFuncName(n *gts.Node, lang *gts.Language, src []byte) string {
	if name := n.ChildByFieldName("name", lang); name != nil {
		return string(name.Text(src))
	}
	return "anonymous function"
}

func tsParamCount(n *gts.Node, lang *gts.Language) int {
	params := n.ChildByFieldName("parameters", lang)
	if params == nil {
		return 0
	}
	return params.NamedChildCount()
}

// tsComplexity is McCabe complexity: 1 + one per decision point anywhere
// in body, regardless of nesting depth. body may be nil (an empty
// function body in a grammar that omits the body field entirely rather
// than producing an empty node) — treated as zero decision points.
func tsComplexity(body *gts.Node, lang *gts.Language, spec tsLangSpec, src []byte) int {
	complexity := 1
	if body == nil {
		return complexity
	}
	var walkNode func(n *gts.Node)
	walkNode = func(n *gts.Node) {
		t := n.Type(lang)
		switch {
		case spec.branchTypes[t]:
			complexity++
		case spec.binaryTypes[t]:
			if op := n.ChildByFieldName("operator", lang); op != nil && spec.logicalOps[string(op.Text(src))] {
				complexity++
			}
		case spec.caseLabelType != "" && t == spec.caseLabelType:
			if strings.HasPrefix(string(n.Text(src)), "case") {
				complexity++
			}
		}
		for _, c := range n.Children() {
			walkNode(c)
		}
	}
	walkNode(body)
	return complexity
}

// tsNestingDepth is the max depth of nested block-level control-flow
// constructs (if/for/while/switch/try) within body — independent of
// complexity: ten sibling ifs is high complexity but nesting depth 1; one
// if inside a for inside an if is depth 3 regardless of total branch count.
func tsNestingDepth(body *gts.Node, lang *gts.Language, spec tsLangSpec) int {
	if body == nil {
		return 0
	}
	max := 0
	var walkNode func(n *gts.Node, depth int)
	walkNode = func(n *gts.Node, depth int) {
		if depth > max {
			max = depth
		}
		for _, c := range n.Children() {
			if spec.nestTypes[c.Type(lang)] {
				walkNode(c, depth+1)
			} else {
				walkNode(c, depth)
			}
		}
	}
	walkNode(body, 0)
	return max
}

// tsMeasureFuncs walks root's whole tree finding every node matching
// spec.funcTypes and returns one funcMetrics per function found.
func tsMeasureFuncs(root *gts.Node, lang *gts.Language, spec tsLangSpec, src []byte, path string) []funcMetrics {
	var out []funcMetrics
	var walkNode func(n *gts.Node)
	walkNode = func(n *gts.Node) {
		if spec.funcTypes[n.Type(lang)] {
			body := n.ChildByFieldName("body", lang)
			start := n.StartPoint()
			end := n.EndPoint()
			out = append(out, funcMetrics{
				name:       tsFuncName(n, lang, src),
				file:       path,
				startLine:  int(start.Row) + 1,
				endLine:    int(end.Row) + 1,
				params:     tsParamCount(n, lang),
				nesting:    tsNestingDepth(body, lang, spec),
				complexity: tsComplexity(body, lang, spec, src),
			})
		}
		for _, c := range n.Children() {
			walkNode(c)
		}
	}
	walkNode(root)
	return out
}
