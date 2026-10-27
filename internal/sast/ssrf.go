package sast

import (
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	gts "github.com/odvcencio/gotreesitter"
)

// SSRF findings are split by how much of the URL request input controls:
//
//	ssrfHigh  input can choose the scheme, host or port
//	ssrfLow   the scheme and host are fixed (a literal, or a config value
//	          such as c.baseURL); input only chooses the path or query
//	ssrfNone  nothing in the URL comes from request input
type ssrfLevel int

const (
	ssrfNone ssrfLevel = iota
	ssrfLow
	ssrfHigh
)

// urlPiece is one left-to-right part of a URL expression: literal text, or
// an expression that is or isn't tainted.
type urlPiece struct {
	lit     string
	isLit   bool
	tainted bool
}

// A literal prefix fixes the host once it has scheme://host followed by
// '/', '?' or '#', or is a same-origin path ("/x", not "//host").
var fixedHostPrefix = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]+[/?#]`)

func classifySSRF(pieces []urlPiece) ssrfLevel {
	first := -1
	for i, p := range pieces {
		if p.tainted {
			first = i
			break
		}
	}
	if first < 0 {
		return ssrfNone
	}
	if first == 0 {
		return ssrfHigh
	}
	prefix := pieces[:first]
	// An untainted non-literal at the start is taken as a configured base
	// URL (c.baseURL). Literals after it only matter if they open a new
	// scheme://host.
	var text strings.Builder
	for _, p := range prefix {
		if p.isLit {
			text.WriteString(p.lit)
		} else {
			text.WriteString("X")
		}
	}
	s := text.String()
	if !prefix[0].isLit {
		i := strings.Index(s, "://")
		if i < 0 || strings.ContainsAny(s[i+3:], "/?#") {
			return ssrfLow
		}
		return ssrfHigh
	}
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") {
		return ssrfLow
	}
	if fixedHostPrefix.MatchString(s) {
		return ssrfLow
	}
	return ssrfHigh
}

// ssrfText returns severity, title and message for a finding at level.
func ssrfText(level ssrfLevel, sink string) (severity, title, message string) {
	if level == ssrfHigh {
		return "HIGH", "Outbound request URL built from request data",
			sink + " URL comes from request input that can choose the scheme, host or port; validate it against an allowlist of destinations"
	}
	return "LOW", "Outbound request path built from request data",
		sink + " host is fixed, but request input chooses the path or query, so it can reach unintended endpoints on that host (e.g. ../admin); validate or encode the path segment"
}

var goFormatVerb = regexp.MustCompile(`%[-+# 0]*(\*|\d+)?(\.(\*|\d+))?[a-zA-Z%]`)

// goURLPieces splits a Go URL expression into pieces. assigns maps a local
// name to the expression last assigned to it in the function.
func goURLPieces(e ast.Expr, env map[string]bool, assigns map[string]ast.Expr, depth int) []urlPiece {
	switch v := e.(type) {
	case *ast.ParenExpr:
		return goURLPieces(v.X, env, assigns, depth)
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			return append(goURLPieces(v.X, env, assigns, depth), goURLPieces(v.Y, env, assigns, depth)...)
		}
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			s, err := strconv.Unquote(v.Value)
			if err == nil {
				return []urlPiece{{lit: s, isLit: true}}
			}
		}
	case *ast.Ident:
		if rhs, ok := assigns[v.Name]; ok && depth < 3 && env[v.Name] {
			return goURLPieces(rhs, env, assigns, depth+1)
		}
	case *ast.CallExpr:
		if pieces, ok := goSprintfPieces(v, env, assigns, depth); ok {
			return pieces
		}
	}
	return []urlPiece{{tainted: goExprTainted(e, env)}}
}

func goSprintfPieces(call *ast.CallExpr, env map[string]bool, assigns map[string]ast.Expr, depth int) ([]urlPiece, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) == 0 {
		return nil, false
	}
	if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "fmt" || sel.Sel.Name != "Sprintf" {
		return nil, false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return nil, false
	}
	format, err := strconv.Unquote(lit.Value)
	if err != nil {
		return nil, false
	}
	args := call.Args[1:]
	var out []urlPiece
	last := 0
	for _, loc := range goFormatVerb.FindAllStringIndex(format, -1) {
		out = append(out, urlPiece{lit: format[last:loc[0]], isLit: true})
		last = loc[1]
		if format[loc[1]-1] == '%' {
			out = append(out, urlPiece{lit: "%", isLit: true})
			continue
		}
		if len(args) == 0 {
			continue
		}
		out = append(out, goURLPieces(args[0], env, assigns, depth)...)
		args = args[1:]
	}
	out = append(out, urlPiece{lit: format[last:], isLit: true})
	return out, true
}

// goLocalAssigns maps each local name in body to its last assigned value.
func goLocalAssigns(body *ast.BlockStmt) map[string]ast.Expr {
	out := map[string]ast.Expr{}
	inspectWithinFunc(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			if len(v.Lhs) != len(v.Rhs) {
				return true
			}
			for i, l := range v.Lhs {
				if id, ok := l.(*ast.Ident); ok {
					out[id.Name] = v.Rhs[i]
				}
			}
		case *ast.ValueSpec:
			if len(v.Names) != len(v.Values) {
				return true
			}
			for i, id := range v.Names {
				out[id.Name] = v.Values[i]
			}
		}
		return true
	})
	return out
}

// tsURLSplitter splits a URL expression in a tree-sitter language.
type tsURLSplitter struct {
	lang       *gts.Language
	boundary   map[string]bool
	assignInfo func(n *gts.Node, lang *gts.Language, src []byte) (string, *gts.Node, bool)
	tainted    func(n *gts.Node, src []byte) bool
	concat     map[string]bool // binary node types
	concatOp   map[string]bool // string-joining operators
	strings    map[string]bool // string node types
	ident      string          // identifier node type
}

var tsStringLiteralParts = map[string]bool{"string_content": true, "string_fragment": true, "escape_sequence": true}

func (s tsURLSplitter) pieces(n *gts.Node, src []byte, depth int) []urlPiece {
	t := n.Type(s.lang)
	switch {
	case strings.HasPrefix(t, "parenthesized"):
		if n.NamedChildCount() == 1 {
			return s.pieces(n.NamedChild(0), src, depth)
		}
	case s.concat[t]:
		op := n.ChildByFieldName("operator", s.lang)
		left, right := n.ChildByFieldName("left", s.lang), n.ChildByFieldName("right", s.lang)
		if op != nil && s.concatOp[op.Text(src)] && left != nil && right != nil {
			return append(s.pieces(left, src, depth), s.pieces(right, src, depth)...)
		}
	case s.strings[t]:
		var out []urlPiece
		for _, c := range n.Children() {
			ct := c.Type(s.lang)
			switch {
			case tsStringLiteralParts[ct]:
				out = append(out, urlPiece{lit: c.Text(src), isLit: true})
			case !c.IsNamed() || ct == "string_start" || ct == "string_end":
			case ct == "interpolation" || ct == "template_substitution":
				if c.NamedChildCount() > 0 {
					out = append(out, s.pieces(c.NamedChild(0), src, depth)...)
				}
			default:
				out = append(out, s.pieces(c, src, depth)...)
			}
		}
		if len(out) == 0 {
			out = []urlPiece{{isLit: true}}
		}
		return out
	case t == s.ident && depth < 3 && s.tainted(n, src):
		if rhs := s.lastAssign(n, src); rhs != nil {
			return s.pieces(rhs, src, depth+1)
		}
	}
	return []urlPiece{{tainted: s.tainted(n, src)}}
}

func (s tsURLSplitter) lastAssign(id *gts.Node, src []byte) *gts.Node {
	body := tsEnclosingBody(id, s.lang, s.boundary)
	if body == nil {
		return nil
	}
	name := id.Text(src)
	var rhs *gts.Node
	tsWalkWithinScope(body, s.lang, s.boundary, func(n *gts.Node) {
		if n.StartByte() >= id.StartByte() {
			return
		}
		if got, r, ok := s.assignInfo(n, s.lang, src); ok && got == name {
			rhs = r
		}
	})
	return rhs
}

func (s tsURLSplitter) classify(n *gts.Node, src []byte) ssrfLevel {
	return classifySSRF(s.pieces(n, src, 0))
}

var (
	pyURL = tsURLSplitter{
		lang: pyLang, boundary: pyFuncBoundary, assignInfo: pyAssignInfo, tainted: pyTaintedArg,
		concat: map[string]bool{"binary_operator": true}, concatOp: map[string]bool{"+": true},
		strings: map[string]bool{"string": true, "concatenated_string": true}, ident: "identifier",
	}
	phpURL = tsURLSplitter{
		lang: phpLang, boundary: phpFuncBoundary, assignInfo: phpAssignInfo, tainted: phpTaintedArg,
		concat: map[string]bool{"binary_expression": true}, concatOp: map[string]bool{".": true},
		strings: map[string]bool{"string": true, "encapsed_string": true}, ident: "variable_name",
	}
	rubyURL = tsURLSplitter{
		lang: rubyLang, boundary: rubyFuncBoundary, assignInfo: rubyAssignInfo, tainted: rubyTaintedArg,
		concat: map[string]bool{"binary": true}, concatOp: map[string]bool{"+": true},
		strings: map[string]bool{"string": true}, ident: "identifier",
	}
	javaURL = tsURLSplitter{
		lang: javaLang, boundary: javaFuncBoundary, assignInfo: javaAssignInfo, tainted: javaTaintedArg,
		concat: map[string]bool{"binary_expression": true}, concatOp: map[string]bool{"+": true},
		strings: map[string]bool{"string_literal": true}, ident: "identifier",
	}
)

func jsURLSplitter(lang *gts.Language) tsURLSplitter {
	return tsURLSplitter{
		lang: lang, boundary: jsFuncBoundary, assignInfo: jsAssignInfo,
		tainted: func(n *gts.Node, src []byte) bool { return jsTaintedArg(n, lang, src) },
		concat:  map[string]bool{"binary_expression": true}, concatOp: map[string]bool{"+": true},
		strings: map[string]bool{"string": true, "template_string": true}, ident: "identifier",
	}
}
