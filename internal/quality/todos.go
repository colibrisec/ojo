package quality

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"regexp"
	"strings"

	gts "github.com/odvcencio/gotreesitter"

	"github.com/colibrisec/ojo/internal/model"
	"github.com/colibrisec/ojo/internal/walk"
)

// SonarQube's own S1135 (TODO)/S1134 (FIXME) rules, generalized to the four
// markers real codebases actually use. Matched against real *comment* node
// text only (not a raw regex over the whole file), so a variable or string
// literal that happens to contain one of these words is never flagged —
// verified per language below, not assumed. Case-insensitive: "// todo:" is
// just as common in practice as "// TODO:". \b on both sides keeps
// "hackathon" from matching "hack".
var todoMarkerRe = regexp.MustCompile(`(?i)\b(TODO|FIXME|HACK|XXX)\b`)

// javaCommentTypes is the one language-specific wrinkle here: Java's
// grammar splits comments into two node types (line_comment/block_comment)
// where Python/JS/TS/TSX/PHP/Ruby all use a single "comment" type for both
// forms — confirmed by dumping a real parse tree for each before writing
// this, not assumed from the other five languages' shape.
var javaCommentTypes = map[string]bool{"line_comment": true, "block_comment": true}

func todoIssue(path string, line int, text string) model.Issue {
	return newIssue("quality-todo-comment", "INFO", path, line,
		"TODO/FIXME comment", "tracked comment: "+strings.TrimSpace(text))
}

// tsFindTODOs walks every node in a tree-sitter tree (including "extra"
// nodes — comments are extras in every one of these grammars) looking for
// a comment node whose text matches todoMarkerRe.
func tsFindTODOs(n *gts.Node, lang *gts.Language, src []byte, path string, isComment func(string) bool, issues *[]model.Issue) {
	if isComment(n.Type(lang)) && todoMarkerRe.MatchString(string(n.Text(src))) {
		*issues = append(*issues, todoIssue(path, int(n.StartPoint().Row)+1, string(n.Text(src))))
	}
	cc := n.ChildCount()
	for i := 0; i < cc; i++ {
		tsFindTODOs(n.Child(i), lang, src, path, isComment, issues)
	}
}

func isPlainComment(t string) bool { return t == "comment" }
func isJavaComment(t string) bool  { return javaCommentTypes[t] }

// scanTSFileTODOs reads and parses one file with the given grammar and
// appends any TODO/FIXME/HACK/XXX comment findings to *issues — the one
// read+parse+skip-on-error block shared by all five tree-sitter-backed
// languages below, instead of five copies of it.
func scanTSFileTODOs(path string, lang *gts.Language, isComment func(string) bool, issues *[]model.Issue) {
	src, err := os.ReadFile(path)
	if err != nil {
		return
	}
	tree, err := gts.NewParser(lang).Parse(src)
	if err != nil {
		return
	}
	tsFindTODOs(tree.RootNode(), lang, src, path, isComment, issues)
}

func scanTODOComments(root string) ([]model.Issue, error) {
	var issues []model.Issue
	err := walk.Walk(root, func(path string, d fs.DirEntry) error {
		switch {
		case strings.HasSuffix(path, ".go"):
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil // ponytail: skip files that don't parse, don't fail the whole scan
			}
			for _, cg := range f.Comments {
				for _, c := range cg.List {
					if todoMarkerRe.MatchString(c.Text) {
						issues = append(issues, todoIssue(path, fset.Position(c.Pos()).Line, c.Text))
					}
				}
			}
		case strings.HasSuffix(path, ".py"):
			scanTSFileTODOs(path, pyLang, isPlainComment, &issues)
		case strings.HasSuffix(path, ".php"):
			scanTSFileTODOs(path, phpLang, isPlainComment, &issues)
		case strings.HasSuffix(path, ".rb"):
			scanTSFileTODOs(path, rubyLang, isPlainComment, &issues)
		case strings.HasSuffix(path, ".java"):
			scanTSFileTODOs(path, javaLang, isJavaComment, &issues)
		default:
			if lang := jsLangForPath(path); lang != nil {
				scanTSFileTODOs(path, lang, isPlainComment, &issues)
			}
		}
		return nil
	})
	return issues, err
}
