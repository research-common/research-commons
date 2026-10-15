package conformance

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
)

// Coverage maps a case id to the tests ("pkg/dir.TestName") that declare it with Covers.
type Coverage map[string][]string

// PartialCoverage maps a case id to "pkg/dir.TestName: remaining" entries from Partial calls.
type PartialCoverage map[string][]string

// ScanCoverage parses every _test.go file under root and collects the string-literal arguments of calls to
// conformance.Covers (or Covers inside this package). Non-literal arguments are reported as errors: the scan
// must be able to see every declared id.
func ScanCoverage(root string) (Coverage, PartialCoverage, []string, error) {
	cov := Coverage{}
	part := PartialCoverage{}
	var problems []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "node_modules" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(path))
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := calledName(call.Fun)
				if name == "Partial" {
					if len(call.Args) != 3 {
						problems = append(problems, fset.Position(call.Pos()).String()+": Partial takes (t, id, remaining)")
						return true
					}
					id, ok1 := literal(call.Args[1])
					rem, ok2 := literal(call.Args[2])
					if !ok1 || !ok2 {
						problems = append(problems, fset.Position(call.Pos()).String()+": Partial arguments are not string literals")
						return true
					}
					part[id] = append(part[id], rel+"."+fn.Name.Name+": "+rem)
					return true
				}
				if name != "Covers" {
					return true
				}
				for _, a := range call.Args[1:] {
					lit, ok := a.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						problems = append(problems, fset.Position(a.Pos()).String()+": Covers argument is not a string literal")
						continue
					}
					id, _ := strconv.Unquote(lit.Value)
					cov[id] = append(cov[id], rel+"."+fn.Name.Name)
				}
				return true
			})
			return false
		})
		return nil
	})
	return cov, part, problems, err
}

// calledName returns "Covers" or "Partial" for conformance.Covers / conformance.Partial (or the bare names
// inside this package), else "".
func calledName(e ast.Expr) string {
	var n string
	switch f := e.(type) {
	case *ast.SelectorExpr:
		x, ok := f.X.(*ast.Ident)
		if !ok || x.Name != "conformance" {
			return ""
		}
		n = f.Sel.Name
	case *ast.Ident:
		n = f.Name
	}
	if n == "Covers" || n == "Partial" {
		return n
	}
	return ""
}

func literal(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}
