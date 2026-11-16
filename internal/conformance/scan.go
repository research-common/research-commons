package conformance

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Coverage maps a case id to the tests ("pkg/dir.TestName") that declare it with Covers.
type Coverage map[string][]string

// PartialCoverage maps a case id to "pkg/dir.TestName: remaining" entries from Partial calls.
type PartialCoverage map[string][]string

// ScanCoverage parses every _test.go file under root and collects the string-literal arguments of calls to
// conformance.Covers (or Covers inside this package). Non-literal arguments are reported as errors: the scan
// must be able to see every declared id.
//
// A test file the default build excludes (a `//go:build` line no default tag satisfies, or a GOOS/GOARCH file
// name for another platform) is never run by `go test ./...`, which is what the default CI jobs run, so its declarations cannot
// pass a case: a Covers in such a file is recorded as a Partial whose remaining text says "covered only under
// build tag <tag>", and a Partial in one carries the same note. The case then stays skipped until a test the
// default build runs covers it.
//
// One exception: a tag listed in internal/conformance/ci-tags.txt (under root) is a tag the CI workflow runs
// (`go test -tags <tag> …` in a job; a test keeps the list and the workflow in agreement), so a file whose
// `//go:build` expression is true under the default tags plus the listed ones is covered like any other.
func ScanCoverage(root string) (Coverage, PartialCoverage, []string, error) {
	tags, err := LoadCITags(root)
	if err != nil {
		return nil, nil, nil, err
	}
	return ScanCoverageTags(root, tags)
}

// CITagsFile is the allow-list of build tags the CI workflow runs, relative to the repository root.
const CITagsFile = "internal/conformance/ci-tags.txt"

// LoadCITags reads the allow-list under root: one tag per line, blank lines and `#` comments ignored (a trailing
// comment too). A missing file is an empty list; a line that is not a single build-tag word is an error.
func LoadCITags(root string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(CITagsFile)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var tags []string
	for i, l := range strings.Split(string(b), "\n") {
		if c := strings.IndexByte(l, '#'); c >= 0 {
			l = l[:c]
		}
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if !validTag(l) {
			return nil, fmt.Errorf("%s:%d: %q is not a single build tag", CITagsFile, i+1, l)
		}
		if !slices.Contains(tags, l) {
			tags = append(tags, l)
		}
	}
	return tags, nil
}

func validTag(s string) bool {
	for _, r := range s {
		if !(r == '_' || r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return false
		}
	}
	return s != ""
}

// ScanCoverageTags is ScanCoverage with the CI tag list given instead of read.
func ScanCoverageTags(root string, ciTags []string) (Coverage, PartialCoverage, []string, error) {
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
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(path))
		excluded := excludedFromDefaultBuild(f, path, ciTags)
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
					if excluded != "" {
						rem += " (this test is in a file the default build excludes: " + excluded + ")"
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
					if excluded != "" {
						part[id] = append(part[id], rel+"."+fn.Name.Name+": covered only under "+excluded+
							"; `go test ./...` does not run this test, so the case is not passed by it")
						continue
					}
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

// excludedFromDefaultBuild is "" when the default build compiles the test file, else why it does not: "build
// tag T" (the tags of its //go:build expression that no default build satisfies), "build constraint E" (an
// expression excluded by a tag it satisfies, such as !linux) or "a GOOS/GOARCH file name for another platform".
// The default build is this host's GOOS, GOARCH, the gc compiler, cgo as the host has it, `unix` on a Unix and
// the release tags of the toolchain, plus ciTags (the tags the CI workflow runs; none for a plain `go test ./...`).
func excludedFromDefaultBuild(f *ast.File, path string, ciTags []string) string {
	have := func(tag string) bool { return defaultTag(tag) || slices.Contains(ciTags, tag) }
	for _, cg := range f.Comments {
		if cg.End() >= f.Package {
			break
		}
		for _, c := range cg.List {
			if !constraint.IsGoBuild(c.Text) {
				continue
			}
			expr, err := constraint.Parse(c.Text)
			if err != nil {
				return "an unparsable build constraint (" + err.Error() + ")"
			}
			if expr.Eval(have) {
				continue
			}
			var tags []string
			collectTags(expr, &tags)
			var missing []string
			for _, t := range tags {
				if !have(t) && !slices.Contains(missing, t) {
					missing = append(missing, t)
				}
			}
			slices.Sort(missing)
			if len(missing) == 0 {
				return "build constraint " + strings.TrimPrefix(c.Text, "//go:build ")
			}
			return "build tag " + strings.Join(missing, ", ")
		}
	}
	// the final check is the go command's own file matching (name suffixes and constraints), with the CI tags set
	ctx := build.Default
	ctx.BuildTags = slices.Clone(ciTags)
	if ok, err := ctx.MatchFile(filepath.Dir(path), filepath.Base(path)); err == nil && !ok {
		return "a GOOS/GOARCH file name for another platform"
	}
	return ""
}

func collectTags(e constraint.Expr, out *[]string) {
	switch x := e.(type) {
	case *constraint.TagExpr:
		*out = append(*out, x.Tag)
	case *constraint.NotExpr:
		collectTags(x.X, out)
	case *constraint.AndExpr:
		collectTags(x.X, out)
		collectTags(x.Y, out)
	case *constraint.OrExpr:
		collectTags(x.X, out)
		collectTags(x.Y, out)
	}
}

func defaultTag(tag string) bool {
	switch tag {
	case runtime.GOOS, runtime.GOARCH, "gc":
		return true
	case "unix":
		return slices.Contains([]string{"aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios", "linux", "netbsd", "openbsd", "solaris"}, runtime.GOOS)
	case "cgo":
		return build.Default.CgoEnabled
	}
	return slices.Contains(build.Default.ReleaseTags, tag)
}
