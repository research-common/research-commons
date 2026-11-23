// Package specgraph joins what the repository already says in separate places into one generated file: which
// case pins which section of which design note, which tests declare each case, and which output tokens and exit
// codes each case's required outcome names. Nothing here is a new source of truth. Every edge is read from a
// case row, a design note's headings, the Covers scan or the CLI's vocabulary, and a test fails when
// docs/spec-graph.json is not what those sources generate.
//
// The package also writes the conformance report of a test run (report.go).
package specgraph

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/cli"
	"github.com/research-common/research-commons/internal/conformance"
)

// GraphFormat names the layout of docs/spec-graph.json. It is a description of this repository for tools and
// readers, outside every format freeze; the number changes when a member is renamed or removed.
const GraphFormat = "spec-graph/0"

// GraphFile is where the graph is kept, relative to the repository root.
const GraphFile = "docs/spec-graph.json"

// Pin is one thing a case row names: a section, an invariant or a worked example of a note.
type Pin struct {
	Note, Section, Invariant, Example string
}

// Case is one conformance case with every edge the sources give it.
type Case struct {
	ID        string
	Profile   string
	DefinedIn string   // the document whose table defines the case
	Pins      []Pin    // from the row's note column; empty when the table has none
	Tokens    []string // output tokens the required outcome names in code marks
	Exits     []int    // exit codes the required outcome names ("exit 3", "exits 0")
	Status    string   // covered, partial or pending, as the Covers scan finds it
	Tests     []string // tests that declare the case covered
	Remaining []string // "test: what is left" for each test that declares part of it
}

// Graph is the whole file.
type Graph struct {
	Notes  []*conformance.Note // in the order the coverage tables use
	Files  map[string]string   // note name → file
	Cases  []Case
	Tokens []cli.Token
	Exits  [][3]string
}

var (
	// headerRow is the first row of a case table; its cells name the columns.
	headerRow = regexp.MustCompile(`(?i)^\| *id *\|`)
	codeSpan  = regexp.MustCompile("`([^`]+)`")
	exitWord  = regexp.MustCompile(`\b[Ee]xits? ([0-9])\b`)
)

// row is a case row's cells by column name.
type row struct{ pins, outcome string }

// caseTables reads every case row of doc with the column names of the table it sits in. The column that pins
// the note is headed "note" (CONFORMANCE.md) or "profile" (the identity note); a table with neither has no pins.
func caseTables(doc []byte) map[string]row {
	out := map[string]row{}
	var cols []string
	for _, c := range conformance.CaseRows(doc) {
		out[c.ID] = row{} // every id CaseRows finds is present, with or without a header
	}
	for _, l := range strings.Split(string(doc), "\n") {
		if !strings.HasPrefix(l, "|") {
			cols = nil
			continue
		}
		cells := strings.Split(l, "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if headerRow.MatchString(l) {
			cols = make([]string, len(cells))
			for i, c := range cells {
				cols[i] = strings.ToLower(c)
			}
			continue
		}
		if len(cells) < 2 || cols == nil {
			continue
		}
		if _, ok := out[cells[1]]; !ok {
			continue
		}
		var r row
		for i, name := range cols {
			if i >= len(cells) {
				break
			}
			switch name {
			case "note", "profile":
				r.pins = cells[i]
			case "required outcome":
				r.outcome = cells[i]
			}
		}
		out[cells[1]] = r
	}
	return out
}

// homeNote is the note a bare `§n` belongs to in a document's case table.
func homeNote(doc string) string {
	for name, file := range conformance.NoteDocs {
		if file == doc && name != "bitcoin-time" {
			return name
		}
	}
	return conformance.ClaimsNote
}

// Build reads the graph from the tree under root. The problems are the ones the pin lint and the scan report.
func Build(root string) (*Graph, []string, error) {
	notes, problems, err := conformance.LoadNotes(root)
	if err != nil {
		return nil, nil, err
	}
	ids, home, err := conformance.LoadCaseIDs(root)
	if err != nil {
		return nil, nil, err
	}
	cov, part, scanProblems, err := conformance.ScanCoverage(root)
	if err != nil {
		return nil, nil, err
	}
	problems = append(problems, scanProblems...)

	rows := map[string]map[string]row{}
	for _, doc := range home {
		if rows[doc] != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(doc)))
		if err != nil {
			return nil, nil, err
		}
		rows[doc] = caseTables(b)
	}
	words := map[string]bool{}
	for _, t := range cli.Vocabulary() {
		words[t.Word] = true
	}
	codes := map[int]bool{}
	for _, r := range cli.ExitRows() {
		n, _ := strconv.Atoi(r[0])
		codes[n] = true
	}

	g := &Graph{Files: conformance.NoteDocs, Tokens: cli.Vocabulary(), Exits: cli.ExitRows()}
	for _, name := range append([]string{conformance.ClaimsNote}, otherNotes()...) {
		if n := notes[name]; n != nil {
			g.Notes = append(g.Notes, n)
		}
	}
	for _, id := range ids {
		r := rows[home[id]][id]
		c := Case{ID: id, Profile: conformance.Profile(id), DefinedIn: home[id], Status: "pending"}
		refs, _ := conformance.ParseNoteColumn(r.pins, homeNote(home[id]))
		seen := map[Pin]bool{}
		for _, ref := range refs {
			s, why := conformance.ResolveRef(ref, notes)
			if s == nil {
				problems = append(problems, id+": "+why)
				continue
			}
			p := Pin{Note: ref.Note, Section: ref.Section, Invariant: ref.Invariant}
			if ref.Example != "" {
				p.Example = s.Title
			}
			if !seen[p] {
				seen[p] = true
				c.Pins = append(c.Pins, p)
			}
		}
		for _, m := range codeSpan.FindAllStringSubmatch(r.outcome, -1) {
			// a span is a token, or "label: token" as a surface prints it (`cohort: hand-picked`)
			span := strings.TrimSpace(m[1])
			for _, w := range []string{span, span[strings.LastIndex(span, ": ")+1:]} {
				if w = strings.TrimSpace(w); words[w] && !slices.Contains(c.Tokens, w) {
					c.Tokens = append(c.Tokens, w)
				}
			}
		}
		sort.Strings(c.Tokens)
		for _, m := range exitWord.FindAllStringSubmatch(r.outcome, -1) {
			if n, _ := strconv.Atoi(m[1]); codes[n] && !slices.Contains(c.Exits, n) {
				c.Exits = append(c.Exits, n)
			}
		}
		sort.Ints(c.Exits)
		c.Tests = slices.Sorted(slices.Values(cov[id]))
		c.Remaining = slices.Sorted(slices.Values(part[id]))
		switch {
		case len(c.Tests) > 0:
			c.Status = "covered"
		case len(c.Remaining) > 0:
			c.Status = "partial"
		}
		g.Cases = append(g.Cases, c)
	}
	return g, problems, nil
}

// otherNotes is every note besides the claims-model note, by name.
func otherNotes() []string {
	var out []string
	for _, n := range conformance.SortedKeys(conformance.NoteDocs) {
		if n != conformance.ClaimsNote {
			out = append(out, n)
		}
	}
	return out
}

func (p Pin) json() object {
	o := object{{"note", p.Note}}
	switch {
	case p.Invariant != "":
		o = append(o, member{"invariant", p.Invariant})
	case p.Section != "":
		o = append(o, member{"section", p.Section})
	default:
		o = append(o, member{"example", p.Example})
	}
	return o
}

func ints(xs []int) []any {
	out := []any{}
	for _, x := range xs {
		out = append(out, x)
	}
	return out
}

func orEmpty(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

// JSON is the file's bytes.
func (g *Graph) JSON() []byte {
	var notes, cases, tokens, exits []any
	for _, n := range g.Notes {
		var secs, invs []any
		for _, k := range n.Order {
			if k != "appendix" {
				secs = append(secs, object{{"section", k}, {"title", n.Sections[k].Title}})
			}
		}
		for _, k := range n.InvOrder {
			invs = append(invs, object{{"invariant", k}, {"title", n.Invariants[k].Title}})
		}
		var ex []string
		for _, e := range n.Examples {
			ex = append(ex, e.Title)
		}
		o := object{{"note", n.Name}, {"file", g.Files[n.Name]}, {"sections", secs}}
		if len(invs) > 0 {
			o = append(o, member{"invariants", invs})
		}
		if len(ex) > 0 {
			o = append(o, member{"examples", ex})
		}
		notes = append(notes, o)
	}
	for _, c := range g.Cases {
		pins := []any{}
		for _, p := range c.Pins {
			pins = append(pins, p.json())
		}
		o := object{{"case", c.ID}, {"profile", c.Profile}, {"defined_in", c.DefinedIn}, {"pins", pins},
			{"tokens", orEmpty(c.Tokens)}, {"exits", ints(c.Exits)}, {"status", c.Status}, {"tests", orEmpty(c.Tests)}}
		if len(c.Remaining) > 0 {
			o = append(o, member{"remaining", c.Remaining})
		}
		cases = append(cases, o)
	}
	for _, t := range g.Tokens {
		tokens = append(tokens, object{{"token", t.Word}, {"kind", t.Kind}})
	}
	for _, e := range g.Exits {
		n, _ := strconv.Atoi(e[0])
		exits = append(exits, object{{"exit", n}, {"name", e[1]}})
	}
	return document(object{
		{"format", GraphFormat},
		{"about", "Generated by RC_UPDATE_DOCS=1 go test -run TestSpecGraphFile ./internal/conformance/specgraph; do not edit. " +
			"Each case with the sections, invariants and worked examples its row names (pins), the output tokens and exit codes " +
			"its required outcome names, and the tests that declare it. Sources: the case tables, the design notes' headings, " +
			"the Covers scan and the CLI's vocabulary. A pin says a row names a section; it does not say the test checks it."},
		{"notes", notes},
		{"cases", cases},
		{"tokens", tokens},
		{"exit_codes", exits},
	})
}

// Findings are answers the graph gives that a reader would otherwise count by hand. They are leads, not
// defects: a token no required outcome names in code marks may still be checked by a test, and a section no
// row names may state nothing testable.
type Findings struct {
	UnpinnedSections []string // "note §n": no case names it or a subsection of it
	OneTestCases     []string // covered by exactly one test
	UnnamedTokens    []string // vocabulary words no required outcome names
	UnnamedExits     []int
	NoPins           []string // cases whose table has no pin column or whose cell names nothing
}

// Findings reads the gaps off the graph.
func (g *Graph) Findings() Findings {
	var f Findings
	pinned := map[string]bool{}
	tok := map[string]bool{}
	ex := map[int]bool{}
	for _, c := range g.Cases {
		for _, p := range c.Pins {
			if p.Section != "" {
				pinned[p.Note+" §"+p.Section] = true
			}
		}
		for _, t := range c.Tokens {
			tok[t] = true
		}
		for _, e := range c.Exits {
			ex[e] = true
		}
		if len(c.Tests) == 1 {
			f.OneTestCases = append(f.OneTestCases, c.ID)
		}
		if len(c.Pins) == 0 {
			f.NoPins = append(f.NoPins, c.ID)
		}
	}
	for _, n := range g.Notes {
		for _, k := range n.Order {
			if k == "appendix" {
				continue
			}
			named := false
			for _, other := range n.Order {
				if (other == k || strings.HasPrefix(other, k+".")) && pinned[n.Name+" §"+other] {
					named = true
				}
			}
			if !named {
				f.UnpinnedSections = append(f.UnpinnedSections, n.Name+" §"+k)
			}
		}
	}
	for _, t := range g.Tokens {
		if !tok[t.Word] {
			f.UnnamedTokens = append(f.UnnamedTokens, t.Word)
		}
	}
	for _, e := range g.Exits {
		if n, _ := strconv.Atoi(e[0]); !ex[n] {
			f.UnnamedExits = append(f.UnnamedExits, n)
		}
	}
	return f
}
