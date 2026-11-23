package conformance

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// This file reads the `note` column of the case tables: the column that says which invariant, section or
// worked example of a design note a case pins. Two things are built on it. LintPins checks that everything a
// row names exists and that every quotation is found where the row says. CoverageMarkdown turns the same
// column into the coverage tables of CONFORMANCE.md, so those tables are an index of the rows and cannot say
// anything the rows do not.

// ClaimsNote is the note a bare `§n` in a note column refers to.
const ClaimsNote = "claims-model"

// NoteDocs maps the name a note column uses ("storage note §3.2") to the note's file, relative to the
// repository root. A row that cites a note not listed here is a lint problem: add the note to cite it.
var NoteDocs = map[string]string{
	ClaimsNote:            "docs/DESIGN-notes-claims-model.md",
	"wire-format":         "docs/DESIGN-notes-wire-format.md",
	"storage":             "docs/DESIGN-notes-storage.md",
	"execution":           "docs/DESIGN-notes-execution.md",
	"bitcoin-time":        "docs/DESIGN-notes-bitcoin-time.md",
	"task-contracts":      "docs/DESIGN-notes-task-contracts.md",
	"fixed-root identity": "docs/DESIGN-notes-fixed-root-identity.md",
}

// noteOrder is the order the coverage tables list the other notes in.
var noteOrder = []string{"wire-format", "storage", "execution", "bitcoin-time", "task-contracts", "fixed-root identity"}

// Section is one numbered section, invariant or worked example of a note. Body includes the text of its
// subsections, so a quotation pinned to §5.3 may sit in §5.3.1.
type Section struct {
	Num   string // "5.3.1a"; "I4" for an invariant; "" for a worked example
	Title string
	Body  string
}

// Note is a design note as the pin checks read it.
type Note struct {
	Name       string
	Sections   map[string]*Section
	Order      []string            // section numbers in document order
	Invariants map[string]*Section // "I4" → its bullet
	InvOrder   []string
	Examples   []*Section // the appendix's worked examples, in order
}

var (
	headingLine  = regexp.MustCompile(`^(#{1,6}) (.+)$`)
	numberedHead = regexp.MustCompile(`^(\d+(?:\.\d+)*[a-z]?)\.? (.+)$`)
	invariantRE  = regexp.MustCompile(`(?m)^- \*\*(I\d+) ([^*]+?)\.\*\*`)
	exampleRE    = regexp.MustCompile(`(?m)^\*\*([^*]+?)\.\*\*`)
)

// ParseNote reads a note's numbered headings (levels 2 to 6, outside code fences), the invariants of its §3
// (bullets that open `- **In Title.**`) and the worked examples of its appendix (paragraphs that open
// `**Title.**`). A section number used twice is returned as a problem.
func ParseNote(name string, src []byte) (*Note, []string) {
	n := &Note{Name: name, Sections: map[string]*Section{}, Invariants: map[string]*Section{}}
	var problems []string
	lines := strings.Split(string(src), "\n")
	type head struct {
		line, level int
		num, title  string
	}
	var heads []head
	fence := false
	for i, l := range lines {
		if strings.HasPrefix(l, "```") {
			fence = !fence
			continue
		}
		if fence {
			continue
		}
		m := headingLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		h := head{line: i, level: len(m[1])}
		if nm := numberedHead.FindStringSubmatch(m[2]); nm != nil && h.level >= 2 {
			h.num, h.title = nm[1], nm[2]
		} else if strings.HasPrefix(m[2], "Appendix") {
			h.num, h.title = "appendix", m[2]
		}
		heads = append(heads, h)
	}
	for k, h := range heads {
		if h.num == "" {
			continue
		}
		end := len(lines)
		for _, next := range heads[k+1:] {
			if next.level <= h.level {
				end = next.line
				break
			}
		}
		if _, dup := n.Sections[h.num]; dup {
			problems = append(problems, fmt.Sprintf("%s note: section %s is numbered twice", name, h.num))
			continue
		}
		n.Sections[h.num] = &Section{Num: h.num, Title: h.title, Body: h.title + "\n" + strings.Join(lines[h.line+1:end], "\n")}
		n.Order = append(n.Order, h.num)
	}
	if s := n.Sections["3"]; s != nil {
		for _, part := range splitAt(s.Body, invariantRE) {
			n.Invariants[part.key] = &Section{Num: part.key, Title: part.title, Body: part.body}
			n.InvOrder = append(n.InvOrder, part.key)
		}
	}
	if s := n.Sections["appendix"]; s != nil {
		for _, m := range exampleRE.FindAllStringSubmatchIndex(s.Body, -1) {
			n.Examples = append(n.Examples, &Section{Title: s.Body[m[2]:m[3]], Body: s.Body[m[0]:]})
		}
		for i := range n.Examples {
			if i+1 < len(n.Examples) {
				e, next := n.Examples[i], n.Examples[i+1]
				e.Body = e.Body[:len(e.Body)-len(next.Body)]
			}
		}
	}
	return n, problems
}

type bullet struct{ key, title, body string }

// splitAt cuts body at each match of re (two groups: key and title); a part runs to the next match or to the
// next heading line.
func splitAt(body string, re *regexp.Regexp) []bullet {
	var out []bullet
	ms := re.FindAllStringSubmatchIndex(body, -1)
	for i, m := range ms {
		end := len(body)
		if i+1 < len(ms) {
			end = ms[i+1][0]
		}
		text := body[m[0]:end]
		if h := strings.Index(text, "\n#"); h >= 0 {
			text = text[:h]
		}
		out = append(out, bullet{key: body[m[2]:m[3]], title: body[m[4]:m[5]], body: text})
	}
	return out
}

// LoadNotes parses every note in NoteDocs under root.
func LoadNotes(root string) (map[string]*Note, []string, error) {
	notes := map[string]*Note{}
	var problems []string
	for _, name := range SortedKeys(NoteDocs) {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(NoteDocs[name])))
		if err != nil {
			return nil, nil, err
		}
		n, p := ParseNote(name, b)
		notes[name] = n
		problems = append(problems, p...)
	}
	return notes, problems, nil
}

// Case is one case row: its id and its note column (the second cell).
type Case struct {
	ID   string
	Note string
}

// CaseRows returns the case rows of a document whose tables carry the note column second, in document order.
func CaseRows(doc []byte) []Case {
	var out []Case
	for _, l := range strings.Split(string(doc), "\n") {
		m := caseRow.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		cells := strings.Split(l, "|")
		if len(cells) < 4 {
			continue
		}
		out = append(out, Case{ID: m[1], Note: strings.TrimSpace(cells[2])})
	}
	return out
}

// Ref is one thing a note column names: a section of a note, an invariant or a worked example of the
// claims-model note, with the quotations the row attaches to it.
type Ref struct {
	Note      string // the note a Section belongs to
	Section   string
	Invariant string
	Example   string // the words in brackets after "appendix"
	Quotes    []string
}

func (r Ref) String() string {
	switch {
	case r.Invariant != "":
		return r.Invariant
	case r.Section != "":
		if r.Note == ClaimsNote {
			return "§" + r.Section
		}
		return r.Note + " note §" + r.Section
	default:
		return "appendix (" + r.Example + ")"
	}
}

var pinToken = func() *regexp.Regexp {
	names := SortedKeys(NoteDocs)
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for i, n := range names {
		names[i] = regexp.QuoteMeta(n)
	}
	return regexp.MustCompile(`"([^"]*)"` + // 1: a quotation
		`|\b(` + strings.Join(names, "|") + `) note\b` + // 2: a known note name
		`|\b([A-Za-z][A-Za-z-]*) note §` + // 3: a note name NoteDocs lacks
		`|§(\d+(?:\.\d+)*[a-z]?)` + // 4: a section
		`|\b(I\d+)\b` + // 5: an invariant
		`|\bappendix\b(?: \(([^()]*)\))?`) // 6: a worked example
}()

// ParseNoteColumn reads one note column whose bare `§n` belongs to the note named home. The grammar, which
// CONFORMANCE.md states for its readers:
//
//   - `§n` is a section of the home note, unless a note name comes before it in the row ("storage note §3.2,
//     §3.4"): a note name applies to every `§` after it, up to the next note name;
//   - `In` is an invariant and `appendix (words)` a worked example, both of the claims-model note;
//   - words in double quotation marks are quoted from whatever was named just before them.
//
// Everything else (brackets, glosses, case ids, issue numbers) is prose and is not read.
func ParseNoteColumn(col, home string) ([]Ref, []string) {
	var refs []Ref
	var problems []string
	cur := home
	if strings.ContainsAny(col, "“”") {
		problems = append(problems, "curly quotation marks (“ ”) are not read as a quotation; use straight ones (\")")
	}
	if strings.Count(col, `"`)%2 == 1 {
		problems = append(problems, "an odd number of quotation marks: a quotation is not closed")
	}
	for _, m := range pinToken.FindAllStringSubmatch(col, -1) {
		switch {
		case strings.HasPrefix(m[0], `"`):
			if len(refs) == 0 {
				problems = append(problems, fmt.Sprintf("quotation %q comes before any section, invariant or example", m[1]))
				continue
			}
			refs[len(refs)-1].Quotes = append(refs[len(refs)-1].Quotes, m[1])
		case m[2] != "":
			cur = m[2]
		case m[3] != "":
			problems = append(problems, fmt.Sprintf("%q is not a note the checks know (NoteDocs)", m[3]+" note"))
		case m[4] != "":
			refs = append(refs, Ref{Note: cur, Section: m[4]})
		case m[5] != "":
			refs = append(refs, Ref{Note: ClaimsNote, Invariant: m[5]})
		default:
			if m[6] == "" {
				problems = append(problems, "appendix is named without the worked example in brackets")
				continue
			}
			refs = append(refs, Ref{Note: ClaimsNote, Example: m[6]})
		}
	}
	return refs, problems
}

// resolve finds what a Ref names, or says why it names nothing.
func resolve(r Ref, notes map[string]*Note) (*Section, string) {
	n := notes[r.Note]
	if n == nil {
		return nil, "the " + r.Note + " note was not read"
	}
	switch {
	case r.Invariant != "":
		if s := n.Invariants[r.Invariant]; s != nil {
			return s, ""
		}
		return nil, "the " + r.Note + " note states no invariant " + r.Invariant
	case r.Section != "":
		if s := n.Sections[r.Section]; s != nil {
			return s, ""
		}
		return nil, "the " + r.Note + " note has no section " + r.Section
	}
	var found []*Section
	for _, e := range n.Examples {
		if strings.Contains(fold(e.Title), fold(r.Example)) {
			found = append(found, e)
		}
	}
	if len(found) == 1 {
		return found[0], ""
	}
	return nil, fmt.Sprintf("%d worked examples of the %s note are titled like %q", len(found), r.Note, r.Example)
}

// fold is the form quotations are compared in: letter case, runs of white space and markup (emphasis asterisks,
// code backticks) do not count. Every word and every other mark does.
func fold(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(markup.Replace(s))), " ")
}

var markup = strings.NewReplacer("*", "", "`", "")

// MaxOmitted is the most words a "…" in a quotation may stand for. An omission is a few words left out of one
// sentence; without a limit two words anywhere in a section, in order, would pass as a quotation of it.
const MaxOmitted = 20

// quoted reports whether q is found in body: its parts, split at each "…", in order, each on word boundaries
// (a part never starts or ends inside a word of the note), with at most MaxOmitted words between one part and
// the next. A quotation with an empty part ("…" first, last or doubled) or no words at all is not found.
func quoted(q, body string) bool {
	text := fold(body)
	var parts []string
	for _, part := range strings.Split(q, "…") {
		p := fold(part)
		if p == "" {
			return false
		}
		parts = append(parts, p)
	}
	return quotedFrom(text, parts, 0, false)
}

// quotedFrom tries every place parts[0] is found at or after from. With bounded set, parts[0] must begin within
// MaxOmitted words of from. Every place is tried because the first one may be the wrong one: the words before
// an omission can occur earlier in the section too.
func quotedFrom(text string, parts []string, from int, bounded bool) bool {
	p := parts[0]
	for at := from; ; {
		i := strings.Index(text[at:], p)
		if i < 0 {
			return false
		}
		start, end := at+i, at+i+len(p)
		if bounded && len(strings.Fields(text[from:start])) > MaxOmitted {
			return false
		}
		if wordEdge(text, start, true) && wordEdge(text, end, false) &&
			(len(parts) == 1 || quotedFrom(text, parts[1:], end, true)) {
			return true
		}
		at = start + 1
	}
}

// wordEdge reports whether position i of text does not split a word: at the start of a part, the character
// before it and the character at it are not both letters or digits; likewise at its end.
func wordEdge(text string, i int, start bool) bool {
	if i <= 0 || i >= len(text) {
		return true
	}
	before, _ := utf8.DecodeLastRuneInString(text[:i])
	after, _ := utf8.DecodeRuneInString(text[i:])
	word := func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }
	return !(word(before) && word(after))
}

// LintPins checks every case's note column: each section, invariant and worked example named exists, and each
// quotation is found in what it is attached to. The problems name the case.
func LintPins(cases []Case, notes map[string]*Note, home string) []string {
	var problems []string
	for _, c := range cases {
		refs, ps := ParseNoteColumn(c.Note, home)
		for _, p := range ps {
			problems = append(problems, c.ID+": "+p)
		}
		for _, r := range refs {
			s, why := resolve(r, notes)
			if s == nil {
				problems = append(problems, c.ID+": "+why)
				continue
			}
			for _, q := range r.Quotes {
				if !quoted(q, s.Body) {
					problems = append(problems, fmt.Sprintf("%s: %q is not in %s (a quotation is whole words of the note, exact apart from letter case, line breaks and markup; … stands for at most %d omitted words; drop the quotation marks for a paraphrase)", c.ID, q, r, MaxOmitted))
				}
			}
		}
	}
	return problems
}

var caseParts = regexp.MustCompile(`^(?:C-([a-z]+)|(P))-([0-9]+)([a-z]?)$`)

// caseLess orders case ids by scope (core, exec, exch, btc, id, properties), number and letter.
func caseLess(a, b string) bool {
	rank := map[string]int{"core": 0, "exec": 1, "exch": 2, "btc": 3, "id": 4, "": 5}
	pa, pb := caseParts.FindStringSubmatch(a), caseParts.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		return a < b
	}
	if rank[pa[1]] != rank[pb[1]] {
		return rank[pa[1]] < rank[pb[1]]
	}
	na, _ := strconv.Atoi(pa[3])
	nb, _ := strconv.Atoi(pb[3])
	if na != nb {
		return na < nb
	}
	return pa[4] < pb[4]
}

// CoverageStart and CoverageEnd bound the generated part of CONFORMANCE.md: from the first line up to, and
// not including, the second.
const (
	CoverageStart = "## Coverage\n"
	CoverageEnd   = "### Alpha findings carried as requirements (#74)\n"
)

// CoverageMarkdown builds the coverage tables from the case rows: for each invariant, section and worked
// example, the cases whose note column names it. A name that does not resolve is left out (LintPins reports
// it).
func CoverageMarkdown(cases []Case, notes map[string]*Note) string {
	by := map[*Section][]string{}
	for _, c := range cases {
		refs, _ := ParseNoteColumn(c.Note, ClaimsNote)
		seen := map[*Section]bool{}
		for _, r := range refs {
			if s, _ := resolve(r, notes); s != nil && !seen[s] {
				seen[s] = true
				by[s] = append(by[s], c.ID)
			}
		}
	}
	row := func(b *strings.Builder, label string, s *Section) {
		ids := by[s]
		sort.SliceStable(ids, func(i, j int) bool { return caseLess(ids[i], ids[j]) })
		fmt.Fprintf(b, "| %s | %s |\n", label, strings.Join(ids, ", "))
	}
	claims := notes[ClaimsNote]
	var b strings.Builder
	b.WriteString(CoverageStart + "\n")
	b.WriteString("These tables are generated from the `note` column of the case tables above, by\n")
	b.WriteString("`RC_UPDATE_DOCS=1 go test -run TestCoverageTables ./internal/conformance`. Do not edit them by hand: a test\n")
	b.WriteString("fails when they and the rows differ. A case is listed under each invariant, section and worked example its\n")
	b.WriteString("row names, and nowhere else. The titles are the notes' own. Cases a profile note defines are not listed.\n\n")
	b.WriteString("### Invariants\n\n| invariant | cases |\n|---|---|\n")
	for _, k := range claims.InvOrder {
		row(&b, k+" "+claims.Invariants[k].Title, claims.Invariants[k])
	}
	b.WriteString("\n### Sections of the claims-model note\n\n| section | cases |\n|---|---|\n")
	// A section no row names is reported only when no row names one of its subsections either.
	named := func(k string) bool {
		for _, other := range claims.Order {
			if (other == k || strings.HasPrefix(other, k+".")) && len(by[claims.Sections[other]]) > 0 {
				return true
			}
		}
		return false
	}
	var unnamed []string
	for _, k := range claims.Order {
		s := claims.Sections[k]
		switch {
		case k == "appendix":
		case len(by[s]) > 0:
			row(&b, "§"+k+" "+s.Title, s)
		case k != "3" && !named(k):
			unnamed = append(unnamed, "§"+k)
		}
	}
	for _, e := range claims.Examples {
		if len(by[e]) > 0 {
			row(&b, "appendix: "+e.Title, e)
		}
	}
	if len(unnamed) > 0 {
		b.WriteString("\nNo row names " + strings.Join(unnamed, ", ") + ", or a subsection of one. §3 is the invariants, listed above.\n")
	}
	b.WriteString("\n### Sections of the other notes\n\n| section | cases |\n|---|---|\n")
	for _, name := range noteOrder {
		n := notes[name]
		if n == nil {
			continue
		}
		for _, k := range n.Order {
			if s := n.Sections[k]; len(by[s]) > 0 {
				row(&b, name+" note §"+k+" "+s.Title, s)
			}
		}
	}
	b.WriteString("\n")
	return b.String()
}

// SpliceCoverage returns doc with its generated part replaced by generated, and false when doc lacks the two
// bounding lines in order.
func SpliceCoverage(doc, generated string) (string, bool) {
	i := strings.Index(doc, "\n"+CoverageStart)
	if i < 0 {
		return doc, false
	}
	i++
	j := strings.Index(doc[i:], "\n"+CoverageEnd)
	if j < 0 {
		return doc, false
	}
	return doc[:i] + generated + doc[i+j+1:], true
}

var caseMention = regexp.MustCompile(`\b(C-(?:core|exec|exch|btc|id)-[0-9]+[a-z]?|P-[0-9]+)\b`)

// CaseMentions returns every case id written in text, in order, repeats included.
func CaseMentions(text []byte) []string {
	var out []string
	for _, m := range caseMention.FindAll(text, -1) {
		out = append(out, string(m))
	}
	return out
}
