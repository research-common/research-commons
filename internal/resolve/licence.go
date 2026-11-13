package resolve

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
)

// The licence disclosure (claims-model note §7: "missing or unparsable means unknown, not open"; C-core-67).
//
// `licence` is an SPDX license expression (SPDX 3.0.1 Annex B, the grammar of SPDX 2.3 Annex D): identifiers,
// `+`, `WITH`, `AND`, `OR`, parentheses, and the user-defined `LicenseRef-` / `DocumentRef-…:LicenseRef-…`.
// The parser here is syntactic only: it ships no copy of the SPDX License List (the tool bundles no list and
// downloads none), so a syntactically valid identifier it cannot place is shown as written and marked unchecked,
// never refused and never rewritten. An expression that does not parse reads `unknown`; it is never read as open
// and no default text is written in its place.

// MaxLicenceBytes bounds the expression the parser reads, and MaxLicenceDepth its parenthesis nesting. Past
// either the expression reads unparsable, naming the bound (no unbounded recursion on peer text).
const (
	MaxLicenceBytes = 1024
	MaxLicenceDepth = 32
)

// Citation states of a `LicenseRef-` id (claims-model note §7, wire-format note §5 `licence_texts`).
const (
	CitedTextHeld     = "cited (text held)"
	CitedTextNotHeld  = "cited (text not held)"
	CitedLocationOnly = "cited (location only, unverified)"
	CitedNoSource     = "cited (no source)"
)

// LicenceChecked is said beside every parsed expression: the syntax was checked, the identifiers were not.
const LicenceChecked = "syntax valid; identifiers not checked against the SPDX License List"

// LicenceRef is one user-defined licence reference an expression uses and where its text is cited from.
type LicenceRef struct {
	ID       string // as written, e.g. `LicenseRef-X` or `DocumentRef-d:LicenseRef-X`
	Source   string // the licence_texts entry: a digest or a location; "" when none
	Citation string // one of the Cited* constants
}

// Licence is the reader's reading of a declared licence: the expression as written, whether it parses, and the
// citation of every `LicenseRef-` it names.
type Licence struct {
	Expr  string
	Valid bool
	Why   string // why it does not parse; "" when Valid
	Refs  []LicenceRef
	// Display is the one-line reading: the expression with its syntax note, or `unknown (…)`.
	Display string
}

var (
	reLicTok  = regexp.MustCompile(`^[A-Za-z0-9.\-:]+`)
	reIDSt    = regexp.MustCompile(`^[A-Za-z0-9.\-]+$`)
	reScheme  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*:[^\s]+$`)
	licOpWord = map[string]string{"AND": "AND", "and": "AND", "OR": "OR", "or": "OR", "WITH": "WITH", "with": "WITH"}
)

type licTok struct {
	kind  byte // '(' ')' 'w' (a word: id, ref or operator)
	text  string
	space bool // whitespace before it
	pos   int
}

type licParser struct {
	toks  []licTok
	i     int
	refs  []string
	depth int
}

// ParseLicence parses an SPDX license expression. It returns the references the expression names (in order of
// first use, as written) or an error saying why it does not parse.
func ParseLicence(expr string) ([]string, error) {
	if len(expr) > MaxLicenceBytes {
		return nil, fmt.Errorf("longer than the %d-byte bound on a licence expression", MaxLicenceBytes)
	}
	if expr == "" {
		return nil, fmt.Errorf("empty")
	}
	var toks []licTok
	space := false
	for i := 0; i < len(expr); {
		c := expr[i]
		switch {
		case c == ' ' || c == '\t':
			space = true
			i++
		case c == '(' || c == ')':
			toks = append(toks, licTok{kind: c, text: string(c), space: space, pos: i})
			space = false
			i++
		case reLicTok.MatchString(expr[i:]):
			w := reLicTok.FindString(expr[i:])
			j := i + len(w)
			if j < len(expr) && expr[j] == '+' { // `+` binds to the id before it, with no whitespace between
				w += "+"
				j++
			}
			toks = append(toks, licTok{kind: 'w', text: w, space: space, pos: i})
			space = false
			i = j
		default:
			return nil, fmt.Errorf("character %q at offset %d is not part of an SPDX license expression", firstRune(expr[i:]), i)
		}
	}
	p := &licParser{toks: toks}
	if err := p.or(); err != nil {
		return nil, err
	}
	if p.i != len(p.toks) {
		return nil, p.errAt("unexpected %q", p.toks[p.i].text)
	}
	return p.refs, nil
}

func firstRune(s string) string {
	for _, r := range s {
		return string(r)
	}
	return ""
}

func (p *licParser) errAt(format string, a ...any) error {
	at := "end of the expression"
	if p.i < len(p.toks) {
		at = fmt.Sprintf("offset %d", p.toks[p.i].pos)
	}
	return fmt.Errorf("%s at %s", fmt.Sprintf(format, a...), at)
}

func (p *licParser) peek() *licTok {
	if p.i < len(p.toks) {
		return &p.toks[p.i]
	}
	return nil
}

// op reports the operator the next token is (AND, OR, WITH), "" when it is not one; a mixed-case operator word
// is reported as an error by the caller, because the case rule leaves it neither an operator nor an identifier.
func (p *licParser) op() (string, error) {
	t := p.peek()
	if t == nil || t.kind != 'w' {
		return "", nil
	}
	if o, ok := licOpWord[t.text]; ok {
		return o, nil
	}
	switch strings.ToUpper(t.text) {
	case "AND", "OR", "WITH":
		return "", p.errAt("operator %q must be all upper case or all lower case", t.text)
	}
	return "", nil
}

// needSpace checks the whitespace rule around an operator: on both sides, whitespace or a parenthesis (WITH:
// whitespace only, which the grammar's operands force anyway).
func (p *licParser) needSpace(o string) error {
	t := p.toks[p.i]
	prev := p.toks[p.i-1]
	if !t.space && prev.kind != ')' && prev.kind != '(' || (o == "WITH" && !t.space) {
		return p.errAt("%s needs whitespace before it", o)
	}
	if p.i+1 < len(p.toks) {
		n := p.toks[p.i+1]
		if !n.space && n.kind == 'w' || (o == "WITH" && !n.space) {
			return p.errAt("%s needs whitespace after it", o)
		}
	}
	return nil
}

func (p *licParser) or() error {
	if err := p.and(); err != nil {
		return err
	}
	for {
		o, err := p.op()
		if err != nil {
			return err
		}
		if o != "OR" {
			return nil
		}
		if err := p.needSpace(o); err != nil {
			return err
		}
		p.i++
		if err := p.and(); err != nil {
			return err
		}
	}
}

func (p *licParser) and() error {
	if err := p.primary(); err != nil {
		return err
	}
	for {
		o, err := p.op()
		if err != nil {
			return err
		}
		if o != "AND" {
			return nil
		}
		if err := p.needSpace(o); err != nil {
			return err
		}
		p.i++
		if err := p.primary(); err != nil {
			return err
		}
	}
}

// primary is a parenthesised expression, or a simple expression with an optional `WITH` addition.
func (p *licParser) primary() error {
	t := p.peek()
	if t == nil {
		return p.errAt("an expression is missing")
	}
	if t.kind == '(' {
		if p.depth++; p.depth > MaxLicenceDepth {
			return fmt.Errorf("parentheses nested deeper than the %d-level bound", MaxLicenceDepth)
		}
		p.i++
		if err := p.or(); err != nil {
			return err
		}
		if c := p.peek(); c == nil || c.kind != ')' {
			return p.errAt("missing `)`")
		}
		p.i++
		p.depth--
		return nil
	}
	if t.kind == ')' {
		return p.errAt("unexpected `)`")
	}
	if o, err := p.op(); err != nil {
		return err
	} else if o != "" {
		return p.errAt("operator %s where an identifier is needed", o)
	}
	if err := p.simple(t.text); err != nil {
		return err
	}
	p.i++
	o, err := p.op()
	if err != nil {
		return err
	}
	if o != "WITH" {
		return nil
	}
	if err := p.needSpace(o); err != nil {
		return err
	}
	p.i++
	a := p.peek()
	if a == nil || a.kind != 'w' {
		return p.errAt("WITH needs an exception identifier")
	}
	if o, err := p.op(); err != nil {
		return err
	} else if o != "" {
		return p.errAt("operator %s where an exception identifier is needed", o)
	}
	if strings.HasSuffix(a.text, "+") || strings.HasPrefix(a.text, "LicenseRef-") || strings.HasPrefix(a.text, "DocumentRef-") && strings.Contains(a.text, ":LicenseRef-") {
		return p.errAt("%q is not an exception identifier", a.text)
	}
	if err := checkAddition(a.text); err != nil {
		return p.errAt("%v", err)
	}
	p.i++
	return nil
}

// simple checks a license-id, `license-id+`, or a license-ref; a ref is recorded.
func (p *licParser) simple(w string) error {
	if strings.HasPrefix(w, "LicenseRef-") {
		return p.ref(w, "LicenseRef-")
	}
	if strings.HasPrefix(w, "DocumentRef-") || strings.HasPrefix(strings.ToLower(w), "licenseref-") {
		return p.ref(w, "LicenseRef-")
	}
	id := strings.TrimSuffix(w, "+")
	if !reIDSt.MatchString(id) {
		return fmt.Errorf("%q is not an identifier", w)
	}
	return nil
}

func (p *licParser) ref(w, kind string) error {
	if strings.HasSuffix(w, "+") {
		return fmt.Errorf("`+` cannot follow a user-defined reference (%q)", w)
	}
	local := w
	if strings.HasPrefix(w, "DocumentRef-") {
		doc, rest, ok := strings.Cut(w, ":")
		if !ok || !reIDSt.MatchString(strings.TrimPrefix(doc, "DocumentRef-")) || strings.TrimPrefix(doc, "DocumentRef-") == "" {
			return fmt.Errorf("%q: a DocumentRef-<id> prefix needs `:%s<id>` after it", w, kind)
		}
		local = rest
	}
	if !strings.HasPrefix(local, kind) {
		return fmt.Errorf("%q is not a valid user-defined reference (the prefix %s is case-sensitive)", w, kind)
	}
	if rest := strings.TrimPrefix(local, kind); rest == "" || !reIDSt.MatchString(rest) {
		return fmt.Errorf("%q has no identifier after %s", w, kind)
	}
	p.addRef(w)
	return nil
}

func (p *licParser) addRef(w string) {
	for _, r := range p.refs {
		if r == w {
			return
		}
	}
	p.refs = append(p.refs, w)
}

func checkAddition(w string) error {
	if strings.HasPrefix(w, "AdditionRef-") && strings.TrimPrefix(w, "AdditionRef-") == "" {
		return fmt.Errorf("%q has no identifier after AdditionRef-", w)
	}
	if !reIDSt.MatchString(w) {
		return fmt.Errorf("%q is not an exception identifier", w)
	}
	return nil
}

// licence builds the licence reading from the licence and licence_texts fields. nil when the field has no
// default value (absent, contested or no default: the field's own state says so).
func (r *Resolver) licence(a *Artifact) *Licence {
	v, ok := a.Field("licence").Default()
	if !ok {
		return nil
	}
	x, err := canon.Parse([]byte(v))
	s, isStr := x.(canon.String)
	if err != nil || !isStr {
		l := &Licence{Why: "not a string"}
		l.Display = "unknown (the declared licence is not a string, so it is not an SPDX license expression)"
		return l
	}
	l := &Licence{Expr: string(s)}
	refs, perr := ParseLicence(l.Expr)
	if perr != nil {
		l.Why = "not an SPDX license expression: " + perr.Error()
		l.Display = "unknown (" + l.Why + ")"
		return l
	}
	l.Valid = true
	texts := parseObj(func() string { s, _ := a.Field("licence_texts").Default(); return s }())
	for _, id := range refs {
		ref := LicenceRef{ID: id, Citation: CitedNoSource}
		if texts != nil {
			if src, ok := texts.Members[id].(canon.String); ok {
				ref.Source = string(src)
				switch {
				case reDigestForm.MatchString(ref.Source) && r.obs.blobs.Has(ref.Source):
					ref.Citation = CitedTextHeld
				case reDigestForm.MatchString(ref.Source):
					ref.Citation = CitedTextNotHeld
				case reScheme.MatchString(ref.Source):
					ref.Citation = CitedLocationOnly
				}
			}
		}
		l.Refs = append(l.Refs, ref)
	}
	l.Display = l.Expr + " (" + LicenceChecked
	for _, ref := range l.Refs {
		l.Display += "; " + ref.ID + " " + ref.Citation
	}
	l.Display += ")"
	return l
}
