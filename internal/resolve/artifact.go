package resolve

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// Authorship, priority and single-party defaults for one blob (claims-model note §5.1, §5.2).
//
// A claim is one key's `authored` statements on the blob. The same key's later `authored` on the same blob
// (a descendant in its log) amends the earlier one (C-core-11): the claim's fields come from its current
// statements, the ones no later statement of the key on the blob amends; its time bound is the best bound of
// any of them, so an amendment never costs the claim its priority.
//
// Claims form units. Claims whose current statements carry the same provenance (workflow hash and input hashes)
// are one unit, a derivation group (§5.2): priority is never computed inside it. A claim without provenance is
// a unit of its own. With one unit there is nothing to rank. With several, the unit whose bound is strictly
// earlier than every rival's at a quality the reader verified (§10) is the default, and the rest are later
// claimants; otherwise the state is `contested`, every claimant is listed and no single-party field defaults
// (C-core-18, C-btc-02). Inside a unit, a field defaults by agreement; two declared values differ → that
// field alone is `contested` (C-core-27).
//
// Statements by other keys that do not claim authorship (`holds`, `describes`, `refutes`, `reproduced`) are
// listed beside the artifact, attributed to their signers, and are inputs to no default (C-core-05, I7).

// AuthorshipState is the authorship answer for a blob.
type AuthorshipState string

const (
	// NoClaim: no counted `authored` statement for the blob is held.
	NoClaim AuthorshipState = "no authorship claim"
	// SoleAuthor: one unit, one key (§5.2 (1)).
	SoleAuthor AuthorshipState = "sole author"
	// Derived: one unit, a derivation group of two or more keys (§5.2, derivation groups).
	Derived AuthorshipState = "derived"
	// Priority: several units, one strictly earliest at a verified quality (§5.2 (2)).
	Priority AuthorshipState = "default author"
	// ContestedAuthorship: several units and none strictly earliest at a verified quality (§5.2 (3)).
	ContestedAuthorship AuthorshipState = "contested"
)

// SingleParty lists the single-party fields of `authored` (claims §5.1; wire §5 disclosures, `type`, lineage).
var SingleParty = []string{"attribution", "availability", "comparator", "description", "extends", "fulfills",
	"intended_for", "licence", "licence_texts", "pre_registration", "replication", "sampling", "shelf_life_days",
	"supersedes", "type"}

// Disclosures are the single-party fields shown beside the grade on every surface, declared or not (claims
// §7, I6, C-core-66). The observation, hub and task disclosures (capture evidence, corroboration, selection,
// referent status, finality) belong to views not built yet.
var Disclosures = []string{"availability", "licence", "pre_registration", "replication", "sampling", "shelf_life_days"}

// absentToken is what a missing field displays: a missing licence is `unknown`, never open (C-core-67);
// every other missing disclosure is `undeclared` (§7: missing pre-registration is undeclared, not exploratory).
func absentToken(name string) string {
	if name == "licence" {
		return "unknown"
	}
	return "undeclared"
}

// Claim is one key's authorship claim on the blob.
type Claim struct {
	Signer string
	// Statements are every `authored` by Signer on the blob that counts, by seq then id.
	Statements []string
	// Current are the counted statements no later one of the same key on the blob amends, sorted. Two on an
	// uncleared fork of the key's log are both current.
	Current []string
	// Amends maps an amending statement to the earlier ones it amends (C-core-11).
	Amends map[string][]string
	// Provenance is the current statements' provenance; nil without one. Current statements that disagree on
	// provenance are separate claims (one per provenance).
	Provenance *Provenance
	Bound      Bound
	current    []*wire.Statement
}

// NotCounted is an `authored` on the blob that counts toward nothing, with why.
type NotCounted struct {
	Statement, Signer, Why string
}

// Provenance is a derivation's workflow and input hashes (wire §5 `provenance`, environment excluded).
type Provenance struct {
	Workflow string
	Inputs   []string // order preserved
}

func (p *Provenance) key() string {
	if p == nil {
		return ""
	}
	return p.Workflow + "<-" + strings.Join(p.Inputs, ",")
}

func (p *Provenance) String() string {
	in := make([]string, len(p.Inputs))
	for i, x := range p.Inputs {
		in[i] = shortDigest(x)
	}
	return "wf-" + shortDigest(p.Workflow) + " on [" + strings.Join(in, ",") + "]"
}

// Unit is a set of claims priority treats as one: a derivation group, or one claim without provenance.
type Unit struct {
	Provenance *Provenance
	Claims     []*Claim // by signer
	Bound      Bound
}

func (u *Unit) signers() string {
	s := make([]string, len(u.Claims))
	for i, c := range u.Claims {
		s[i] = shortKey(c.Signer)
	}
	return strings.Join(s, ",")
}

func (u *Unit) describe() string {
	if u.Provenance == nil {
		return shortKey(u.Claims[0].Signer)
	}
	return u.signers() + " under " + u.Provenance.String()
}

// Source is one signed value of a single-party field.
type Source struct {
	Value     string // canonical JSON
	Signer    string
	Statement string
}

// FieldState is the state of one single-party field.
type FieldState string

const (
	FieldDefault   FieldState = "default"
	FieldContested FieldState = "contested"
	FieldAbsent    FieldState = "undeclared"
	// FieldNoDefault: authorship itself is contested, so no claimant's value is the default (C-btc-02).
	FieldNoDefault FieldState = "no default (authorship contested)"
)

// Field is the resolved single-party field.
type Field struct {
	Name  string
	State FieldState
	// From are the default unit's values: one value from one or more signers when Default, several values
	// when Contested.
	From []Source
	// Rivals are values from claimants outside the default unit, listed with their signers, never dropped.
	Rivals []Source
}

// Default returns the field's default value (canonical JSON) and whether it has one.
func (f Field) Default() (string, bool) {
	if f.State != FieldDefault {
		return "", false
	}
	return f.From[0].Value, true
}

// Artifact is the view of one blob.
type Artifact struct {
	Digest     string
	State      AuthorshipState
	Claims     []*Claim // every counted claim, by signer then provenance
	NotCounted []NotCounted
	Units      []*Unit
	Default    *Unit   // nil when contested or unclaimed
	Later      []*Unit // later claimants, when a default exists by priority
	Fields     []Field // SingleParty order
	// Holders are the keys whose current `holds` for the blob does not withdraw it, sorted.
	Holders []string
	// Held lists every other statement about the blob or its claims, attributed: describes, refutes, retracts,
	// reproduced across workflows. Shown beside the artifact; inputs to no default.
	Held []*Placed
	// Groups are the derivation groups of every claimant unit with provenance, whatever the authorship state.
	// Group is the one this blob's step comes from: the strongest evidence any of them holds for these bytes
	// (see grade), the default unit's on a tie. Nil when no claimant has provenance.
	Groups []*Group
	Group  *Group
	// Grade is the chain grade (weakest derivation step, §7); Step is this blob's own step.
	Grade, Step Grade
	// RestsOn summarises the leaves under the chain (§7, scoped summary).
	RestsOn []string
	// Selection is the reader's authorship-declaration selection for the blob (policy.go); nil without one.
	Selection *Selected
	Explain   []string
}

// Artifact resolves the view of the blob with content digest d ("sha256:" + hex).
func (r *Resolver) Artifact(d string) *Artifact {
	return r.artifact(d, map[string]bool{})
}

func (r *Resolver) artifact(d string, visiting map[string]bool) *Artifact {
	a := r.authorship(d)
	r.grade(a, visiting)
	return a
}

// authorship computes everything but the grade: claims, units, priority, fields, holders, held statements.
func (r *Resolver) authorship(d string) *Artifact {
	a := &Artifact{Digest: d}
	byKey := map[string][]*Placed{}
	for _, p := range r.byKind["authored"] {
		if contentDigest(p.St.Body) != d {
			continue
		}
		if !p.Counts() {
			a.NotCounted = append(a.NotCounted, NotCounted{p.St.ID, p.St.Signer, notCountedWhy(p)})
			continue
		}
		byKey[p.St.Signer] = append(byKey[p.St.Signer], p)
	}
	slices.SortFunc(a.NotCounted, func(x, y NotCounted) int { return strings.Compare(x.Signer+x.Statement, y.Signer+y.Statement) })
	for _, k := range sortedKeys(byKey) {
		a.Claims = append(a.Claims, r.claims(k, byKey[k])...)
	}

	units := map[string]*Unit{}
	for _, c := range a.Claims {
		uk := "key:" + c.Signer + "|" + c.Provenance.key()
		if c.Provenance != nil {
			uk = "prov:" + c.Provenance.key()
		}
		u, ok := units[uk]
		if !ok {
			u = &Unit{Provenance: c.Provenance, Bound: Bound{Quality: NoBound}}
			units[uk] = u
		}
		u.Claims = append(u.Claims, c)
		u.Bound = better(u.Bound, c.Bound)
	}
	for _, k := range sortedKeys(units) {
		a.Units = append(a.Units, units[k])
	}

	switch len(a.Units) {
	case 0:
		a.State = NoClaim
		a.Explain = append(a.Explain, "no counted authored statement for this blob is held")
	case 1:
		a.Default = a.Units[0]
		if a.Default.Provenance != nil && len(a.Default.Claims) > 1 {
			a.State = Derived
			a.Explain = append(a.Explain, "one derivation group ("+a.Default.Provenance.String()+"): priority is not computed within a derivation group (claims §5.2)")
		} else {
			a.State = SoleAuthor
		}
	default:
		r.priority(a)
	}
	a.Fields = r.fields(a)
	r.selectDefaults(a) // the reader's authorship-declaration selection, if any (policy.go)
	a.Explain = append(a.Explain, forked(a)...)
	a.Holders = r.holders(d)
	a.Held = r.held(a)
	return a
}

// claims builds key k's claims on the blob from its counted `authored` statements: one per provenance among
// its current statements.
func (r *Resolver) claims(k string, ps []*Placed) []*Claim {
	slices.SortFunc(ps, func(x, y *Placed) int { return cmpSeq(x.St, y.St) })
	amends := map[string][]string{}
	var current []*wire.Statement
	for _, p := range ps {
		amended := false
		for _, q := range ps {
			if r.precedes(k, p.St.ID, q.St.ID) {
				amended = true
				amends[q.St.ID] = append(amends[q.St.ID], p.St.ID)
			}
		}
		if !amended {
			current = append(current, p.St)
		}
	}
	byProv := map[string]*Claim{}
	for _, st := range current {
		pv := provenance(st.Body)
		c, ok := byProv[pv.key()]
		if !ok {
			c = &Claim{Signer: k, Provenance: pv, Amends: map[string][]string{}, Bound: Bound{Quality: NoBound}}
			byProv[pv.key()] = c
		}
		c.Current = append(c.Current, st.ID)
		c.current = append(c.current, st)
	}
	var out []*Claim
	for _, pk := range sortedKeys(byProv) {
		c := byProv[pk]
		// every counted statement of the key on the blob that the claim's current statements amend, plus
		// themselves; its bound is the best of them
		for _, p := range ps {
			mine := slices.Contains(c.Current, p.St.ID)
			for _, cur := range c.Current {
				mine = mine || r.precedes(k, p.St.ID, cur)
			}
			if mine {
				c.Statements = append(c.Statements, p.St.ID)
				c.Bound = better(c.Bound, r.bound(p.St))
				if am, ok := amends[p.St.ID]; ok {
					c.Amends[p.St.ID] = am
				}
			}
		}
		slices.Sort(c.Current)
		out = append(out, c)
	}
	return out
}

// priority ranks several units (§5.2 (2), (3); bitcoin-time note §8.3).
func (r *Resolver) priority(a *Artifact) {
	for _, u := range a.Units {
		wins := true
		for _, v := range a.Units {
			if u == v {
				continue
			}
			if ok, _ := earlier(u.Bound, v.Bound); !ok {
				wins = false
			}
		}
		if wins {
			a.Default = u
		}
	}
	for _, u := range a.Units {
		a.Explain = append(a.Explain, fmt.Sprintf("claimant %s: bound %s", u.describe(), u.Bound))
	}
	if a.Default == nil {
		a.State = ContestedAuthorship
		for i, u := range a.Units {
			for _, v := range a.Units[i+1:] {
				_, why := earlier(u.Bound, v.Bound)
				if why == "later" {
					_, why = earlier(v.Bound, u.Bound)
				}
				a.Explain = append(a.Explain, fmt.Sprintf("%s vs %s: %s", u.describe(), v.describe(), why))
			}
		}
		a.Explain = append(a.Explain, "no claimant is strictly earliest at a quality this reader verified; local quality does not rank (claims §10)")
		return
	}
	a.State = Priority
	for _, u := range a.Units {
		if u != a.Default {
			a.Later = append(a.Later, u)
			_, why := earlier(a.Default.Bound, u.Bound)
			a.Explain = append(a.Explain, fmt.Sprintf("later claimant %s (%s); priority is credit for publishing first, not evidence of copying (claims §5.2)", u.describe(), why))
		}
	}
}

// forked explains a key whose log is forked and which holds two current `authored` on the blob, one per
// branch (claims §5.1, a forked log; decisions A3). The reader reads every branch: nothing is frozen at the fork.
// When they disagree, a field (same provenance) or the authorship (two provenances) is contested, and clearing
// the fork with `merges` alone does not choose: an `authored` whose history holds both branches amends both.
func forked(a *Artifact) []string {
	cur := map[string][]string{}
	for _, c := range a.Claims {
		cur[c.Signer] = append(cur[c.Signer], c.Current...)
	}
	var out []string
	for _, k := range sortedKeys(cur) {
		if ids := cur[k]; len(ids) > 1 {
			slices.Sort(ids)
			out = append(out, fmt.Sprintf("%s holds %d current authored on this blob on separate branches of its log (%s): every branch counts, and nothing is frozen at the fork; "+
				"a field or provenance they disagree on stays contested until one authored whose history holds both branches amends them (a merge that is not an authored amends nothing)",
				shortKey(k), len(ids), shorts(ids)))
		}
	}
	return out
}

// fields resolves every single-party field.
func (r *Resolver) fields(a *Artifact) []Field {
	var out []Field
	for _, name := range SingleParty {
		f := Field{Name: name}
		var mine, rivals []Source
		for _, u := range a.Units {
			for _, c := range u.Claims {
				for _, st := range c.current {
					v, ok := st.Body.Get(name)
					if !ok {
						continue
					}
					s := Source{Value: string(canon.Encode(v)), Signer: c.Signer, Statement: st.ID}
					if u == a.Default {
						mine = append(mine, s)
					} else {
						rivals = append(rivals, s)
					}
				}
			}
		}
		sortSources(mine)
		sortSources(rivals)
		f.Rivals = rivals
		switch {
		case a.Default == nil && len(a.Units) > 1:
			f.State = FieldNoDefault
		case len(mine) == 0:
			f.State = FieldAbsent
		case distinctValues(mine) > 1:
			f.State = FieldContested
		default:
			f.State = FieldDefault
		}
		f.From = mine
		out = append(out, f)
	}
	return out
}

// Field returns the named single-party field.
func (a *Artifact) Field(name string) Field {
	for _, f := range a.Fields {
		if f.Name == name {
			return f
		}
	}
	return Field{Name: name, State: FieldAbsent}
}

// holders lists the keys serving the blob: a key's current `holds` for the digest is the one no later `holds`
// of the same key for the same digest follows in its log (wire §5); it serves unless that one withdraws. On an
// uncleared fork two current statements may disagree; the key is listed if either serves.
func (r *Resolver) holders(d string) []string {
	byKey := map[string][]*Placed{}
	for _, p := range r.byKind["holds"] {
		if p.Counts() && contentDigest(p.St.Body) == d {
			byKey[p.St.Signer] = append(byKey[p.St.Signer], p)
		}
	}
	var out []string
	for _, k := range sortedKeys(byKey) {
		for _, p := range byKey[k] {
			later := false
			for _, q := range byKey[k] {
				later = later || r.precedes(k, p.St.ID, q.St.ID)
			}
			if _, w := p.St.Body.Get("withdrawn"); !later && !w {
				out = append(out, k)
				break
			}
		}
	}
	return out
}

// held lists the statements about the blob or its claims that are not claims: describes, refutes, retracts,
// and reproduced statements that link a claim under another provenance (#22, C-core-26).
func (r *Resolver) held(a *Artifact) []*Placed {
	claimIDs := map[string]*Claim{}
	for _, c := range a.Claims {
		for _, id := range c.Statements {
			claimIDs[id] = c
		}
	}
	var out []*Placed
	for _, kind := range []string{"describes", "refutes", "retracts", "reproduced"} {
		for _, p := range r.byKind[kind] {
			if !p.EvidenceReady() {
				continue
			}
			b := p.St.Body
			switch kind {
			case "describes":
				about, _ := b.Get("about")
				ao := about.(*canon.Object)
				if str(ao, "content") == a.Digest || claimIDs[str(ao, "statement")] != nil {
					out = append(out, p)
				}
			case "refutes", "retracts":
				if claimIDs[str(b, "of")] != nil {
					out = append(out, p)
				}
			case "reproduced":
				if c := claimIDs[str(b, "of")]; c != nil && provenance(b).key() != c.Provenance.key() {
					out = append(out, p)
				}
			}
		}
	}
	slices.SortFunc(out, func(x, y *Placed) int { return strings.Compare(x.St.Kind+x.St.ID, y.St.Kind+y.St.ID) })
	return out
}

// Verify is `verify` for blob d from the statements held: the answer Artifact(d).VerifyExit() gives, computed
// with only what the exit needs. It skips the chain grade (inputs are not this blob's step) and compares d's own
// output with the others until the first match, so it costs at most k-1 comparator runs in a group of k outputs
// where the full view costs k(k-1)/2 (claims §13; the full view stays the one `show` and `explain` use).
func (r *Resolver) Verify(d string) (int, []string) {
	a := r.authorship(d)
	if a.State != NoClaim {
		r.groups(a, d)
	}
	return a.VerifyExit()
}

// VerifyExit is `verify` for the blob from the statements held (claims §13; execution §5.2 tokens): 1 when a
// completed comparison disagreed (a diverged derivation step), else 3 when anything could not be checked (no
// claim, contested authorship, a contested field, an unchecked or not comparable step, or a derivation nobody
// re-derived), else 0. A derived blob's claim is "this workflow on these inputs produced these bytes", and exit 0
// means it was checked: by a second run in its group, or by the reader's own re-run, which is the execution
// layer's part of `verify` and replaces this answer when it runs. A construction without provenance makes no
// such claim, so a sole author with nothing contested exits 0 (C-core-17). Why lists each cause.
func (a *Artifact) VerifyExit() (int, []string) {
	var why []string
	switch a.State {
	case NoClaim, ContestedAuthorship:
		why = append(why, "authorship: "+string(a.State))
	}
	for _, f := range a.Fields {
		if f.State == FieldContested {
			why = append(why, "field "+f.Name+": contested")
		}
	}
	if a.Selection != nil && !a.Selection.Met() {
		why = append(why, "reader's authorship selection: "+a.Selection.State)
	}
	if a.Group != nil {
		switch a.Step.Why {
		case DivergedToken:
			return 1, append([]string{"derivation: diverged"}, why...)
		case UncheckedToken, NotComparable, NotRederived:
			why = append(why, "derivation: "+a.Step.Why)
		}
	}
	if len(why) > 0 {
		return 3, why
	}
	return 0, nil
}

// Outcome is the priority outcome and every single-party default, without the evidence behind them: the part
// of the view that time evidence of local quality must never change (P-06).
func (a *Artifact) Outcome() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s", a.State)
	if a.Default != nil {
		fmt.Fprintf(&b, " default=%s", a.Default.describe())
	}
	for _, u := range a.Later {
		fmt.Fprintf(&b, " later=%s", u.describe())
	}
	for _, f := range a.Fields {
		if v, ok := f.Default(); ok {
			fmt.Fprintf(&b, " %s=%s", f.Name, v)
		} else if f.State != FieldAbsent {
			fmt.Fprintf(&b, " %s:%s", f.Name, f.State)
		}
	}
	return b.String()
}

// Render is the artifact display: a function of the view only.
func (a *Artifact) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "blob %s: %s", shortDigest(a.Digest), a.State)
	if a.State == Derived || (a.Group != nil && len(a.Group.Derivers) > 1) {
		fmt.Fprintf(&b, " (derived by %d under wf-%s)", len(a.Group.Derivers), shortDigest(a.Group.Provenance.Workflow))
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "  grade %s", a.Grade)
	if a.Step != a.Grade {
		fmt.Fprintf(&b, " (this step %s)", a.Step)
	}
	b.WriteString("\n")
	for _, s := range a.RestsOn {
		fmt.Fprintf(&b, "  rests on %s\n", s)
	}
	for _, u := range a.Units {
		role := "claimant"
		switch {
		case u == a.Default && a.State == Priority:
			role = "default author"
		case u == a.Default && a.State == Derived:
			role = "derivers"
		case u == a.Default:
			role = "author"
		case slices.Contains(a.Later, u):
			role = "later claimant"
		}
		fmt.Fprintf(&b, "  %s %s, bound %s\n", role, u.describe(), u.Bound)
		for _, c := range u.Claims {
			for _, id := range c.Current {
				fmt.Fprintf(&b, "    authored %s by %s", keylog.Short(id), shortKey(c.Signer))
				if am := c.Amends[id]; len(am) > 0 {
					fmt.Fprintf(&b, " (amends %s)", shorts(am))
				}
				b.WriteString("\n")
			}
		}
	}
	for _, n := range a.NotCounted {
		fmt.Fprintf(&b, "  authored %s by %s not counted: %s\n", keylog.Short(n.Statement), shortKey(n.Signer), n.Why)
	}
	for _, f := range a.Fields {
		switch f.State {
		case FieldAbsent:
			if !slices.Contains(Disclosures, f.Name) && len(f.Rivals) == 0 {
				continue
			}
			fmt.Fprintf(&b, "  %s: %s\n", f.Name, absentToken(f.Name))
		case FieldDefault:
			fmt.Fprintf(&b, "  %s: %s (%s)\n", f.Name, f.From[0].Value, sources(f.From))
		default:
			fmt.Fprintf(&b, "  %s: %s\n", f.Name, f.State)
			for _, s := range f.From {
				fmt.Fprintf(&b, "    %s by %s in %s\n", s.Value, shortKey(s.Signer), keylog.Short(s.Statement))
			}
		}
		for _, s := range f.Rivals {
			fmt.Fprintf(&b, "    rival %s by %s in %s\n", s.Value, shortKey(s.Signer), keylog.Short(s.Statement))
		}
	}
	if a.Group != nil {
		b.WriteString(a.Group.render("  "))
	}
	for _, g := range a.Groups {
		if g != a.Group {
			b.WriteString(g.render("  "))
		}
	}
	if len(a.Holders) > 0 {
		hs := make([]string, len(a.Holders))
		for i, h := range a.Holders {
			hs[i] = shortKey(h)
		}
		fmt.Fprintf(&b, "  holders %s\n", strings.Join(hs, ","))
	}
	for _, p := range a.Held {
		fmt.Fprintf(&b, "  held %s %s by %s%s (not an input to any default)\n", p.St.Kind, keylog.Short(p.St.ID), shortKey(p.St.Signer), heldDetail(p))
	}
	code, why := a.VerifyExit()
	fmt.Fprintf(&b, "  verify %d", code)
	if len(why) > 0 {
		fmt.Fprintf(&b, ": %s", strings.Join(why, "; "))
	}
	b.WriteString("\n")
	for _, x := range a.Explain {
		fmt.Fprintf(&b, "  explain: %s\n", x)
	}
	return b.String()
}

func heldDetail(p *Placed) string {
	b := p.St.Body
	switch p.St.Kind {
	case "refutes":
		return " of " + keylog.Short(str(b, "of")) + " evidence " + shortDigest(str(b, "evidence"))
	case "retracts":
		return " (retracted) of " + keylog.Short(str(b, "of"))
	case "reproduced":
		return fmt.Sprintf(" %s of %s across workflows (%s)", str(b, "result"), keylog.Short(str(b, "of")), provenance(b))
	}
	return ""
}

// helpers

// contentDigest also associates non-counting evidence with a blob for display. It must tolerate an
// unvalidated or absent body (another wire major exposes linkage only); association never grants a claim.
func contentDigest(b *canon.Object) string {
	if b == nil {
		return ""
	}
	c, ok := b.Get("content")
	if !ok {
		return ""
	}
	o, ok := c.(*canon.Object)
	if !ok {
		return ""
	}
	return str(o, "digest")
}

func provenance(b *canon.Object) *Provenance {
	v, ok := b.Get("provenance")
	if !ok {
		return nil
	}
	o := v.(*canon.Object)
	return &Provenance{Workflow: str(o, "workflow"), Inputs: ids(o, "inputs")}
}

func notCountedWhy(p *Placed) string {
	switch {
	case !p.Chained:
		return "detached"
	case !p.EvidenceReady():
		return string(p.St.Status)
	case len(p.After) > 0:
		return p.After[0]
	}
	return strings.Join(p.Doubted, "; ")
}

// better returns the better of two bounds for one claimant: a verified bound beats an unverified one, a lower
// height beats a higher one; among unverified bounds a local one beats none. Ties break by anchor id so the
// answer is order-free.
func better(a, b Bound) Bound {
	switch {
	case a.verified() != b.verified():
		if a.verified() {
			return a
		}
		return b
	case a.verified() && a.Height != b.Height:
		if a.Height < b.Height {
			return a
		}
		return b
	case a.Quality != b.Quality:
		if a.Quality == Local {
			return a
		}
		return b
	case a.Quality == NoBound && (a.Anchor == "") != (b.Anchor == ""):
		// neither bounds anything; the one naming a refused anchor is shown, so the refusal is not hidden
		if a.Anchor != "" {
			return a
		}
		return b
	case a.Anchor <= b.Anchor:
		return a
	}
	return b
}

func cmpSeq(a, b *wire.Statement) int {
	if a.Seq != b.Seq {
		if a.Seq < b.Seq {
			return -1
		}
		return 1
	}
	return strings.Compare(a.ID, b.ID)
}

func sortSources(s []Source) {
	slices.SortFunc(s, func(x, y Source) int {
		return strings.Compare(x.Value+x.Signer+x.Statement, y.Value+y.Signer+y.Statement)
	})
}

func distinctValues(s []Source) int {
	seen := map[string]bool{}
	for _, x := range s {
		seen[x.Value] = true
	}
	return len(seen)
}

func sources(s []Source) string {
	var parts []string
	for _, x := range s {
		parts = append(parts, shortKey(x.Signer)+" in "+keylog.Short(x.Statement))
	}
	return strings.Join(parts, "; ")
}

func shortDigest(d string) string {
	return keylog.Short(strings.TrimPrefix(d, "sha256:"))
}
