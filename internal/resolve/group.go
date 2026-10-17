package resolve

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/keylog"
)

// Derivation groups and grades (claims-model note §5.2 "Derivation groups", §7; execution note §5.3).
//
// A derivation group is every counted run of one provenance (workflow hash and input hashes), whatever its
// output bytes: each key's current `authored` with that provenance, and each `reproduced` re-run of one of
// them (its `of` is an `authored` with the same provenance, C-exec-01). A `reproduced` that names an
// `authored` under another provenance links two groups (#22, C-core-26) and is a run of neither.
//
// Bytes are read against the replication mode and comparator the workflow's own `authored` declares, which the
// derivers inherit: the workflow blob's single-party defaults, resolved like any blob's. A workflow whose
// authorship is contested has no default mode, so its group is `unchecked` (fail closed, I4).
//
// Comparisons are the reader's own (I9): a comparator runs under the reader's Comparator, never taken from a
// runner's `reproduced` token, which is shown as that runner's claim. The default runs nothing, so every
// `protocol` comparison of different bytes is `unchecked`.

// Comparator runs a declared comparator on two outputs. Result is "match", "diverged", "not comparable" or
// "unchecked" (it could not run); why explains the last two.
type Comparator interface {
	Compare(comparator, a, b string) (result, why string)
}

// NoComparator is the default: it runs nothing.
type NoComparator struct{}

// Compare implements Comparator.
func (NoComparator) Compare(_, _, _ string) (string, string) {
	return "unchecked", "no comparator runner configured"
}

// WithComparator sets the reader's comparator runner.
func WithComparator(c Comparator) Option { return func(r *Resolver) { r.cmp = c } }

// Grade is a derivation step's grade, or why it has none. Tier is "T0" or "T1" (T2 needs tasks, §9); "" when
// the step carries no tier, and Why names the token.
type Grade struct {
	Tier  string
	Under string // the comparator, for T1
	Why   string
}

// The tokens a step without a tier carries.
const (
	NoDerivation    = "no derivation (no provenance)"
	NotRederived    = "not re-derived"
	IdenticalProto  = "identical bytes (protocol workflow)"
	DivergedToken   = "diverged"
	UncheckedToken  = "unchecked"
	NotComparable   = "not comparable"
	ObservationLeaf = "observation (not a tier)"
	NotHeld         = "no statement held"
)

func (g Grade) String() string {
	switch {
	case g.Tier == "T1":
		return "T1 under " + shortDigest(g.Under)
	case g.Tier != "":
		return g.Tier
	}
	return g.Why
}

// evidence orders one blob's steps from several derivation groups, to pick the step the blob shows: a tier
// first (T0 > T1 > T2), then `diverged`, then the tokens that compared nothing. A re-derivation under any
// provenance is a check of these bytes that passed, and its tier names the workflow. A completed comparison
// that disagreed outranks one that never ran, so a claim under a second provenance cannot hide a divergence
// behind "not re-derived". Neither order gives a third party anything: a key that can join a group can already
// add a run to it, and a run under its own provenance only adds evidence beside the others (I5, I7).
func (g Grade) evidence() int {
	if r := g.rank(); r > 0 {
		return 10 + r
	}
	switch g.Why {
	case DivergedToken:
		return 5
	case IdenticalProto:
		return 4
	case NotComparable:
		return 3
	case UncheckedToken:
		return 2
	case NotRederived:
		return 1
	}
	return 0
}

// rank orders grades for the weakest-link rule: T0 > T1 > T2 > anything without a tier. A step with no
// derivation (a leaf) is not a step and is never passed here.
func (g Grade) rank() int {
	switch g.Tier {
	case "T0":
		return 3
	case "T1":
		return 2
	case "T2":
		return 1
	}
	return 0
}

// Run is one derivation in a group.
type Run struct {
	Signer, Statement, Kind, Output string
	// Result is this run's step: a tier or a token. Partners are the runs whose outputs it matched.
	Grade    Grade
	Partners []string
}

// Group is the view of one derivation group.
type Group struct {
	Provenance *Provenance
	// Mode is the workflow's declared replication ("bytes", "protocol", "none") or "undeclared"; ModeFrom says
	// where it came from (the workflow's authored statement, or why there is no default).
	Mode, Comparator, ModeFrom string
	Derivers                   []string // distinct keys with an authored in the group, sorted
	Runs                       []Run    // by output, signer, statement
	Outputs                    []string // distinct output digests, sorted
	Token                      string   // the group display
	Explain                    []string
}

// Group resolves the derivation group of provenance p.
func (r *Resolver) Group(p *Provenance) *Group {
	g := &Group{Provenance: p, Mode: "undeclared"}
	authored := map[string]bool{}
	for _, q := range r.byKind["authored"] {
		if !q.Counts() || provenance(q.St.Body).key() != p.key() {
			continue
		}
		// only the key's current claim on that blob runs; an amended statement is history (C-core-11)
		if r.amended(q) {
			continue
		}
		authored[q.St.ID] = true
		g.Runs = append(g.Runs, Run{Signer: q.St.Signer, Statement: q.St.ID, Kind: "authored", Output: contentDigest(q.St.Body)})
		if !slices.Contains(g.Derivers, q.St.Signer) {
			g.Derivers = append(g.Derivers, q.St.Signer)
		}
	}
	for _, q := range r.byKind["reproduced"] {
		if q.Counts() && authored[str(q.St.Body, "of")] && provenance(q.St.Body).key() == p.key() {
			g.Runs = append(g.Runs, Run{Signer: q.St.Signer, Statement: q.St.ID, Kind: "reproduced", Output: contentDigest(q.St.Body)})
		}
	}
	slices.Sort(g.Derivers)
	slices.SortFunc(g.Runs, func(a, b Run) int {
		return strings.Compare(a.Output+a.Signer+a.Statement, b.Output+b.Signer+b.Statement)
	})
	for _, run := range g.Runs {
		if !slices.Contains(g.Outputs, run.Output) {
			g.Outputs = append(g.Outputs, run.Output)
		}
	}
	slices.Sort(g.Outputs)

	wf := r.authorship(p.Workflow)
	switch {
	case wf.State == NoClaim:
		g.ModeFrom = "the workflow " + shortDigest(p.Workflow) + " has no authored statement held"
	case wf.Default == nil:
		g.ModeFrom = "the workflow's authorship is " + string(wf.State) + ", so it declares no default replication"
	default:
		f := wf.Field("replication")
		if v, ok := f.Default(); ok {
			g.Mode = strings.Trim(v, `"`)
			g.ModeFrom = "declared by the workflow's authored (" + sources(f.From) + ")"
		} else if f.State == FieldContested {
			g.ModeFrom = "the workflow's replication is contested among its derivers"
		} else {
			g.ModeFrom = "the workflow's authored declares no replication"
		}
		if v, ok := wf.Field("comparator").Default(); ok {
			g.Comparator = strings.Trim(v, `"`)
		}
	}
	r.compare(g)
	return g
}

// amended reports whether a later counted `authored` of the same key on the same blob follows q.
func (r *Resolver) amended(q *Placed) bool {
	d := contentDigest(q.St.Body)
	for _, o := range r.byKind["authored"] {
		if o.St.Signer == q.St.Signer && o.Counts() && contentDigest(o.St.Body) == d && r.precedes(q.St.Signer, q.St.ID, o.St.ID) {
			return true
		}
	}
	return false
}

// compare grades every run under the group's mode (claims §5.2 table, execution §5.3).
func (r *Resolver) compare(g *Group) {
	set := func(f func(i int) Grade) {
		for i := range g.Runs {
			g.Runs[i].Grade = f(i)
		}
	}
	k := len(g.Derivers)
	switch {
	case len(g.Runs) < 2:
		set(func(int) Grade { return Grade{Why: NotRederived} })
		g.Token = fmt.Sprintf("derived by %d, not re-derived", k)
	case g.Mode == "bytes" && len(g.Outputs) == 1:
		set(func(int) Grade { return Grade{Tier: "T0"} })
		g.Token = fmt.Sprintf("derived by %d: byte-identical re-derivation (T0)", k)
	case g.Mode == "bytes":
		// graded per output: a run whose bytes another run of the group also produced is a byte-identical
		// re-derivation whatever else the group holds, so one stray output never takes T0 from the others;
		// an output no other run produced is the one that diverged
		runs := map[string]int{}
		for _, run := range g.Runs {
			runs[run.Output]++
		}
		reproduced := 0
		for _, o := range g.Outputs {
			if runs[o] > 1 {
				reproduced++
			}
		}
		set(func(i int) Grade {
			if runs[g.Runs[i].Output] > 1 {
				return Grade{Tier: "T0"}
			}
			return Grade{Why: DivergedToken}
		})
		g.Token = fmt.Sprintf("derived by %d: diverged (%d different outputs)", k, len(g.Outputs))
		if reproduced > 0 {
			g.Token += fmt.Sprintf("; %d of them byte-identical across runs (T0)", reproduced)
		}
		g.Explain = append(g.Explain, "an environment differs or the determinism claim is wrong; no member is marked wrong")
		if reproduced > 0 {
			g.Explain = append(g.Explain, "an output another run also produced is a byte-identical re-derivation (T0); an output no other run produced is diverged")
		}
	case g.Mode == "protocol" && len(g.Outputs) == 1:
		set(func(int) Grade { return Grade{Why: IdenticalProto} })
		g.Token = fmt.Sprintf("derived by %d: %s", k, IdenticalProto)
		g.Explain = append(g.Explain, "identical bytes under a protocol workflow are consistent with a re-run and with a copy, and evidence of neither; independence is claims §9.3's question")
	case g.Mode == "protocol" && g.Comparator == "":
		set(func(int) Grade { return Grade{Why: UncheckedToken} })
		g.Token = fmt.Sprintf("derived by %d: unchecked", k)
		g.Explain = append(g.Explain, "the workflow declares protocol replication and no comparator; no default comparison is made")
	case g.Mode == "protocol":
		r.compareProtocol(g)
	default:
		set(func(int) Grade { return Grade{Why: UncheckedToken} })
		g.Token = fmt.Sprintf("derived by %d: unchecked", k)
		g.Explain = append(g.Explain, "replication "+g.Mode+": "+g.ModeFrom)
	}
}

// compareProtocol runs the comparator on each pair of different outputs. A run whose output matched another
// output is T1 under the comparator, with its partners listed (tolerance is not transitive, so partners are
// named, never chained, claims §9.3). A run that compared against every other output and matched none is
// diverged; otherwise not comparable or unchecked.
func (r *Resolver) compareProtocol(g *Group) {
	type res struct{ result, why string }
	pair := map[[2]string]res{}
	for i, a := range g.Outputs {
		for _, b := range g.Outputs[i+1:] {
			x, why := r.cmp.Compare(g.Comparator, a, b)
			pair[[2]string{a, b}], pair[[2]string{b, a}] = res{x, why}, res{x, why}
			if x == "unchecked" || x == "not comparable" {
				g.Explain = append(g.Explain, fmt.Sprintf("%s vs %s: %s (%s)", shortDigest(a), shortDigest(b), x, why))
			}
		}
	}
	match, diverged := 0, 0
	for i := range g.Runs {
		run := &g.Runs[i]
		var results []string
		for _, o := range g.Outputs {
			if o == run.Output {
				continue
			}
			p := pair[[2]string{run.Output, o}]
			results = append(results, p.result)
			if p.result == "match" {
				run.Partners = append(run.Partners, o)
			}
		}
		switch {
		case len(run.Partners) > 0:
			run.Grade = Grade{Tier: "T1", Under: g.Comparator}
			match++
		case !slices.ContainsFunc(results, func(s string) bool { return s != "diverged" }):
			run.Grade = Grade{Why: DivergedToken}
			diverged++
		case slices.Contains(results, "not comparable"):
			run.Grade = Grade{Why: NotComparable}
		default:
			run.Grade = Grade{Why: UncheckedToken}
		}
	}
	g.Token = fmt.Sprintf("derived by %d: %d match, %d diverged", len(g.Derivers), match, diverged)
	if other := len(g.Runs) - match - diverged; other > 0 {
		g.Token += fmt.Sprintf(", %d unchecked", other)
	}
}

// stepOf is the grade of the step that produced output d: the best grade among the runs with that output (a
// blob two keys derived is as well re-derived as its best-evidenced run).
func (g *Group) stepOf(d string) Grade {
	best := Grade{Why: NotRederived}
	found := false
	for _, run := range g.Runs {
		if run.Output != d {
			continue
		}
		if !found || run.Grade.rank() > best.rank() {
			best, found = run.Grade, true
		}
	}
	return best
}

func (g *Group) render(indent string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%sgroup %s: %s; replication %s (%s)\n", indent, g.Provenance, g.Token, g.Mode, g.ModeFrom)
	for _, run := range g.Runs {
		fmt.Fprintf(&b, "%s  %s %s by %s -> %s: %s", indent, run.Kind, keylog.Short(run.Statement), shortKey(run.Signer), shortDigest(run.Output), run.Grade)
		if len(run.Partners) > 0 {
			ps := make([]string, len(run.Partners))
			for i, p := range run.Partners {
				ps[i] = shortDigest(p)
			}
			fmt.Fprintf(&b, " (matched %s)", strings.Join(ps, ","))
		}
		b.WriteString("\n")
	}
	for _, x := range g.Explain {
		fmt.Fprintf(&b, "%s  explain: %s\n", indent, x)
	}
	return b.String()
}

// grade computes a's step, chain grade and leaf summary (claims §7). The step comes from the group of the
// default unit (or the only claimant's provenance). The chain grade is the weakest step over the derivation
// inputs that are themselves derived; leaves (observations, constructions without provenance) are not steps
// and are summarised beside the grade. A blob that is the evidence of a counted `refutes` is graded on its own
// derivation only (exempt from the weakest-link rule).
func (r *Resolver) grade(a *Artifact, visiting map[string]bool) {
	visiting[a.Digest] = true
	defer delete(visiting, a.Digest)
	if r.isObservation(a.Digest) && a.State == NoClaim {
		a.Step, a.Grade = Grade{Why: ObservationLeaf}, Grade{Why: ObservationLeaf}
		return
	}
	if a.State == NoClaim {
		a.Step, a.Grade = Grade{Why: NotHeld}, Grade{Why: NotHeld}
		return
	}
	r.groups(a)
	a.Grade = a.Step
	if a.Group == nil {
		return
	}
	prov := a.Group.Provenance
	exempt := r.isRefutation(a.Digest)
	var obs, contra, leaves, missing int
	for _, in := range prov.Inputs {
		if visiting[in] {
			a.Explain = append(a.Explain, "input "+shortDigest(in)+" is on a cycle of provenance; not followed")
			continue
		}
		if r.isObservation(in) {
			obs++
			if r.contradicted(in) > 0 {
				contra++
			}
			continue
		}
		sub := r.artifact(in, visiting)
		switch {
		case sub.State == NoClaim:
			missing++
		case sub.Step.Why == NoDerivation:
			leaves++
		case !exempt && sub.Grade.rank() < a.Grade.rank():
			a.Grade = sub.Grade
			a.Explain = append(a.Explain, "chain grade "+sub.Grade.String()+" from input "+shortDigest(in)+" (weakest derivation step)")
		}
		if !exempt {
			a.RestsOn = append(a.RestsOn, sub.RestsOn...)
		}
	}
	if exempt {
		a.Explain = append(a.Explain, "a refutation is graded on its own derivation, exempt from the weakest-link rule (claims §7)")
	}
	if obs > 0 {
		s := fmt.Sprintf("%d observation(s)", obs)
		if contra > 0 {
			s += fmt.Sprintf(": %d contradicted within statements you hold", contra)
		}
		a.RestsOn = append(a.RestsOn, s)
	}
	if leaves > 0 {
		a.RestsOn = append(a.RestsOn, fmt.Sprintf("%d construction(s) without provenance", leaves))
	}
	if missing > 0 {
		a.RestsOn = append(a.RestsOn, fmt.Sprintf("%d input(s) with no statement held", missing))
	}
	slices.Sort(a.RestsOn)
	a.RestsOn = slices.Compact(a.RestsOn)
}

// groups resolves the derivation group of every claimant unit with provenance and takes the blob's step from
// the one with the strongest evidence for these bytes (Grade.evidence), the default unit's on a tie. Whether a
// workflow reproduces the bytes does not depend on who authored them first, so authorship (contested, or a
// claimant without provenance ranked first) never hides a group's evidence: a statement that bears only on
// authorship cannot change the grade (I5).
func (r *Resolver) groups(a *Artifact) {
	units := make([]*Unit, 0, len(a.Units))
	if a.Default != nil && a.Default.Provenance != nil {
		units = append(units, a.Default)
	}
	for _, u := range a.Units {
		if u.Provenance != nil && u != a.Default {
			units = append(units, u)
		}
	}
	for _, u := range units {
		g := r.Group(u.Provenance)
		a.Groups = append(a.Groups, g)
		if step := g.stepOf(a.Digest); a.Group == nil || step.evidence() > a.Step.evidence() {
			a.Group, a.Step = g, step
		}
	}
	if a.Group == nil {
		a.Step = Grade{Why: NoDerivation}
		return
	}
	for _, g := range a.Groups {
		if g != a.Group && g.stepOf(a.Digest).Why == DivergedToken {
			a.Explain = append(a.Explain, "the derivation group "+g.Provenance.String()+" shows these bytes diverged; shown beside the grade, which comes from "+a.Group.Provenance.String())
		}
	}
	if a.Default == nil || a.Default.Provenance == nil || a.Default.Provenance.key() != a.Group.Provenance.key() {
		a.Explain = append(a.Explain, "grade from the derivation group "+a.Group.Provenance.String()+"; authorship ("+
			string(a.State)+") does not move it: whether a workflow reproduces these bytes does not depend on who authored them first")
	}
}

func (r *Resolver) isObservation(d string) bool {
	for _, p := range r.byKind["observed"] {
		if p.Counts() && contentDigest(p.St.Body) == d {
			return true
		}
	}
	return false
}

func (r *Resolver) isRefutation(d string) bool {
	for _, p := range r.byKind["refutes"] {
		if p.Counts() && str(p.St.Body, "evidence") == d {
			return true
		}
	}
	return false
}

// contradicted counts the counted `corroborates` with verdict `contradicts` on any counted `observed` of d,
// within the statements held. The full corroboration status (agreement models, trust, scope, §5.3.2) is a
// later slice; this count is what the scoped summary beside a grade needs today.
func (r *Resolver) contradicted(d string) int {
	obs := map[string]bool{}
	for _, p := range r.byKind["observed"] {
		if p.Counts() && contentDigest(p.St.Body) == d {
			obs[p.St.ID] = true
		}
	}
	n := 0
	for _, p := range r.byKind["corroborates"] {
		if p.Counts() && obs[str(p.St.Body, "of")] && str(p.St.Body, "verdict") == "contradicts" {
			n++
		}
	}
	return n
}
