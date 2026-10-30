package resolve

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
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
// authorship is contested has no default; its groups use the mode and comparator only when every claimant of
// the workflow declares the same pair, and are otherwise `unchecked` (fail closed, I4). A rival can therefore
// never raise a group's grade, and can lower it only by disagreeing, visibly.
//
// Under `bytes` a run is graded by its own output: T0 when another run produced the same bytes, `diverged`
// when none did. Under a comparator a run is T1 when it matched at least one other output (partners named),
// and the group summary says whether all runs agree. A blob's step is the strongest evidence any group holds
// for its bytes, so authorship never hides a group (artifact.go, grade).
//
// Comparisons are the reader's own (I9): a comparator runs under the reader's Comparator, never taken from a
// runner's `reproduced` token, which is shown as that runner's claim. The default runs nothing, so every
// `protocol` comparison of different bytes is `unchecked`.
//
// A comparator is asked about each unordered pair of outputs once per resolver, always with the pair in digest
// order, and its answer is reused for every view (pair). That assumes what a comparator must be for T1 to mean
// anything: deterministic and symmetric. The tool cannot check either; it can only make sure an asymmetric
// comparator is asked one way round, so the answer cannot depend on which blob was viewed first (I14).

type cmpResult struct{ result, why string }

// pair returns the comparator's result for outputs a and b, asking the reader's Comparator at most once per
// unordered pair (see the package comment above on determinism and symmetry).
func (r *Resolver) pair(comparator, a, b string) (string, string) {
	if b < a {
		a, b = b, a
	}
	k := [3]string{comparator, a, b}
	r.cmpMu.Lock()
	v, ok := r.cmpRuns[k]
	r.cmpMu.Unlock()
	if !ok {
		x, why := r.cmp.Compare(comparator, a, b)
		v = cmpResult{x, why}
		r.cmpMu.Lock()
		r.cmpRuns[k] = v
		r.cmpMu.Unlock()
	}
	return v.result, v.why
}

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
	// Says is a `reproduced` run's own `result` token, Env its environment record (canonical JSON, "" when
	// absent; an `authored` run's environment rides on its provenance). Both are the runner's signed word,
	// shown beside the reader's Grade and never graded (claims I2, I9; decisions A5).
	Says, Env string
	// Trust is the reader's attestation trust in Signer under its policy, display only ("" = trustLine).
	Trust string
}

// trustLine is what a run shows for the reader's trust in its signer with no reader policy configured: it says
// so rather than imply either answer. With a policy, Run.Trust carries the policy's answer (policy.go).
const trustLine = "your trust in this key: not configured"

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
	only                       string // set when only one output's runs were graded (group)
}

// Group resolves the derivation group of provenance p.
func (r *Resolver) Group(p *Provenance) *Group { return r.group(p, "") }

// group resolves the group of p. With only set, it grades only the runs whose output is only, comparing that
// output with the others until the first match (verify's question, Resolver.Verify); the group's token and the
// other runs' grades are then left unset, and the view is never rendered.
func (r *Resolver) group(p *Provenance, only string) *Group {
	g := &Group{Provenance: p, Mode: "undeclared", only: only}
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
		g.Runs = append(g.Runs, Run{Signer: q.St.Signer, Statement: q.St.ID, Kind: "authored", Output: contentDigest(q.St.Body), Env: envOf(q.St.Body)})
		if !slices.Contains(g.Derivers, q.St.Signer) {
			g.Derivers = append(g.Derivers, q.St.Signer)
		}
	}
	for _, q := range r.byKind["reproduced"] {
		if q.Counts() && authored[str(q.St.Body, "of")] && provenance(q.St.Body).key() == p.key() {
			g.Runs = append(g.Runs, Run{Signer: q.St.Signer, Statement: q.St.ID, Kind: "reproduced", Output: contentDigest(q.St.Body),
				Says: str(q.St.Body, "result"), Env: envOf(q.St.Body)})
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
	case r.modeFromPolicy(g, p.Workflow):
		// the reader's workflow-declaration selection decides, met or not (policy.go)
	case wf.State == NoClaim:
		g.ModeFrom = "the workflow " + shortDigest(p.Workflow) + " has no authored statement held"
	case wf.Default == nil:
		// every claimant of the workflow declaring the same mode and comparator is an answer whoever authored
		// it first; any disagreement (an absent value included) fails closed (decisions A7)
		if mode, comparator, n, ok := r.agreedMode(wf); ok {
			g.Mode, g.Comparator = mode, comparator
			if g.Mode == "" {
				g.Mode = "undeclared"
			}
			g.ModeFrom = fmt.Sprintf("the workflow's authorship is %s; all %d claimants of wf-%s declare the same replication and comparator", wf.State, n, shortDigest(p.Workflow))
		} else {
			g.ModeFrom = "the workflow's authorship is " + string(wf.State) + " and its claimants do not all declare the same replication and comparator, so it declares no default replication"
		}
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
		if why := r.modeAmended(wf); why != "" {
			g.Explain = append(g.Explain, why)
		}
	}
	r.compare(g)
	r.runTrust(g)
	for _, run := range g.Runs {
		if says, mine := run.Says, readerResult(run.Grade); says != "" && mine != "" && says != mine {
			g.Explain = append(g.Explain, fmt.Sprintf("%s %s signed %q; this reader's comparison: %q (shown, never graded: claims §5.2)",
				shortKey(run.Signer), keylog.Short(run.Statement), says, mine))
		}
	}
	if len(g.Runs) > 1 && g.only == "" && !slices.ContainsFunc(g.Runs, func(run Run) bool { return run.Signer != g.Runs[0].Signer }) {
		g.Explain = append(g.Explain, "re-derived by its author only: the re-run shows the bytes reproduce, not that anyone else got them (independence is claims §9.3's question)")
	}
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
		g.Explain = append(g.Explain, "no second run of this provenance is held, so the derivation is unchecked; a re-run by the reader, or a `reproduced` by anyone, is what checks it")
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
	case g.Mode == "protocol" && g.Comparator == "":
		// no comparator: no comparison is possible whatever the bytes, so identical bytes are unchecked too
		// (execution §5.3; claims §13: holding less evidence never passes where holding more would not)
		set(func(int) Grade { return Grade{Why: UncheckedToken} })
		g.Token = fmt.Sprintf("derived by %d: unchecked", k)
		g.Explain = append(g.Explain, "the workflow declares protocol replication and no comparator; no default comparison is made")
	case g.Mode == "protocol" && len(g.Outputs) == 1:
		set(func(int) Grade { return Grade{Why: IdenticalProto} })
		g.Token = fmt.Sprintf("derived by %d: %s", k, IdenticalProto)
		g.Explain = append(g.Explain, "identical bytes under a protocol workflow are consistent with a re-run and with a copy, and evidence of neither; independence is claims §9.3's question")
	case g.Mode == "protocol":
		r.compareProtocol(g)
	default:
		set(func(int) Grade { return Grade{Why: UncheckedToken} })
		g.Token = fmt.Sprintf("derived by %d: unchecked", k)
		g.Explain = append(g.Explain, "replication "+g.Mode+": "+g.ModeFrom)
	}
}

// compareProtocol grades runs under a declared comparator. A run is T1 when its output matched at least one
// other output, with its partners listed; it is diverged when every comparison it took part in ran and disagreed;
// otherwise not comparable or unchecked. Tolerance is not transitive, so matches are never chained (claims §9.3):
// the token says "all n runs match" only when every pair of outputs matched, and otherwise flags matching runs
// that do not agree with each other, naming the pairs in explain.
func (r *Resolver) compareProtocol(g *Group) {
	if g.only != "" {
		grade, _ := r.row(g, g.only, true)
		for i := range g.Runs {
			if g.Runs[i].Output == g.only {
				g.Runs[i].Grade = grade
			}
		}
		return
	}
	for i, a := range g.Outputs {
		for _, b := range g.Outputs[i+1:] {
			if x, why := r.pair(g.Comparator, a, b); x == "unchecked" || x == "not comparable" {
				g.Explain = append(g.Explain, fmt.Sprintf("%s vs %s: %s (%s)", shortDigest(a), shortDigest(b), x, why))
			}
		}
	}
	rows := map[string]Grade{}
	partners := map[string][]string{}
	for _, o := range g.Outputs {
		rows[o], partners[o] = r.row(g, o, false)
	}
	match, diverged := 0, 0
	for i := range g.Runs {
		run := &g.Runs[i]
		run.Grade, run.Partners = rows[run.Output], partners[run.Output]
		switch {
		case run.Grade.Tier == "T1":
			match++
		case run.Grade.Why == DivergedToken:
			diverged++
		}
	}

	// do the outputs that matched something agree with each other?
	var matched []string
	for _, o := range g.Outputs {
		if len(partners[o]) > 0 {
			matched = append(matched, o)
		}
	}
	pairs, apart, unknown := 0, 0, 0
	for i, a := range matched {
		for _, b := range matched[i+1:] {
			pairs++
			switch x, _ := r.pair(g.Comparator, a, b); x {
			case "match":
			case "diverged":
				apart++
				g.Explain = append(g.Explain, fmt.Sprintf("%s vs %s: diverged, though each matched another run (tolerance is not transitive; matches are never chained, claims §9.3)", shortDigest(a), shortDigest(b)))
			default:
				unknown++
			}
		}
	}
	k := len(g.Derivers)
	if match == len(g.Runs) && apart+unknown == 0 {
		g.Token = fmt.Sprintf("derived by %d: all %d runs match under %s", k, match, shortDigest(g.Comparator))
		return
	}
	g.Token = fmt.Sprintf("derived by %d: %d match, %d diverged", k, match, diverged)
	if other := len(g.Runs) - match - diverged; other > 0 {
		g.Token += fmt.Sprintf(", %d unchecked", other)
	}
	if apart+unknown > 0 {
		lead := "matching runs not all compared with each other"
		if apart > 0 {
			lead = "not all runs agree"
		}
		var parts []string
		if apart > 0 {
			parts = append(parts, fmt.Sprintf("%d of %d pairs among them diverged", apart, pairs))
		}
		if unknown > 0 {
			parts = append(parts, fmt.Sprintf("%d of %d unchecked", unknown, pairs))
		}
		g.Token += fmt.Sprintf("; %s (%s; %s)", lead, plural(clusters(r, g, matched), "cluster"), strings.Join(parts, ", "))
	}
}

// row grades output o against every other output of g: T1 with its partners when it matched any, diverged
// when every comparison ran and disagreed, else not comparable or unchecked. lazy stops at the first match,
// which decides the grade; the partners are then incomplete.
func (r *Resolver) row(g *Group, o string, lazy bool) (Grade, []string) {
	var partners []string
	n, apart, notComparable := 0, 0, false
	for _, x := range g.Outputs {
		if x == o {
			continue
		}
		n++
		switch res, _ := r.pair(g.Comparator, o, x); res {
		case "match":
			partners = append(partners, x)
			if lazy {
				return Grade{Tier: "T1", Under: g.Comparator}, partners
			}
		case "diverged":
			apart++
		case "not comparable":
			notComparable = true
		}
	}
	switch {
	case len(partners) > 0:
		return Grade{Tier: "T1", Under: g.Comparator}, partners
	case apart == n:
		return Grade{Why: DivergedToken}, nil
	case notComparable:
		return Grade{Why: NotComparable}, nil
	}
	return Grade{Why: UncheckedToken}, nil
}

// clusters counts the connected components of the match graph over outputs (each matched output with its
// partners). Components can chain, so this is a count for the summary, never a claim that a cluster agrees.
func clusters(r *Resolver, g *Group, outputs []string) int {
	seen := map[string]bool{}
	n := 0
	for _, o := range outputs {
		if seen[o] {
			continue
		}
		n++
		stack := []string{o}
		seen[o] = true
		for len(stack) > 0 {
			x := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, y := range outputs {
				if !seen[y] {
					if res, _ := r.pair(g.Comparator, x, y); res == "match" {
						seen[y] = true
						stack = append(stack, y)
					}
				}
			}
		}
	}
	return n
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// agreedMode reports the replication and comparator every current `authored` of every claimant of the workflow
// declares, when they all declare the same pair ("" for an absent value, which disagrees with any declared
// one), and how many claimants there are.
func (r *Resolver) agreedMode(wf *Artifact) (mode, comparator string, n int, ok bool) {
	first := true
	for _, c := range wf.Claims {
		n++
		for _, st := range c.current {
			m, k := str(st.Body, "replication"), str(st.Body, "comparator")
			if first {
				mode, comparator, first = m, k, false
			} else if m != mode || k != comparator {
				return "", "", n, false
			}
		}
	}
	return mode, comparator, n, !first
}

// modeAmended names the amendment when the workflow's default claim amends a statement that declared another
// replication or comparator: every group under the workflow is read under the current one (execution §5.2,
// the author's correction after a divergence), and the reader should see why its grades moved.
func (r *Resolver) modeAmended(wf *Artifact) string {
	for _, c := range wf.Default.Claims {
		for _, cur := range c.current {
			for _, old := range c.Amends[cur.ID] {
				p, ok := r.byID[old]
				if !ok {
					continue
				}
				if str(p.St.Body, "replication") != str(cur.Body, "replication") || str(p.St.Body, "comparator") != str(cur.Body, "comparator") {
					return fmt.Sprintf("the workflow's author amended its replication or comparator (%s amends %s); every group under it is read under the current declaration",
						keylog.Short(cur.ID), keylog.Short(old))
				}
			}
		}
	}
	return ""
}

// readerResult maps a run's grade to the `reproduced` result vocabulary (wire §5: match, diverged,
// not-comparable), or "" when the reader made no comparison that maps to one.
func readerResult(g Grade) string {
	switch {
	case g.Tier != "", g.Why == IdenticalProto:
		return "match"
	case g.Why == DivergedToken:
		return "diverged"
	case g.Why == NotComparable:
		return "not-comparable"
	}
	return ""
}

// envOf is a statement's environment record as canonical JSON: a `reproduced`'s or an `authored`'s
// provenance.environment. "" when absent.
func envOf(b *canon.Object) string {
	p, ok := b.Get("provenance")
	if !ok {
		return ""
	}
	po, ok := p.(*canon.Object)
	if !ok {
		return ""
	}
	e, ok := po.Get("environment")
	if !ok {
		return ""
	}
	return string(canon.Encode(e))
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
		if run.Says != "" {
			fmt.Fprintf(&b, "%s    runner says: %s\n", indent, run.Says)
		}
		if run.Env != "" {
			fmt.Fprintf(&b, "%s    environment (runner's record): %s\n", indent, run.Env)
		}
		if run.Says != "" || run.Env != "" {
			fmt.Fprintf(&b, "%s    %s\n", indent, cmp.Or(run.Trust, trustLine))
		}
	}
	for _, x := range g.Explain {
		fmt.Fprintf(&b, "%s  explain: %s\n", indent, x)
	}
	return b.String()
}

// grade computes a's step, chain grade and leaf summary (claims §7). The step comes from the strongest group
// among the claimant units with provenance (groups), whatever the authorship state. The chain grade is the weakest step over the derivation
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
	r.groups(a, "")
	a.Grade = a.Step
	if a.Group == nil {
		return
	}
	prov := a.Group.Provenance
	exempt := r.isRefutation(a.Digest)
	var obs, contra, leaves, missing int
	refs := map[string]int{}
	for _, in := range prov.Inputs {
		if visiting[in] {
			a.Explain = append(a.Explain, "input "+shortDigest(in)+" is on a cycle of provenance; not followed")
			continue
		}
		if r.isObservation(in) {
			obs++
			c, ref := r.obsNotes(in) // observation.go: lite status and the referent status that bears on the input
			if c {
				contra++
			}
			if ref != "" {
				refs[ref]++
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
		var parts []string
		for _, k := range sortedKeys(refs) {
			parts = append(parts, fmt.Sprintf("%d %s", refs[k], k))
		}
		if contra > 0 {
			parts = append(parts, fmt.Sprintf("%d contradicted %s", contra, r.obs.scope))
		}
		if len(parts) > 0 {
			s += ": " + strings.Join(parts, "; ")
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
func (r *Resolver) groups(a *Artifact, only string) {
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
		g := r.group(u.Provenance, only)
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
