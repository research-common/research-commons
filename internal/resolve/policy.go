package resolve

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

// The reader's local policy (fixed-root identity note §6, `reader-policy-v1`; package policy parses it).
//
// With no policy (the default) every answer is exactly what it is without this file. With one:
//
//   - a selection for (content, role) chooses which declaration supplies an answer the resolver otherwise
//     derives from every claimant: `authorship-declaration` the blob's single-party defaults,
//     `workflow-declaration` a workflow's replication mode and comparator for every group under it (the reader's
//     pin instead of the deriver's choice), `observation-declaration` the observation a derived result's leaf
//     summary reads. An exact pin selects exactly that eligible statement: never an alias, a successor, an
//     amendment or the key's latest. A pin that is missing or ineligible stays unmet and non-passing: nothing is
//     substituted. A principal selection `{key: K}` follows K's eligible current claims only; when they disagree
//     the disagreement is shown (a contested field, an unmet workflow selection), never settled by arrival. An
//     `{identity: I}` principal is unknown: the identity profile is not active. A selection may change a
//     recomputed grade because the declaration changed; it never adds a run, a comparison or a statement.
//   - trust entries answer "does this reader trust key K for purpose P over content C" (package policy,
//     Policy.Trusts). Corroboration status counts only evidence from keys trusted for `corroboration` over the
//     observation's content (claims §5.3.2 "holds and trusts"); a run's signed result and environment show the
//     reader's `attestation` trust in the runner, display only, never graded. The reader's own computations are
//     never filtered: they are not a key's statement.
//
// Every answer a policy changes cites the policy digest and the selection or trust answer behind it, so two
// readers that differ only by policy see which policy made the difference (P-11).

// WithPolicy sets the reader's local policy. A nil policy is no policy.
func WithPolicy(p *policy.Policy) Option { return func(r *Resolver) { r.policy = p } }

// PolicyDigest is the digest of the configured policy, "" when none is configured.
func (r *Resolver) PolicyDigest() string {
	if r.policy == nil {
		return ""
	}
	return r.policy.Digest
}

// Selection states.
const (
	SelMet        = "met"
	SelMissing    = "not met: statement not held"
	SelIneligible = "not met: statement ineligible"
	SelNone       = "not met: no eligible current claim of the principal"
	SelConflict   = "not met: the principal's current claims disagree"
	SelIdentity   = "unknown (identity profile not active)"
)

// FieldSelectionUnmet is a single-party field whose authorship-declaration selection is not met: no default,
// and no other declaration substituted.
const FieldSelectionUnmet FieldState = "no default (reader's selection not met)"

// Selected is a policy selection resolved against the held statements.
type Selected struct {
	Selection policy.Selection
	Policy    string // the policy digest
	State     string
	Why       string
	// Statements are the selected eligible statements: the pinned one, or the principal's current claims.
	Statements []*wire.Statement
}

// Met reports whether the selection supplies a declaration.
func (s *Selected) Met() bool { return s != nil && s.State == SelMet }

// Explain is the selection as an explanation line, citing the policy digest and the selection.
func (s *Selected) Explain() string {
	line := fmt.Sprintf("reader policy %s selects %s: %s", shortPolicy(s.Policy), s.Selection, s.State)
	if s.Why != "" {
		line += " (" + s.Why + ")"
	}
	return line
}

// policyLine is the explain line every view carries when a policy is configured (claims §13 "explain" lists the
// policy behind an answer; C-core-136), so an answer that moved because of the policy always names it (P-11),
// including one that moved through an input's grade.
func (r *Resolver) policyLine() string {
	return fmt.Sprintf("evaluated under reader policy %s (%d selection(s), %d trust entr(ies))", r.policy.Digest, len(r.policy.Selections), len(r.policy.Trust))
}

func shortPolicy(d string) string { return "sha256:" + shortDigest(d) }

// selection resolves the policy's selection for (content, role); nil when there is none.
func (r *Resolver) selection(content, role string) *Selected {
	sel, ok := r.policy.Select(content, role)
	if !ok {
		return nil
	}
	s := &Selected{Selection: sel, Policy: r.policy.Digest}
	switch {
	case sel.Statement != "":
		p, held := r.byID[sel.Statement]
		if !held {
			s.State, s.Why = SelMissing, "no other statement is substituted"
			return s
		}
		if why := r.ineligible(p, content, role); why != "" {
			s.State, s.Why = SelIneligible, why+"; no other statement is substituted"
			return s
		}
		s.State, s.Statements = SelMet, []*wire.Statement{p.St}
	case sel.Principal.Key == "":
		s.State = SelIdentity
		s.Why = "the policy names identity " + keylog.Short(sel.Principal.Identity) + "; no key's claims are followed in its place"
	default:
		s.Statements = r.currentOf(sel.Principal.Key, content, role)
		s.State = SelMet
		if len(s.Statements) == 0 {
			s.State, s.Why = SelNone, "following key "+shortKey(sel.Principal.Key)
		}
	}
	return s
}

// ineligible says why p cannot supply role for content, or "".
func (r *Resolver) ineligible(p *Placed, content, role string) string {
	kind := "authored"
	if role == policy.RoleObservation {
		kind = "observed"
	}
	switch {
	case p.St.Kind != kind:
		return "a " + p.St.Kind + ", not an " + kind
	case contentDigest(p.St.Body) != content:
		return "about another blob"
	case role == policy.RoleWorkflow && str(p.St.Body, "type") != "workflow":
		return "not a workflow declaration (type " + fmt.Sprintf("%q", str(p.St.Body, "type")) + ")"
	case !p.Counts():
		return "counts toward nothing: " + notCountedWhy(p)
	}
	return ""
}

// currentOf is key k's eligible current claims for (content, role): its counted statements of the role's kind
// on the content that no later counted statement of k on the content amends, then the eligible ones. Two on an
// uncleared fork are both current; neither is preferred.
func (r *Resolver) currentOf(k, content, role string) []*wire.Statement {
	kind := "authored"
	if role == policy.RoleObservation {
		kind = "observed"
	}
	var mine []*Placed
	for _, p := range r.byKind[kind] {
		if p.St.Signer == k && p.Counts() && contentDigest(p.St.Body) == content {
			mine = append(mine, p)
		}
	}
	var out []*wire.Statement
	for _, p := range mine {
		amended := kind == "authored" && slices.ContainsFunc(mine, func(q *Placed) bool { return r.precedes(k, p.St.ID, q.St.ID) })
		if !amended && r.ineligible(p, content, role) == "" {
			out = append(out, p.St)
		}
	}
	slices.SortFunc(out, func(a, b *wire.Statement) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// --- authorship-declaration: single-party defaults (artifact.go) ---------------------------------------------

// selectDefaults applies an authorship-declaration selection to a's single-party fields: the selected
// statements supply the defaults; every other current claim's value is listed as a rival. Authorship state,
// priority and the grade are unchanged: the selection chooses whose declaration a reader reads, not who was
// first. An unmet selection leaves every declared field without a default.
func (r *Resolver) selectDefaults(a *Artifact) {
	if r.policy == nil {
		return
	}
	a.Explain = append(a.Explain, r.policyLine())
	s := r.selection(a.Digest, policy.RoleAuthorship)
	if s == nil {
		return
	}
	a.Selection = s
	a.Explain = append(a.Explain, s.Explain())
	chosen := map[string]bool{}
	for _, st := range s.Statements {
		chosen[st.ID] = true
	}
	for i, f := range a.Fields {
		var mine, rivals []Source
		add := func(st *wire.Statement, signer string) {
			if v, ok := st.Body.Get(f.Name); ok {
				src := Source{Value: string(canon.Encode(v)), Signer: signer, Statement: st.ID}
				if chosen[st.ID] {
					mine = append(mine, src)
				} else {
					rivals = append(rivals, src)
				}
			}
		}
		for _, st := range s.Statements {
			add(st, st.Signer)
		}
		for _, u := range a.Units {
			for _, c := range u.Claims {
				for _, st := range c.current {
					if !chosen[st.ID] {
						add(st, c.Signer)
					}
				}
			}
		}
		sortSources(mine)
		sortSources(rivals)
		f.From, f.Rivals = mine, rivals
		switch {
		case !s.Met() && len(rivals) > 0:
			f.State = FieldSelectionUnmet
		case len(mine) == 0:
			f.State = FieldAbsent
		case distinctValues(mine) > 1:
			f.State = FieldContested
		default:
			f.State = FieldDefault
		}
		a.Fields[i] = f
	}
}

// --- workflow-declaration: replication mode and comparator (group.go) ----------------------------------------

// modeFromPolicy sets g's mode and comparator from a workflow-declaration selection for workflow wf, and
// reports whether there is one. Met with agreeing declarations: their mode and comparator, whoever authored the
// workflow first and whatever its other claimants declare. Unmet, or the principal's current claims disagree:
// no default replication (`unchecked`), nothing substituted. Either way explain cites the policy.
func (r *Resolver) modeFromPolicy(g *Group, wf string) bool {
	if r.policy == nil {
		return false
	}
	s := r.selection(wf, policy.RoleWorkflow)
	if s == nil {
		return false
	}
	if s.Met() {
		mode, comparator := str(s.Statements[0].Body, "replication"), str(s.Statements[0].Body, "comparator")
		for _, st := range s.Statements[1:] {
			if str(st.Body, "replication") != mode || str(st.Body, "comparator") != comparator {
				s.State, s.Why = SelConflict, "statements "+shorts(ids_(s.Statements))+" declare different replication or comparator; none is chosen"
				break
			}
		}
		if s.Met() {
			g.Mode, g.Comparator = mode, comparator
			if g.Mode == "" {
				g.Mode = "undeclared"
			}
			g.ModeFrom = "selected by the reader's policy (" + sourcesOf(s.Statements) + ")"
		}
	}
	if !s.Met() {
		g.ModeFrom = "the reader's workflow-declaration selection is " + s.State + ", so no default replication is read"
	}
	g.Explain = append(g.Explain, s.Explain())
	return true
}

func ids_(sts []*wire.Statement) []string {
	out := make([]string, len(sts))
	for i, st := range sts {
		out[i] = st.ID
	}
	return out
}

func sourcesOf(sts []*wire.Statement) string {
	parts := make([]string, len(sts))
	for i, st := range sts {
		parts[i] = shortKey(st.Signer) + " in " + keylog.Short(st.ID)
	}
	return strings.Join(parts, ", ")
}

// --- observation-declaration: the observation a leaf summary reads (corroboration.go) ------------------------

// observedFor is the counted `observed` statements of d a derived result's leaf summary reads: every one with
// no selection; the selected ones with a met selection; none with an unmet one (unmet names why).
func (r *Resolver) observedFor(d string) (ps []*Placed, unmet string) {
	all := r.observedOf(d, true)
	if r.policy == nil {
		return all, ""
	}
	s := r.selection(d, policy.RoleObservation)
	if s == nil {
		return all, ""
	}
	if !s.Met() {
		return nil, "reader's observation selection " + s.State
	}
	for _, p := range all {
		if slices.ContainsFunc(s.Statements, func(st *wire.Statement) bool { return st.ID == p.St.ID }) {
			ps = append(ps, p)
		}
	}
	return ps, ""
}

// observationSelection adds to an observation's explain whether the reader's policy selects it.
func (r *Resolver) observationSelection(o *Observation) {
	if r.policy == nil {
		return
	}
	o.Explain = append(o.Explain, r.policyLine())
	s := r.selection(o.Digest, policy.RoleObservation)
	if s == nil {
		return
	}
	line := s.Explain()
	if slices.ContainsFunc(s.Statements, func(st *wire.Statement) bool { return st.ID == o.Statement }) {
		line += "; this statement is selected"
	} else {
		line += "; this statement is not the selected one (shown, not read by derived results' summaries)"
	}
	o.Explain = append(o.Explain, line)
}

// --- trust (corroboration.go, group.go) ----------------------------------------------------------------------

// TrustLineUnconfigured is a run's trust line with no policy configured.
const TrustLineUnconfigured = trustLine

// runTrust sets each run's trust line: the reader's attestation trust in the runner over the run's output.
// Display only; a grade never reads it. A policy that names no principal for attestation leaves the line
// `not configured` (trust is configured per purpose).
func (r *Resolver) runTrust(g *Group) {
	if !r.policy.Configures(policy.PurposeAttestation) {
		return
	}
	for i := range g.Runs {
		g.Runs[i].Trust = "your trust in this key: " + r.policy.Trusts(g.Runs[i].Signer, policy.PurposeAttestation, g.Runs[i].Output).String()
	}
}

// trustFilter leaves out of the counts every counted piece of evidence signed by a key the reader's policy does
// not trust for corroboration over the observation's content, with the policy's answer as its cause. Trust is
// configured per purpose: with no policy, or a policy that names no principal for corroboration, nothing is
// filtered and the status says so (the current text of claims §5.3.2; see the trust note in corroboration.go).
// The reader's own computations are never filtered.
func (r *Resolver) trustFilter(c *Corroboration, o *Observation) {
	if !r.policy.Configures(policy.PurposeCorroboration) {
		c.Trust = "your trust in these keys: not configured (every counted statement is counted)"
		return
	}
	trusted, untrusted := map[string]bool{}, map[string]bool{}
	for i := range c.Evidence {
		e := &c.Evidence[i]
		if e.Reader() || e.Key == "" {
			continue
		}
		ans := r.policy.Trusts(e.Key, policy.PurposeCorroboration, o.Digest)
		if ans.Trusted() {
			trusted[e.Key] = true
			continue
		}
		untrusted[e.Key] = true
		if e.Counted {
			e.Counted = false
			if e.Cause != "" {
				e.Cause += "; "
			}
			e.Cause += ans.String()
		}
	}
	c.Trust = fmt.Sprintf("your trust in these keys: reader policy %s (%d trusted, %d not trusted for corroboration of this content; evidence from a key not trusted is shown and not counted)",
		shortPolicy(r.policy.Digest), len(trusted), len(untrusted))
}
