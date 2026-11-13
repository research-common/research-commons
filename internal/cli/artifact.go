package cli

import (
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/store"
)

// One builder per answer, shared by every command that prints it, so show, list, verify and explain print
// the same tokens for the same statements, policy and evaluator (claims-model note §11 "one validation core",
// §13; C-core-134).

// artifactCore is what every surface prints about a blob: authorship, labels, bytes, grade, and the full
// disclosure set beside the grade (claims-model note §7: "shown wherever a grade is shown", C-core-66).
func (v *view) artifactCore(a *resolve.Artifact) *Obj {
	o := newObj().set("digest", refV(a.Digest)).set("authorship", tokV(tok(string(a.State))))
	if l := v.labels(a); len(l) > 0 {
		o.set("labels", l)
	}
	o.set("bytes", tokV(tok(v.bytesState(a.Digest))))
	o.set("grade", gradeObj(a.Grade))
	if a.Step != a.Grade {
		o.set("step", tokV(tok(a.Step.Token())))
	}
	o.set("disclosures", disclosures(a))
	if len(a.Incomplete) > 0 {
		// a traversal stopped by a limit of this reader: operational, the limit and the scope it cut (C-core-131)
		l := listV{}
		for _, f := range a.Incomplete {
			l = append(l, newObj().set("class", tokV(tok(string(f.Class)))).set("reason", textV(f.Reason)).set("detail", textV(f.Detail)))
		}
		o.set("incomplete", l)
	}
	if len(a.RestsOn) > 0 {
		// what a derived result's grade rests on, scoped, beside the grade (claims-model note §7, C-core-73)
		on := make([]string, len(a.RestsOn))
		for i, x := range a.RestsOn {
			on[i] = "rests on " + x
		}
		o.set("rests_on", texts(on...))
	}
	if a.Inputs != nil {
		// the derived result's scoped summary over its inputs, declared beside computed (claims-model note §7)
		o.set("inputs_summary", texts(a.Inputs.Lines()...))
	}
	if obs := v.observationsObj(a.Digest); len(obs) > 0 {
		// each observation of the blob with its corroboration status, from the one observation view, so every
		// surface that prints the blob prints the same status (C-core-134); a disclosure, never an exit (I6)
		o.set("observations", obs)
	}
	return o
}

func gradeObj(g resolve.Grade) value {
	t := tok(g.Token())
	if g.Tier == "T1" {
		return newObj().set("grade", tokV(t)).set("under", refV(g.Under))
	}
	return tokV(t)
}

// disclosures is every disclosure field, each with its state token and, when a default exists, its value and
// signers. Values are peer-signed JSON, carried as JSON and rendered inert.
func disclosures(a *resolve.Artifact) *Obj {
	o := newObj()
	for _, name := range resolve.Disclosures {
		f := a.Field(name)
		d := newObj()
		state := string(f.State)
		if f.State == resolve.FieldAbsent && name == "licence" {
			state = "unknown" // a missing licence is never read as open (C-core-67)
		}
		if name == "licence" && a.Licence != nil && !a.Licence.Valid {
			state = "unknown" // an expression this reader cannot parse is unknown, never open (C-core-67)
		}
		d.set("state", tokV(tok(state)))
		if val, ok := f.Default(); ok {
			if cv, err := canon.Parse([]byte(val)); err == nil {
				d.set("value", rawV{cv})
			}
			var by []string
			for _, s := range f.From {
				by = append(by, s.Signer)
			}
			d.set("signers", refs(by...))
		} else if f.State == resolve.FieldContested || f.State == resolve.FieldNoDefault || f.State == resolve.FieldUnknown {
			d.set("values", sources(append(slices.Clone(f.From), f.Rivals...)))
		}
		if f.Why != "" {
			d.set("why", textV(f.Why))
		}
		switch {
		case name == "availability" && a.Availability != nil:
			availabilityObj(d, a.Availability)
		case name == "shelf_life_days" && a.ShelfLife != nil:
			shelfLifeObj(d, a.ShelfLife)
		case name == "licence" && a.Licence != nil:
			licenceObj(d, a.Licence)
		}
		o.set(name, d)
	}
	return o
}

// licenceObj adds the reader's reading of a declared licence: whether the expression parses (never whether its
// identifiers are on the SPDX list, which this tool does not ship) and where each LicenseRef's text is cited from
// (claims-model note §7, C-core-67). An expression it cannot parse is `unknown`, the reason beside it.
func licenceObj(d *Obj, l *resolve.Licence) {
	if !l.Valid {
		d.set("parse", textV(l.Why))
		return
	}
	d.set("parse", textV(resolve.LicenceChecked))
	if len(l.Refs) == 0 {
		return
	}
	rs := listV{}
	for _, r := range l.Refs {
		e := newObj().set("id", peerV(r.ID)).set("citation", textV(r.Citation))
		if r.Source != "" {
			e.set("source", peerV(r.Source))
		}
		rs = append(rs, e)
	}
	d.set("refs", rs)
}

// availabilityObj adds the reader's reading of a declared availability: redistribution and obtainability as two
// members, never one (claims-model note §7, C-core-68), and for a withheld artifact whether it was revealed.
func availabilityObj(d *Obj, av *resolve.Availability) {
	d.set("redistribution", textV(av.Redistribution)).set("obtainable_declared", boolV(av.Obtainable))
	if av.WithheldUntil != "" {
		d.set("withheld_until", peerV(av.WithheldUntil))
	}
	if av.Redistribution != "withheld" {
		return
	}
	switch {
	case av.Revealed:
		d.set("reveal", textV("revealed: a holds is published and the bytes are held here, verified by full hash"))
	case len(av.Holders) > 0:
		d.set("reveal", textV("a holds is published (holder's word); not revealed until the bytes are fetched and verified"))
	case av.Held:
		d.set("reveal", textV("not revealed: the bytes are held here but no holds is published"))
	default:
		d.set("reveal", textV("not revealed: no holds held"))
	}
}

// shelfLifeObj adds the declared validity beside the age at read time (claims-model note §7, C-core-74). The age
// is counted from a verified bound only; without one it is unknown, never computed from a self-declared time.
func shelfLifeObj(d *Obj, s *resolve.ShelfLife) {
	d.set("declared_days", intV(s.Days))
	switch {
	case s.Aged:
		verdict := "within declared validity"
		if s.Age > s.Days {
			verdict = "past declared validity"
		}
		d.set("age", textV(strconv.FormatInt(s.Age, 10)+" days, "+verdict)).set("age_from", refV(s.Since.Anchor))
	case s.Since.Quality == resolve.Bitcoin:
		d.set("age", textV("not computed (no read time)"))
	default:
		d.set("age", textV("unknown (no verified time; a self-declared time is not turned into an age)"))
	}
}

func sources(ss []resolve.Source) listV {
	l := listV{}
	for _, s := range ss {
		e := newObj().set("signer", refV(s.Signer)).set("statement", refV(s.Statement))
		if cv, err := canon.Parse([]byte(s.Value)); err == nil {
			e.set("value", rawV{cv})
		}
		l = append(l, e)
	}
	return l
}

// labels are the display labels of a blob: `retracted` when a claimant retracted its own claim (claims-model
// note §13: retraction is display; the bytes stay servable).
func (v *view) labels(a *resolve.Artifact) listV {
	owner := map[string]string{}
	for _, c := range a.Claims {
		for _, id := range c.Statements {
			if p, ok := v.r.Statement(id); ok {
				owner[id] = p.St.Signer // a retraction is its signer's own act on its own statement
			}
		}
	}
	for _, n := range a.NotCounted {
		owner[n.Statement] = n.Signer
	}
	for _, p := range a.Held {
		if p.St.Kind != "retracts" {
			continue
		}
		if s, ok := p.St.Body.Get("of"); ok {
			if of, ok := s.(canon.String); ok && owner[string(of)] == p.St.Signer {
				return tokens("retracted")
			}
		}
	}
	return nil
}

// bytesState says whether this store holds the blob's bytes intact: the blob is re-hashed on open (storage
// note §2), so a corrupt copy is not held.
func (v *view) bytesState(d string) string {
	f, err := v.st.OpenBlob(store.Digest(d))
	if err != nil {
		return "not held here"
	}
	io.Copy(io.Discard, f)
	f.Close()
	return "held here"
}

// claimants lists every claimant unit with its role, signers, provenance and time bound.
func (v *view) claimants(a *resolve.Artifact) listV {
	l := listV{}
	for _, u := range a.Units {
		role := "claimant"
		switch {
		case u == a.Default && a.State == resolve.Priority:
			role = "default author"
		case u == a.Default && a.State == resolve.Derived:
			role = "derivers"
		case u == a.Default:
			role = "author"
		case slices.Contains(a.Later, u):
			role = "later claimant"
		}
		e := newObj().set("role", tokV(tok(role)))
		var current, ids []string
		subjects := listV{}
		for _, c := range u.Claims {
			subjects = append(subjects, subjectObj(c.Subject))
			current = append(current, c.Current...)
			if !c.Subject.IsKey() {
				ids = append(ids, "identity "+c.Subject.ID)
			}
		}
		// JSON carries each claim's typed subject; both surfaces print the keys that signed the unit's statements,
		// which for key subjects is the subjects themselves, so a key-only human line is unchanged
		e.setJSON("subjects", subjects).set("signers", refs(u.Signers()...))
		if len(ids) > 0 {
			e.setHuman("for", texts(ids...))
		}
		e.set("statements", refs(current...))
		var unresolved []string
		for _, c := range u.Claims {
			unresolved = append(unresolved, c.Unresolved...)
		}
		if len(unresolved) > 0 {
			// an identity's current view is unknown (identity profile §5.1); reachable only with an actor evaluator
			e.set("current_view", tokV(tok("unknown"))).set("unresolved", texts(unresolved...))
		}
		if u.Provenance != nil {
			e.set("provenance", newObj().set("workflow", refV(u.Provenance.Workflow)).set("inputs", refs(u.Provenance.Inputs...)))
		}
		e.set("time", v.boundObj(u.Bound))
		l = append(l, e)
	}
	return l
}

// subjectObj is a claim's typed subject, tagged as the wire tags it: {"key": K} or {"identity": I}.
func subjectObj(s resolve.Subject) *Obj {
	return newObj().set(string(s.Kind), refV(s.ID))
}

// boundObj is a time bound: its quality and, for an anchor, the verifier's state token for it.
func (v *view) boundObj(b resolve.Bound) *Obj {
	o := newObj().set("quality", tokV(tok(string(b.Quality))))
	if b.Anchor != "" {
		o.set("anchor", refV(b.Anchor))
		if e, ok := v.anchorEvidence(b.Anchor); ok {
			o.set("time_state", tokV(tok(string(e.State))))
		}
	}
	return o
}

func (v *view) notCounted(a *resolve.Artifact) listV {
	l := listV{}
	for _, n := range a.NotCounted {
		e := newObj().set("statement", refV(n.Statement)).setHuman("signer", refV(n.Signer)).
			setJSON("subject", subjectObj(n.Subject)).setJSON("signers", refs(n.Signer))
		if !n.Subject.IsKey() {
			e.setHuman("for", textV("identity "+n.Subject.ID))
		}
		l = append(l, e.set("counted", tokV(tok("not counted"))).set("reason", textV(n.Why)))
	}
	return l
}

func (v *view) groups(a *resolve.Artifact) listV {
	l := listV{}
	for _, g := range a.Groups {
		e := newObj().set("workflow", refV(g.Provenance.Workflow)).set("inputs", refs(g.Provenance.Inputs...)).
			set("replication", textV(g.Mode))
		if g.ModeFrom != "" {
			e.set("replication_from", textV(g.ModeFrom))
		}
		if g.Comparator != "" {
			e.set("comparator", refV(g.Comparator))
		}
		// the group's own reasoning (why it is unchecked, diverged, re-derived by its author only): the resolver's
		// words, so a display that grades the group also says why (C-core-18a: "the workflow declares no comparator")
		if len(g.Explain) > 0 {
			e.set("explain", texts(g.Explain...))
		}
		e.set("derivers", refs(g.Derivers...))
		runs := listV{}
		for _, r := range g.Runs {
			ro := newObj().set("statement", refV(r.Statement)).set("signer", refV(r.Signer)).set("kind", textV(r.Kind)).
				set("output", refV(r.Output)).set("grade", gradeObj(r.Grade))
			if r.Says != "" {
				ro.set("runner_says", peerV(r.Says))
			}
			runs = append(runs, ro)
		}
		e.set("runs", runs)
		if g == a.Group {
			e.set("graded_from", boolV(true))
		}
		l = append(l, e)
	}
	return l
}

// held is every other statement about the blob, attributed. Peer-written text (a description's note, tags) is
// peer text: a JSON string, rendered inert and quoted (C-core-122).
func (v *view) held(a *resolve.Artifact) listV {
	l := listV{}
	for _, p := range a.Held {
		e := newObj().set("kind", textV(p.St.Kind)).set("statement", refV(p.St.ID)).set("signer", refV(p.St.Signer))
		b := p.St.Body
		for _, k := range []string{"note", "reason", "result"} {
			if s, ok := b.Get(k); ok {
				if t, ok := s.(canon.String); ok {
					e.set(k, peerV(string(t)))
				}
			}
		}
		if t, ok := b.Get("tags"); ok {
			if arr, ok := t.(canon.Array); ok {
				tl := listV{}
				for _, x := range arr {
					if s, ok := x.(canon.String); ok {
						tl = append(tl, peerV(string(s)))
					}
				}
				e.set("tags", tl)
			}
		}
		l = append(l, e)
	}
	return l
}

// verifyArtifact is `verify` for a blob from the statements held: the resolver's answer (claims-model note
// §13), and exit 4 when the claim's derivation names an input it did not pin, so there is nothing to re-run
// (execution note §1 rule 1). verify never runs anything: a re-run needs the reader's execution policy and
// an explicit request (admission is not execution).
func (v *view) verifyArtifact(d string) (int, listV) {
	code, why := v.r.Verify(d)
	causes := listV{}
	for _, w := range why {
		about, _, _ := strings.Cut(w, ": ")
		causes = append(causes, newObj().set("about", textV(about)).set("state", tokV(tok(causeToken(w)))))
	}
	// Contested authorship rests on the claimants' time bounds: each bound this reader could not verify is a
	// cause, with the verifier's state token (backend-unconfigured when no chain backend is configured).
	if a := v.r.Artifact(d); a.State == resolve.ContestedAuthorship {
		for _, u := range a.Units {
			if u.Bound.Anchor == "" {
				continue
			}
			if e, ok := v.anchorEvidence(u.Bound.Anchor); ok && !e.Live() {
				causes = append(causes, newObj().set("about", textV("time")).set("state", tokV(tok(string(e.State)))).
					set("anchor", refV(u.Bound.Anchor)))
			}
		}
	}
	if code == ExitWrong {
		return code, causes
	}
	if un := v.unpinned(d); len(un) > 0 {
		// A cause that could not be checked keeps exit 3; otherwise there is nothing to re-run.
		if code == ExitOK {
			code = ExitNothing
		}
		for _, u := range un {
			causes = append(causes, newObj().set("about", textV("input")).set("state", tokV(tok("unpinned"))).set("input", peerV(u)))
		}
	}
	return code, causes
}

// unpinned is the unpinned inputs named by the current counted claims on d (partial provenance, execution
// note §1 rule 1, in the encoding the execution layer writes).
func (v *view) unpinned(d string) []string {
	a := v.r.Artifact(d)
	var out []string
	for _, c := range a.Claims {
		for _, id := range c.Current {
			if p, ok := v.r.Statement(id); ok {
				out = append(out, unpinnedOf(p.St.Body)...)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// unpinnedOf reads `provenance_partial.unpinned` from an authored body: the encoding the execution layer
// writes (run.UnpinnedOf, checked equal by test). The CLI does not import the execution package, so no read
// command links a code path that starts a process.
func unpinnedOf(body *canon.Object) []string {
	v, ok := body.Get("provenance_partial")
	if !ok {
		return nil
	}
	po, ok := v.(*canon.Object)
	if !ok {
		return nil
	}
	u, _ := po.Get("unpinned")
	arr, _ := u.(canon.Array)
	var out []string
	for _, x := range arr {
		if s, ok := x.(canon.String); ok {
			out = append(out, string(s))
		}
	}
	return out
}

// observationCauses renders resolve.Observation.VerifyExit's reasons ("<about>: <token>[ (<detail>)]"): the token
// from the closed vocabulary, the detail (field names, a rule name) as text beside it.
func observationCauses(why []string) listV {
	causes := listV{}
	for _, w := range why {
		about, rest, _ := strings.Cut(w, ": ")
		state, detail, hasDetail := strings.Cut(rest, " (")
		c := newObj().set("about", textV(about)).set("state", tokV(tok(state)))
		if hasDetail {
			c.set("detail", textV(strings.TrimSuffix(detail, ")")))
		}
		causes = append(causes, c)
	}
	return causes
}
