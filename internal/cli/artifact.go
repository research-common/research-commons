package cli

import (
	"io"
	"slices"
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
		} else if f.State == resolve.FieldContested || f.State == resolve.FieldNoDefault {
			d.set("values", sources(append(slices.Clone(f.From), f.Rivals...)))
		}
		o.set(name, d)
	}
	return o
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
			owner[id] = c.Signer
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
		var signers, current []string
		for _, c := range u.Claims {
			signers = append(signers, c.Signer)
			current = append(current, c.Current...)
		}
		e.set("signers", refs(signers...)).set("statements", refs(current...))
		if u.Provenance != nil {
			e.set("provenance", newObj().set("workflow", refV(u.Provenance.Workflow)).set("inputs", refs(u.Provenance.Inputs...)))
		}
		e.set("time", v.boundObj(u.Bound))
		l = append(l, e)
	}
	return l
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
		l = append(l, newObj().set("statement", refV(n.Statement)).set("signer", refV(n.Signer)).
			set("counted", tokV(tok("not counted"))).set("reason", textV(n.Why)))
	}
	return l
}

func (v *view) groups(a *resolve.Artifact) listV {
	l := listV{}
	for _, g := range a.Groups {
		e := newObj().set("workflow", refV(g.Provenance.Workflow)).set("inputs", refs(g.Provenance.Inputs...)).
			set("replication", textV(g.Mode))
		if g.Comparator != "" {
			e.set("comparator", refV(g.Comparator))
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
