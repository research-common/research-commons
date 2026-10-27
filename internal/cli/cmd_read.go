package cli

import (
	"slices"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// The read commands: show, verify, explain, list. Each builds one view of the store and prints from the shared
// builders in artifact.go. None executes anything, fetches anything, or writes to the store beyond the journal
// replay every open performs (storage note §3.4).

func init() {
	ref := []Arg{{Name: "digest|id", Shape: ShapeRef}}
	Register(&Command{Name: "show", Summary: "show a blob (authorship, grade, every disclosure) or a statement", Args: ref, Store: true, ReaderPolicy: true,
		Help: "A digest shows the blob: authorship and every claimant, labels, whether the bytes are held here, the grade with the full disclosure set beside it, derivation groups, and every other statement about it. An id shows the statement.",
		Run:  showCmd})
	Register(&Command{Name: "verify", Summary: "check a blob or a statement from the statements held; exit per the exit table", Args: ref, Store: true, ReaderPolicy: true,
		Flags:   rerunFlags,
		Prepare: prepareRerun,
		Help:    "Statement-only by default: verify reads the statements this store holds and runs nothing. With --rerun (a blob only) and --exec-policy <file>, the reader re-runs the derivation under its own execution policy and the re-run's token replaces the derivation cause; without a policy the re-run is unchecked and nothing runs. Exit 0 checked and passed, 1 a completed comparison disagreed, 3 could not check, 4 nothing to re-run, 5 environment mismatch.",
		Run:     verifyCmd})
	Register(&Command{Name: "explain", Summary: "the statements, policy, evaluator and time context behind every token shown", Args: ref, Store: true, ReaderPolicy: true,
		Run: explainCmd})
	Register(&Command{Name: "list", Summary: "every blob a statement in this store names, one line of tokens each", Store: true, ReaderPolicy: true,
		Run: listCmd})
}

func viewOf(c *Ctx) (*view, error) {
	v, err := loadView(c.Store, c.Policy.Reader)
	if err != nil {
		return nil, failed(err, "store", false, "run status, then fsck")
	}
	return v, nil
}

// --- show --------------------------------------------------------------------------------------------------

func showCmd(c *Ctx) (*Obj, int, error) {
	v, err := viewOf(c)
	if err != nil {
		return nil, 0, err
	}
	ref := c.Args["digest|id"]
	if isDigest(ref) {
		return v.showArtifact(ref), ExitOK, nil
	}
	o, _ := v.showStatement(ref)
	return o, ExitOK, nil
}

func (v *view) showArtifact(d string) *Obj {
	a := v.r.Artifact(d)
	o := v.artifactCore(a)
	o.set("claimants", v.claimants(a))
	if nc := v.notCounted(a); len(nc) > 0 {
		o.set("not_counted", nc)
	}
	if g := v.groups(a); len(g) > 0 {
		o.set("groups", g)
	}
	if h := v.held(a); len(h) > 0 {
		o.set("statements_about", h)
	}
	o.set("holders", refs(a.Holders...))
	return o
}

// statementCore is a statement as every surface prints it: kind, signer, its status token, its place in the
// signer's log and whether it counts.
func (v *view) statementCore(id string) (*Obj, *wire.Statement) {
	p, ok := v.r.Statement(id)
	if !ok {
		if st := v.retained(id); st != nil {
			return newObj().set("statement", refV(id)).set("kind", peerV(st.Kind)).set("signer", refV(st.Signer)).
				set("status", tokV(tok(string(st.Status)))).set("line", tokV(tok("retained"))).
				set("counted", tokV(tok("not counted"))), st
		}
		return newObj().set("statement", refV(id)).set("status", tokV(tok("no statement held"))), nil
	}
	st := p.St
	o := newObj().set("statement", refV(id)).set("kind", peerV(st.Kind)).set("signer", refV(st.Signer)).
		set("seq", intV(st.Seq)).set("ts_signer_declared", refV(st.TS.Text)).
		set("status", tokV(tok(string(st.Status)))).set("line", tokV(tok(v.lineState(id))))
	if p.Counts() {
		o.set("counted", tokV(tok("counted")))
	} else {
		o.set("counted", tokV(tok("not counted")))
		var why []string
		why = append(why, p.After...)
		why = append(why, p.Doubted...)
		if !p.Chained {
			why = append(why, "detached: a predecessor in the signer's log is not held")
		} else if !p.EvidenceReady() {
			why = append(why, "status "+string(st.Status))
		}
		o.set("reasons", texts(why...))
	}
	return o, st
}

// retained finds an unverified line kept in its signer's log and not placed (another rc major, an unknown alg).
func (v *view) retained(id string) *wire.Statement {
	for _, k := range v.logs.Keys() {
		for _, st := range v.logs.Log(k).View().Retained {
			if st.ID == id {
				return st
			}
		}
	}
	return nil
}

func (v *view) showStatement(id string) (*Obj, bool) {
	o, st := v.statementCore(id)
	if st == nil {
		return o, false
	}
	if st.Status == wire.Valid && st.Body != nil {
		// the body is the signer's word: a JSON value, rendered inert
		o.set("body", rawV{st.Body})
	}
	if st.Kind == "anchors" {
		if e, ok := v.anchorEvidence(id); ok {
			o.set("time", evidenceObj(e))
		}
	}
	if d := contentOf(st); d != "" && st.Kind == "authored" {
		o.set("artifact", v.artifactCore(v.r.Artifact(d)))
	}
	return o, true
}

func contentOf(st *wire.Statement) string {
	if st.Body == nil {
		return ""
	}
	c, ok := st.Body.Get("content")
	if !ok {
		return ""
	}
	co, ok := c.(*canon.Object)
	if !ok {
		return ""
	}
	if dv, ok := co.Get("digest"); ok {
		if d, ok := dv.(canon.String); ok {
			return string(d)
		}
	}
	return ""
}

func evidenceObj(e btctime.Evidence) *Obj {
	o := newObj().set("quality", tokV(tok(string(e.Quality)))).set("time_state", tokV(tok(string(e.State))))
	if e.Why != "" {
		o.set("why", textV(e.Why))
	}
	o.set("policy_fingerprint", refV(e.PolicyFingerprint)).set("verifier_version", textV(e.VerifierVersion))
	return o
}

// --- verify ------------------------------------------------------------------------------------------------

func verifyCmd(c *Ctx) (*Obj, int, error) {
	v, err := viewOf(c)
	if err != nil {
		return nil, 0, err
	}
	ref := c.Args["digest|id"]
	if _, rerun := c.Flag("rerun"); rerun {
		return v.verifyRerun(c, ref)
	}
	if isDigest(ref) {
		a := v.r.Artifact(ref)
		code, causes := v.verifyArtifact(ref)
		o := v.artifactCore(a)
		if a.State == resolve.ContestedAuthorship {
			o.set("claimants", v.claimants(a))
		}
		o.set("causes", causes).set("exit", intV(int64(code))).set("exit_name", textV(ExitName(code)))
		return o, code, nil
	}
	o, st := v.statementCore(ref)
	code := ExitOK
	switch {
	case st == nil:
		code = ExitCouldNot
	case st.Status != wire.Valid || o.get("line") != tokV("chained"):
		code = ExitCouldNot
	case st.Kind == "anchors":
		e, _ := v.anchorEvidence(ref)
		o.set("time", evidenceObj(e))
		code = btctime.Exit([]btctime.Evidence{e})
	}
	o.set("exit", intV(int64(code))).set("exit_name", textV(ExitName(code)))
	return o, code, nil
}

// --- explain -----------------------------------------------------------------------------------------------

func explainCmd(c *Ctx) (*Obj, int, error) {
	v, err := viewOf(c)
	if err != nil {
		return nil, 0, err
	}
	ref := c.Args["digest|id"]
	var o *Obj
	var inputs []string
	if isDigest(ref) {
		a := v.r.Artifact(ref)
		o = v.showArtifact(ref)
		inputs = artifactInputs(a)
		for _, u := range a.Units {
			if u.Bound.Anchor != "" {
				inputs = append(inputs, u.Bound.Anchor)
			}
		}
		code, causes := v.verifyArtifact(ref)
		o.set("verify", newObj().set("causes", causes).set("exit", intV(int64(code))))
		o.set("reasoning", texts(a.Explain...))
	} else {
		var held bool
		o, held = v.showStatement(ref)
		if p, ok := v.r.Statement(ref); held && ok {
			st := p.St
			inputs = append(inputs, ref)
			if st.Prev != "" {
				inputs = append(inputs, st.Prev)
			}
			inputs = append(inputs, st.Merges...)
		}
	}
	slices.Sort(inputs)
	inputs = slices.Compact(inputs)
	in := listV{}
	for _, id := range inputs {
		e := newObj().set("statement", refV(id))
		if p, ok := v.r.Statement(id); ok {
			e.set("signer", refV(p.St.Signer)).set("kind", peerV(p.St.Kind)).set("status", tokV(tok(string(p.St.Status)))).
				set("line", tokV(tok(v.lineState(id))))
		} else {
			e.set("status", tokV(tok("no statement held")))
		}
		in = append(in, e)
	}
	o.set("statements", in)
	o.set("policy", newObj().set("source", textV(c.Policy.Source)).set("digest", refV(c.Policy.Digest)).
		set("time_policy_fingerprint", refV(v.timeV.Policy.Fingerprint())).set("reader_policy", c.Policy.readerObj()))
	o.set("evaluator", evaluatorObj(c.Env.Build))
	o.set("time_context", textV("none: this answer does not depend on the reader's clock (no shelf life, finality or freshness is evaluated, and no chain backend is configured)"))
	return o, ExitOK, nil
}

func evaluatorObj(b Build) *Obj {
	vo := versionObj(b)
	return newObj().set("tool", vo.get("version")).set("commit", vo.get("commit")).set("time_verifier", textV(btctime.VerifierVersion))
}

// artifactInputs is every statement the artifact view read: claims (current and amended), statements not
// counted, statements about it, and every run of every group.
func artifactInputs(a *resolve.Artifact) []string {
	var ids []string
	for _, cl := range a.Claims {
		ids = append(ids, cl.Statements...)
	}
	for _, n := range a.NotCounted {
		ids = append(ids, n.Statement)
	}
	for _, p := range a.Held {
		ids = append(ids, p.St.ID)
	}
	for _, g := range a.Groups {
		for _, r := range g.Runs {
			ids = append(ids, r.Statement)
		}
	}
	return ids
}

// --- list --------------------------------------------------------------------------------------------------

func listCmd(c *Ctx) (*Obj, int, error) {
	v, err := viewOf(c)
	if err != nil {
		return nil, 0, err
	}
	var ds []string
	for _, p := range v.r.All() {
		if p.St.Kind == "authored" || p.St.Kind == "holds" {
			if d := contentOf(p.St); d != "" {
				ds = append(ds, d)
			}
		}
	}
	slices.Sort(ds)
	ds = slices.Compact(ds)
	l := listV{}
	for _, d := range ds {
		l = append(l, v.artifactCore(v.r.Artifact(d)))
	}
	return newObj().set("blobs", l).set("count", intV(int64(len(ds)))), ExitOK, nil
}
