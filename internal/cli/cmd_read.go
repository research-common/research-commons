package cli

import (
	"slices"
	"strings"
	"time"

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
	Register(&Command{Name: "show", Summary: "show a blob (authorship, grade, every disclosure), a statement, or a resource", Args: ref, Store: true, ReaderPolicy: true,
		Help: "A digest shows the blob: authorship and every claimant, labels, whether the bytes are held here, the grade with the full disclosure set beside it, derivation groups, and every other statement about it. An id shows the statement. A resource's id is its genesis statement's id: show prints the genesis and the resource view beside it (controllers and rule, the current edition and the chain behind it by hash, every edition with its approvals, any FORK, the current edition's members and the receiver's check of a completeness claim). An edition id, or the statement id of one of its approvals, shows the resource pinned at that edition. An observation's statement shows its corroboration status. A statement on a fork of its signer's log shows the fork (FORK with its tips, or merged with the clearing line); it never changes whether the statement counts.",
		Run:  showCmd})
	Register(&Command{Name: "verify", Summary: "check a blob or a statement from the statements held; exit per the exit table", Args: ref, Store: true, ReaderPolicy: true,
		Flags:   rerunFlags,
		Prepare: prepareRerun,
		Before:  rerunBefore,
		Help:    "Statement-only by default: verify reads the statements this store holds and runs nothing. With --rerun (a blob only) and --exec-policy <file>, the reader re-runs the derivation under its own execution policy and the re-run's token replaces the derivation cause; without a policy the re-run is unchecked and nothing runs. Exit 0 checked and passed, 1 a completed comparison disagreed, 3 could not check, 4 nothing to re-run, 5 environment mismatch.",
		Run:     verifyCmd})
	Register(&Command{Name: "explain", Summary: "the statements, policy, evaluator and time context behind every token shown", Args: ref, Store: true, ReaderPolicy: true,
		Flags:   []Flag{sinceFlag},
		Prepare: prepareSince,
		Before:  sinceBefore,
		Help: "Everything show prints, plus the statements behind it (hash, signer, status, log line, counted or not; the key events of their signers are among them), the policy digests (and the reader policy document), the evaluator and the time context. For a resource (its genesis id, an edition id, or an approval's id) it adds each edition's reasoning: the rule and predecessor it was evaluated under, and each approval counted or not. " +
			"With --since <file>, an earlier explain --json of the same ref, it also prints what changed since then, each change with its cause: a statement added or removed (a key event named as one), a statement's status, log line or counted state, the hub, reader (each entry that differs) or time policy, the evaluator, or the time context; and whether the rest of the answer changed. Nothing is cached between runs: the file is the only memory. A file that is not an explain output of this ref is exit 2; otherwise the exit is explain's own.",
		Run: explainCmd})
	Register(&Command{Name: "list", Summary: "every blob a statement in this store names, and every resource, one line of tokens each", Store: true, ReaderPolicy: true,
		Help: "One line per blob a held authored or holds statement names (authorship, grade, disclosures), then one line per resource this store holds a genesis for: its id (the genesis id), its current edition (or FORK and the tips), and how many controllers the current authority has. show <resource id> prints the full resource view. Each open FORK of a held key log adds a log_forks row (key, seq, tips).",
		Run:  listCmd})
}

// viewOf is the read commands' view: the reader policy, the production contract reader, so a task's terms
// are read under the profiles this reader implements (the task section, resource.go and task.go), and the source
// profiles the store-root policy pins, so an observation's finality rule resolves through the profile its
// rule_source cites (claims-model note §5.3.1a). A pin this store cannot honour stops the command (exit 2, naming
// the entry), as it stops pull: it is never read as "no profiles".
func viewOf(c *Ctx) (*view, error) {
	opts := []resolve.Option{resolve.WithContractReader(resolve.ContractProfiles{})}
	profiles, err := storeProfiles(c)
	if err != nil {
		return nil, err
	}
	if profiles != nil {
		opts = append(opts, resolve.WithFinalityRules(*profiles))
	}
	v, err := buildView(c.Store, c.Policy.Reader, timeVerifierFor(c), opts...)
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
		return v.scoped(v.showArtifact(ref)), ExitOK, nil
	}
	return v.scoped(v.showRef(ref, false)), ExitOK, nil
}

// showRef is show of an id: the statement it names, and the resource view beside it when the statement is a
// genesis (the resource id) or an approval of an edition; an edition id, which names no statement, shows its
// resource pinned at that edition (resource.go).
func (v *view) showRef(ref string, full bool) *Obj {
	o, held := v.showStatement(ref)
	rr, ok := v.resourceOf(ref)
	if !ok {
		return o
	}
	if !held {
		// an edition id: no statement, so the statement core's "no statement held" is not printed
		o = newObj()
	}
	if rr.edition != nil {
		o.set("pinned_edition", v.editionObj(rr.edition, full))
	}
	o.set("resource_view", v.resourceObj(rr.res, full))
	if t, ok := v.taskOf(rr.res); ok {
		o.set("task", v.taskObj(t, full))
	}
	return o
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
	if a := v.actorObj(p); a != nil {
		o.set("actor", a)
	}
	// counted is the counting gate every counting consumer asks (resolve.Counted): for a bare-key statement the
	// key's own status; for an identity statement its actor's eligibility, with the key's status shown beside it
	c := v.r.Counted(p)
	if c.Counts {
		o.set("counted", tokV(tok("counted")))
		if c.Why != "" {
			o.set("reasons", texts(c.Why))
		}
	} else if p.IdentityContext() && p.Chained && p.EvidenceReady() {
		o.set("counted", tokV(tok("not counted")))
		o.set("reasons", texts(c.Why))
	} else {
		o.set("counted", tokV(tok("not counted")))
		var why []string
		why = append(why, p.After...)
		why = append(why, p.Doubted...)
		if !p.Chained {
			// the gap named as the log display names it: the missing seq range, and each unheld line a prev or
			// merges entry names by id (C-core-127b, C-core-143)
			gap := "a predecessor in the signer's log is not held"
			if ln, ok := v.logLine(st.Signer, id); ok {
				if d := ln.Waiting.Describe(st.Signer); d != "" {
					gap = "waiting for " + d
				}
			}
			why = append(why, "detached: "+gap)
		} else if !p.EvidenceReady() {
			why = append(why, "status "+string(st.Status))
		}
		o.set("reasons", texts(why...))
	}
	// a fork of the signer's log is shown beside every line on it; it never changes counted or an exit
	v.setLogForks(o, st.Signer, id)
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
	if st.Kind == "observed" {
		// corroboration status is a disclosure beside the observation (claims §5.3.2, §13, I6): shown here and on
		// verify and explain, from the one observation view, and never moves an exit
		if ob, ok := v.r.Observation(id); ok {
			if ob.BodyUnderstood && ob.ReferentStatus != "" {
				o.set("referent", referentObj(ob, true))
			}
			if ob.Corroboration != nil {
				o.set("corroboration", corroborationObj(ob.Corroboration, true))
			}
		}
	}
	return o, true
}

// referentObj is an observation's referent status as the reader computed it (claims §5.3.1, §7): the token, the
// states beside it (`provisional (R1; final at RF)` is the token `provisional` with detail `R1; final at RF`) and,
// in the full form, the history that explains it.
func referentObj(ob *resolve.Observation, full bool) *Obj {
	status, detail := ob.ReferentStatus, ""
	if !IsToken(status) {
		if i := strings.Index(status, " ("); i > 0 && strings.HasSuffix(status, ")") {
			status, detail = status[:i], status[i+2:len(status)-1]
		}
	}
	o := newObj().set("status", tokV(tok(status)))
	if detail != "" {
		o.set("detail", textV(detail))
	}
	if full && len(ob.ReferentHistory) > 0 {
		o.set("history", texts(ob.ReferentHistory...))
	}
	return o
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
		o, code, err := v.verifyRerun(c, ref)
		if err != nil {
			return nil, 0, err
		}
		return v.scoped(o), code, nil
	}
	if isDigest(ref) {
		a := v.r.Artifact(ref)
		code, causes := v.verifyArtifact(ref)
		o := v.artifactCore(a)
		if a.State == resolve.ContestedAuthorship {
			o.set("claimants", v.claimants(a))
		}
		o.set("causes", causes).set("exit", intV(int64(code))).set("exit_name", textV(ExitName(code)))
		return v.scoped(o), code, nil
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
	case st.Kind == "observed":
		// claims §13: signature and pins; corroboration and capture evidence never move the exit (I6)
		if ob, ok := v.r.Observation(ref); ok {
			var why []string
			code, why = ob.VerifyExit()
			o.set("causes", observationCauses(why))
			if ob.BodyUnderstood && ob.ReferentStatus != "" {
				// the reader's referent status (claims §5.3.1, §7): a disclosure beside the exit, like corroboration
				o.set("referent", referentObj(ob, false))
			}
			if ob.Corroboration != nil {
				// shown beside the exit, never moving it (claims §13, I6)
				o.set("corroboration", corroborationObj(ob.Corroboration, false))
			}
		}
	}
	if rr, ok := v.resourceOf(ref); ok {
		if st == nil {
			o, code = newObj(), ExitOK // an edition id names no statement: the edition is what is verified
		}
		code = v.verifyResource(o, rr, code)
	}
	o.set("exit", intV(int64(code))).set("exit_name", textV(ExitName(code)))
	return v.scoped(o), code, nil
}

// verifyResource is verify of a resource or of one pinned edition (claims-model note §8, §13), after the
// statement's own check (code). The resource: 0 with one current edition, 3 under an uncleared FORK (no edition
// is current, C-core-84) or with a contested edition (§4.1). A pinned edition: 0 when it is an authorized
// edition, 3 otherwise (pending, orphan, contested, …: not established as an edition from the statements held).
// A completeness claim's check is shown beside it and never moves the exit (I6). A task adds its own causes
// (task.go, taskCauses) for the current edition, or for the pinned edition.
func (v *view) verifyResource(o *Obj, rr resourceRef, code int) int {
	causes := listV{}
	if rr.edition != nil {
		o.set("pinned_edition", v.editionObj(rr.edition, false))
		if rr.edition.State != resolve.Authorized {
			causes = append(causes, newObj().set("about", textV("edition")).set("state", tokV(tok(string(rr.edition.State)))))
		}
	} else {
		res := rr.res
		if res.Current == "" {
			causes = append(causes, newObj().set("about", textV("current edition")).set("state", tokV(tok("FORK"))))
		}
		if len(res.Contested) > 0 {
			causes = append(causes, newObj().set("about", textV("edition")).set("state", tokV(tok("contested"))))
		}
	}
	o.set("resource_view", v.resourceObj(rr.res, false))
	if t, ok := v.taskOf(rr.res); ok {
		// a task (task-contracts note §5.7): readiness unknown or unchecked, or a decision conflict, is exit 3;
		// ready, not ready and settled by review are completed checks (not ready says "not yet", never exit 1)
		ed := ""
		if rr.edition != nil {
			ed = rr.edition.ID
		}
		o.set("task", v.taskObj(t, false))
		causes = append(causes, taskCauses(t, ed)...)
	}
	if len(causes) > 0 {
		o.set("causes", causes)
		if code == ExitOK {
			code = ExitCouldNot
		}
	}
	return code
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
		inputs = v.answerInputs(a)
		code, causes := v.verifyArtifact(ref)
		o.set("verify", newObj().set("causes", causes).set("exit", intV(int64(code))))
		o.set("reasoning", texts(a.Explain...))
	} else {
		o = v.showRef(ref, true)
		if rr, ok := v.resourceOf(ref); ok {
			inputs = append(inputs, v.resourceInputs(rr.res)...)
			if t, ok := v.taskOf(rr.res); ok {
				inputs = append(inputs, v.taskInputs(t)...)
			}
		}
		if p, ok := v.r.Statement(ref); ok {
			st := p.St
			inputs = append(inputs, ref)
			if st.Prev != "" {
				inputs = append(inputs, st.Prev)
			}
			inputs = append(inputs, st.Merges...)
			if st.Kind == "observed" {
				if ob, ok := v.r.Observation(ref); ok && ob.Corroboration != nil {
					inputs = append(inputs, corroborationInputs(ob.Corroboration)...)
				}
			}
			// showStatement prints the blob an authored names (its authorship and grade): the statements behind
			// those tokens are inputs of this answer too (I14), or a rival claim would change it unlisted
			if d := contentOf(st); d != "" && st.Kind == "authored" {
				inputs = append(inputs, v.answerInputs(v.r.Artifact(d))...)
			}
		}
	}
	inputs = append(inputs, v.keyEventInputs(inputs)...)
	slices.Sort(inputs)
	inputs = slices.Compact(inputs)
	in := listV{}
	for _, id := range inputs {
		e := newObj().set("statement", refV(id))
		if p, ok := v.r.Statement(id); ok {
			e.set("signer", refV(p.St.Signer)).set("kind", peerV(p.St.Kind)).set("status", tokV(tok(string(p.St.Status)))).
				set("line", tokV(tok(v.lineState(id))))
			if v.r.Counted(p).Counts {
				e.set("counted", tokV(tok("counted")))
			} else {
				e.set("counted", tokV(tok("not counted")))
			}
		} else {
			e.set("status", tokV(tok("no statement held")))
		}
		in = append(in, e)
	}
	o.set("statements", in)
	rp := c.Policy.readerObj()
	if c.Policy.Reader != nil {
		// the document itself, so a later explain --since can name each entry that differs (policy.Diff)
		rp.set("document", peerV(string(c.Policy.Reader.Canonical)))
	}
	o.set("policy", newObj().set("source", textV(c.Policy.Source)).set("digest", refV(c.Policy.Digest)).
		set("time_policy_fingerprint", refV(v.timeV.Policy.Fingerprint())).set("reader_policy", rp))
	o.set("evaluator", evaluatorObj(c.Env.Build))
	tc := "none: this answer does not depend on the reader's clock (no shelf life, finality or freshness is evaluated, and no chain backend is configured)"
	if v.timeV.View != nil {
		tc = chainContext(v.timeV)
	} else if v.timeV.Unavailable != "" {
		tc = "none: this answer does not depend on the reader's clock (no shelf life, finality or freshness is evaluated; the chain backend is unavailable: " + v.timeV.Unavailable + ")"
	}
	if isDigest(ref) {
		if s := v.r.Artifact(ref).ShelfLife; s != nil && s.UsedReadTime {
			tc = "read time " + v.r.ReadTime().Format(time.RFC3339) + ": the shelf-life age is counted to it from the verified bound of anchor " + s.Since.Anchor
		}
	}
	o.set("time_context", textV(tc))
	o.set("explained", refV(ref))
	if saved, ok := c.Prep.(*canon.Object); ok {
		path, _ := c.Flag("since")
		o.set("since", sinceObj(path, saved, o))
	}
	return v.scoped(o), ExitOK, nil
}

// keyEventInputs is the rotate_key and revoke_key statements in force in the log of every signer of the given
// inputs: a key event decides whether its signer's other lines count (claims-model note §4.1), so it is an input of
// every answer that reads one of them (I14), and explain --since names its arrival as a key event.
func (v *view) keyEventInputs(ids []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range ids {
		p, ok := v.r.Statement(id)
		if !ok || seen[p.St.Signer] {
			continue
		}
		seen[p.St.Signer] = true
		for _, ev := range v.logs.Log(p.St.Signer).View().KeyState().Events {
			if ev.InForce {
				out = append(out, ev.St.ID)
			}
		}
	}
	return out
}

func evaluatorObj(b Build) *Obj {
	vo := versionObj(b)
	return newObj().set("tool", vo.get("version")).set("commit", vo.get("commit")).set("time_verifier", textV(btctime.VerifierVersion))
}

// answerInputs is every statement an artifact answer read: the artifact's own (artifactInputs), the anchors
// behind each claimant's bound, and for each derivation group the counted authored statements of its workflow,
// which declare the replication mode and comparator the group is graded under (a workflow claim arriving or
// leaving changes the grade, so it is an input, I14).
func (v *view) answerInputs(a *resolve.Artifact) []string {
	ids := artifactInputs(a)
	for _, ob := range v.r.Observations(a.Digest) {
		ids = append(ids, ob.Statement)
		if ob.Corroboration != nil {
			ids = append(ids, corroborationInputs(ob.Corroboration)...)
		}
	}
	for _, u := range a.Units {
		if u.Bound.Anchor != "" {
			ids = append(ids, u.Bound.Anchor)
		}
	}
	for _, g := range a.Groups {
		for _, cl := range v.r.Artifact(g.Provenance.Workflow).Claims {
			ids = append(ids, cl.Statements...)
		}
	}
	return ids
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
	o := newObj().set("blobs", l).set("count", intV(int64(len(ds)))).set("resources", v.resourceRows())
	if fs := logForkRows(v.logs, true); len(fs) > 0 {
		// a marker per open fork of a held key log; show <id> of a line on it prints the fork in full
		o.set("log_forks", fs)
	}
	return v.scoped(o), ExitOK, nil
}

// resourceRows is list's line per held resource, by genesis id: the resource, its current edition (the genesis
// itself when no edition is authorized yet) or FORK with its tips, and the size of the current authority.
func (v *view) resourceRows() listV {
	l := listV{}
	for _, g := range v.geneses() {
		res, ok := v.r.Resource(g)
		if !ok {
			continue
		}
		row := rowObj().set("resource", refV(res.ID))
		if res.Current != "" {
			row.set("current", refV(res.Current))
			if res.Current == res.ID {
				row.set("current_is", textV("the genesis: no edition is authorized yet"))
			}
			ctl, _ := v.authorityOf(res)
			row.set("controllers", intV(int64(len(ctl))))
		} else {
			row.set("state", tokV(tok("FORK"))).set("tips", refs(res.Tips...))
		}
		if len(res.Contested) > 0 {
			row.set("contested", intV(int64(len(res.Contested))))
		}
		l = append(l, row)
	}
	return l
}
