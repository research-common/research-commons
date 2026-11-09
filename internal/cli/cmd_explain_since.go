package cli

import (
	"slices"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/policy"
)

// explain --since FILE: the named difference between an earlier `explain --json` of the same ref and the answer
// now (claims-model note §13, I14, I5; C-core-06, P-08). It is stateless and a pure function of the two outputs:
// nothing is cached between runs, and the tool reads nothing but the file the invocation names. Each change names
// its cause:
//
//   - a statement added to or removed from the answer's inputs (its id; a rotate_key or revoke_key is a key event,
//     with its kind), or an input whose status, log line or counted state changed (its id, before and after);
//   - the hub policy digest, the reader policy digest (with policy.Diff: every entry one side has and the other
//     lacks, read from the policy document each explain carries), or the time policy fingerprint;
//   - the evaluator (tool version, commit, time verifier) or the time context.
//
// `answer` says whether everything else explain prints (the tokens, the resource view, the verify causes) changed.
// A changed answer with no named cause is printed as such, never hidden: P-08 says it cannot happen, and a test
// holds the tool to it. The exit is explain's own; a file that is not an explain output for this ref is exit 2.

// sinceMax caps the saved explain output read by --since.
const sinceMax = 32 << 20

// sinceMembers are the members of an explain output; a file lacking one is not an explain output.
var sinceMembers = []string{"explained", "statements", "policy", "evaluator", "time_context"}

// sinceCauses are the members whose differences are causes; every other member is the answer.
var sinceCauses = []string{"explained", "statements", "policy", "evaluator", "time_context", "since", "status_scope"}

var sinceFlag = Flag{Name: "since", Value: "file",
	Help: "an earlier `explain --json` output of the same ref: print what changed since, each change with its cause (statement, key event, policy, evaluator, time context)"}

// prepareSince reads and parses the saved explain before any work: unreadable, not strict JSON, or not an explain
// output is exit 2. Whether it is for this ref is checked once aliases are resolved (sinceBefore).
func prepareSince(c *Ctx) *Problem {
	path, ok := c.Flag("since")
	if !ok {
		return nil
	}
	next := "give the file an earlier `commons explain <ref> --json` of the same ref printed"
	b, err := readCapped(path, sinceMax)
	if err != nil {
		return usage("since-unreadable", "the --since file could not be read", "nothing was done", "option --since", next, err.Error())
	}
	v, err := canon.Parse(trimNewline(b))
	if err != nil {
		return usage("since-unreadable", "the --since file is not strict JSON", "nothing was done", "option --since", next, err.Error())
	}
	o, ok := v.(*canon.Object)
	if !ok {
		return usage("since-not-explain", "the --since file is not an explain output", "it is not a JSON object; nothing was done", "option --since", next, "")
	}
	for _, m := range sinceMembers {
		if _, ok := o.Get(m); !ok {
			return usage("since-not-explain", "the --since file is not an explain output", "it has no `"+m+"` member; nothing was done", "option --since", next, m)
		}
	}
	if _, ok := o.Members["explained"].(canon.String); !ok {
		return usage("since-not-explain", "the --since file is not an explain output", "its `explained` member is not a ref; nothing was done", "option --since", next, "")
	}
	c.Prep = o
	return nil
}

// sinceBefore refuses a saved explain of another ref (after a display alias is resolved to its full hash).
func sinceBefore(c *Ctx) *Problem {
	saved, ok := c.Prep.(*canon.Object)
	if !ok {
		return nil
	}
	if was := string(saved.Members["explained"].(canon.String)); was != c.Args["digest|id"] {
		return usage("since-other-ref", "the --since file explains another ref",
			"it is an explain output of another ref (named in peer_text), not of the ref given; nothing was done",
			"option --since", "give an explain output of this ref, or explain the ref that file names", was)
	}
	return nil
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// sinceObj is the difference between the saved explain and the current one (cur, the explain tree before since is
// added), each change with its cause.
func sinceObj(path string, saved *canon.Object, cur *Obj) *Obj {
	now := toCanon(cur).(*canon.Object)
	var changes listV
	changes = append(changes, statementChanges(saved, now)...)
	changes = append(changes, policyChanges(saved, now)...)
	if a, b := encodeMember(saved, "evaluator"), encodeMember(now, "evaluator"); a != b {
		changes = append(changes, rowObj().set("change", tokV(tok("evaluator changed"))).set("from", peerV(a)).set("to", textV(b)))
	}
	if a, b := encodeMember(saved, "time_context"), encodeMember(now, "time_context"); a != b {
		changes = append(changes, rowObj().set("change", tokV(tok("time context changed"))).set("from", peerV(a)).set("to", textV(b)))
	}
	if changes == nil {
		changes = listV{}
	}
	o := newObj().set("file", peerV(path))
	answer := "answer unchanged"
	if answerOf(saved) != answerOf(now) {
		answer = "answer changed"
	}
	o.set("answer", tokV(tok(answer))).set("changes", changes)
	if answer == "answer changed" && len(changes) == 0 {
		o.set("unexplained", textV("the answer changed and no statement, policy, evaluator or time context change was found; report this: every answer is a function of those"))
	}
	return o
}

// answerOf is the canonical text of everything an explain output prints except its causes.
func answerOf(o *canon.Object) string {
	a := &canon.Object{Members: map[string]canon.Value{}}
	for _, k := range o.Keys {
		if !slices.Contains(sinceCauses, k) {
			a.Keys = append(a.Keys, k)
			a.Members[k] = o.Members[k]
		}
	}
	return string(canon.Encode(a))
}

func encodeMember(o *canon.Object, k string) string {
	v, ok := o.Get(k)
	if !ok {
		return "(none)"
	}
	if s, ok := v.(canon.String); ok {
		return string(s)
	}
	return string(canon.Encode(v))
}

// inputEntry is one row of an explain output's statements.
type inputEntry struct {
	kind, status, line, counted string
}

func inputsOf(o *canon.Object) (map[string]inputEntry, []string) {
	out := map[string]inputEntry{}
	var ids []string
	l, _ := o.Members["statements"].(canon.Array)
	for _, x := range l {
		e, ok := x.(*canon.Object)
		if !ok {
			continue
		}
		id := stringMember(e, "statement")
		if id == "" {
			continue
		}
		if _, dup := out[id]; !dup {
			ids = append(ids, id)
		}
		out[id] = inputEntry{kind: stringMember(e, "kind"), status: stringMember(e, "status"), line: stringMember(e, "line"), counted: stringMember(e, "counted")}
	}
	slices.Sort(ids)
	return out, ids
}

func stringMember(o *canon.Object, k string) string {
	if s, ok := o.Members[k].(canon.String); ok {
		return string(s)
	}
	return ""
}

func isKeyEvent(kind string) bool { return kind == "rotate_key" || kind == "revoke_key" }

// statementChanges names every input added, removed or changed, by statement id.
func statementChanges(saved, now *canon.Object) listV {
	was, wasIDs := inputsOf(saved)
	is, isIDs := inputsOf(now)
	var l listV
	for _, id := range isIDs {
		e, held := was[id]
		n := is[id]
		if !held {
			ch := "statement added"
			if isKeyEvent(n.kind) {
				ch = "key event"
			}
			r := rowObj().set("change", tokV(tok(ch))).set("statement", refV(id))
			if n.kind != "" {
				r.set("kind", peerV(n.kind))
			}
			l = append(l, r)
			continue
		}
		for _, d := range []struct{ ch, a, b string }{{"status changed", e.status, n.status}, {"line changed", e.line, n.line}, {"counted changed", e.counted, n.counted}} {
			if d.a != d.b && d.a != "" && d.b != "" {
				r := rowObj().set("change", tokV(tok(d.ch))).set("statement", refV(id))
				if n.kind != "" {
					r.set("kind", peerV(n.kind))
				}
				l = append(l, r.set("from", peerV(d.a)).set("to", textV(d.b)))
			}
		}
	}
	for _, id := range wasIDs {
		if _, ok := is[id]; ok {
			continue
		}
		r := rowObj().set("change", tokV(tok("statement removed"))).set("statement", peerV(id))
		if k := was[id].kind; k != "" {
			r.set("kind", peerV(k))
		}
		l = append(l, r)
	}
	return l
}

// policyChanges names a changed hub policy, reader policy (with policy.Diff over the two documents) or time policy.
func policyChanges(saved, now *canon.Object) listV {
	sp, _ := saved.Members["policy"].(*canon.Object)
	np, _ := now.Members["policy"].(*canon.Object)
	if sp == nil {
		sp = &canon.Object{Members: map[string]canon.Value{}}
	}
	var l listV
	for _, m := range []struct{ key, ch string }{{"digest", "policy changed"}, {"time_policy_fingerprint", "time policy changed"}} {
		if a, b := encodeMember(sp, m.key), encodeMember(np, m.key); a != b {
			l = append(l, rowObj().set("change", tokV(tok(m.ch))).set("from", peerV(a)).set("to", textV(b)))
		}
	}
	srp, _ := sp.Members["reader_policy"].(*canon.Object)
	nrp, _ := np.Members["reader_policy"].(*canon.Object)
	digestOf := func(o *canon.Object) string {
		if o == nil {
			return "(none)"
		}
		if d := stringMember(o, "digest"); d != "" {
			return d
		}
		return "(none)"
	}
	a, b := digestOf(srp), digestOf(nrp)
	if a == b {
		return l
	}
	r := rowObj().set("change", tokV(tok("reader policy changed"))).set("from", peerV(a)).set("to", textV(b))
	sd, sok := readerDocument(srp)
	nd, _ := readerDocument(nrp)
	if !sok {
		r.set("detail", textV("the saved output carries no reader policy document the reader can parse, so the entries that differ are not named"))
		return append(l, r)
	}
	// policy.Diff's first line repeats the digests; the rest names each entry one side has and the other lacks
	d := policy.Diff(sd, nd)
	if len(d) > 1 {
		r.set("entries", texts(d[1:]...))
	}
	return append(l, r)
}

// readerDocument parses the reader policy document an explain output carries; (nil, true) when none is configured.
func readerDocument(o *canon.Object) (*policy.Policy, bool) {
	if o == nil || stringMember(o, "digest") == "" {
		return nil, true
	}
	doc := stringMember(o, "document")
	if doc == "" {
		return nil, false
	}
	p, err := policy.Parse([]byte(doc))
	if err != nil {
		return nil, false
	}
	return p, true
}
