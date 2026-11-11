package resolve

import (
	"fmt"
	"slices"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// This file signs candidate rc/2 lines into a world: the fixed-root identity profile's root inception and
// grants, and acts by worker keys with an actor, with the marker only, tampered, or authenticated but invalid.
// Every line is a real signature over the profile's exact envelope (PAE of the v2 payload type); nothing builds
// a Placed by hand. Readers see the lines only through a store (dualStore for the candidate reader).

// rc2Act is how an rc/2 line is signed.
type rc2Act int

const (
	rc2Actor      rc2Act = iota // marker + an x_actor_v1 naming identity/grant
	rc2MarkerOnly               // marker, no actor: a key(K) statement on an identity-aware body (D-1108b-3)
)

// signRC2 appends an rc/2 statement to key n's log, chained after its head. actor is [identity, grant] statement
// ids for rc2Actor.
func (w *world) signRC2(name, n, kind string, body *canon.Object, act rc2Act, actor [2]string) string {
	w.t.Helper()
	line, id := w.rc2Line(n, kind, body, act, actor)
	w.head[n], w.seq[n] = id, w.seq[n]+1
	w.lines = append(w.lines, line)
	w.ids[name], w.by[id] = id, n
	return id
}

// rc2Line signs (without appending) the rc/2 line key n would write next.
func (w *world) rc2Line(n, kind string, body *canon.Object, act rc2Act, actor [2]string) ([]byte, string) {
	k := w.key(n)
	s := w.seq[n]
	b := body
	if _, ok := body.Get(wire.IdentityCrit); !ok {
		b = withMember(body, wire.IdentityCrit, obj()) // the marker, unless the caller wrote one (amends)
	}
	d := wire.Draft{RC: "rc/2", Kind: kind, Seq: s, Prev: w.head[n], TS: fmt.Sprintf("2026-10-16T03:%02d:%02dZ", s/60%60, s%60),
		Crit: []string{wire.IdentityCrit}, Body: b}
	env := d.Envelope(k)
	if act == rc2Actor {
		env = withMember(env, wire.ActorField, obj("grant", actor[1], "identity", actor[0]))
	}
	ss := wire.PAE(wire.PayloadType(kind, 2), canon.Encode(env))
	return canon.Encode(withMember(env, "sig", canon.String(k.Sign(ss)))), wire.ID(ss)
}

// withMember returns a copy of o with k set to v.
func withMember(o *canon.Object, k string, v canon.Value) *canon.Object {
	out := &canon.Object{Members: map[string]canon.Value{}}
	for _, x := range o.Keys {
		if x != k {
			out.Keys = append(out.Keys, x)
			out.Members[x] = o.Members[x]
		}
	}
	out.Keys = append(out.Keys, k)
	out.Members[k] = v
	slices.SortFunc(out.Keys, canon.CompareKeys)
	return out
}

// firstLine is the id of key n's seq-0 line among the world's lines (the delegate's inception a grant names).
func (w *world) firstLine(n string) string {
	w.t.Helper()
	for _, l := range w.lines {
		st, err := wire.Read(l)
		if err == nil && st.Signer == w.signer(n) && st.Seq == 0 {
			return st.ID
		}
	}
	w.t.Fatalf("key %s has no seq-0 line yet", n)
	return ""
}

// identityOf incepts identity name with a fresh root key root (seq 0 of its log) and grants each worker every
// delegable kind the tests use, over any target. It returns the inception id and one grant id per worker.
func (w *world) identityOf(name, root string, workers ...string) (string, map[string]string) {
	w.t.Helper()
	if w.seq[root] != 0 {
		w.t.Fatalf("root %s is not fresh", root)
	}
	id := w.signRC2(name, root, "identity_inception", obj("profile", wire.FixedRootProfile), rc2MarkerOnly, [2]string{})
	grants := map[string]string{}
	for _, wk := range workers {
		perms := canon.Array{
			obj("kind", "authored", "targets", obj("any_content", true), "amend", false),
			obj("kind", "corroborates", "targets", obj("any_statement", true)),
			obj("kind", "holds", "targets", obj("any_content", true)),
			obj("kind", "observed", "targets", obj("any_content", true), "amend", false),
		}
		slices.SortFunc(perms, func(a, b canon.Value) int { return canon.CompareKeys(string(canon.Encode(a)), string(canon.Encode(b))) })
		grants[wk] = w.signRC2(name+":grant:"+wk, root, "identity_grant", obj("identity", id,
			"delegate", obj("key", w.signer(wk), "inception", w.firstLine(wk)), "permissions", perms), rc2MarkerOnly, [2]string{})
	}
	return id, grants
}

// tamper returns line with one byte of its signature changed: the dual reader refuses it (bad signature), the
// unchanged reader retains it unverified (another major).
func tamper(line []byte) []byte {
	v, _ := canon.Parse(line)
	o := v.(*canon.Object)
	s := []byte(string(o.Members["sig"].(canon.String)))
	i := len(s) - 3
	if s[i] == '0' {
		s[i] = '1'
	} else {
		s[i] = '0'
	}
	o.Members["sig"] = canon.String(s)
	return canon.Encode(o)
}

// deliverAll delivers lines into s in order. A line the store's reader refuses is dropped (a tampered rc/2 line
// under the dual reader), exactly as a pull would drop it; the count of refusals is returned.
func deliverAll(s *keylog.Store, lines [][]byte) (refused int) {
	for _, ln := range lines {
		st, err := s.Read(ln)
		if err != nil {
			refused++
			continue
		}
		if kept, err := s.Log(st.Signer).Add(ln); err != nil && kept == nil {
			refused++
		}
	}
	return refused
}
