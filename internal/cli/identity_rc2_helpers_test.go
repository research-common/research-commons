package cli

import (
	"fmt"
	"slices"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// rc/2 statements for the CLI tests of the identity reader. The writer signs rc/1 only, so these are signed here
// exactly as the profile's builders sign them (wire.Draft with an rc/2 envelope, the actor added to the signed
// envelope) and committed through the store, which reads them with the production reader.

// withMember returns a copy of o with k set to v, keys in canonical order.
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

// rc2Line signs the rc/2 line key n would write next; actor is {identity, grant}, or empty for a marker-only line.
func (w *world) rc2Line(n, kind string, body *canon.Object, actor [2]string) ([]byte, string) {
	k := w.key(n)
	s := w.seq[n]
	b := body
	if _, ok := body.Get(wire.IdentityCrit); !ok {
		b = withMember(body, wire.IdentityCrit, obj())
	}
	d := wire.Draft{RC: "rc/2", Kind: kind, Seq: s, Prev: w.head[n], TS: fmt.Sprintf("2026-10-16T03:%02d:%02dZ", s/60%60, s%60),
		Crit: []string{wire.IdentityCrit}, Body: b}
	env := d.Envelope(k)
	if actor[0] != "" {
		env = withMember(env, wire.ActorField, obj("grant", actor[1], "identity", actor[0]))
	}
	ss := wire.PAE(wire.PayloadType(kind, 2), canon.Encode(env))
	return canon.Encode(withMember(env, "sig", canon.String(k.Sign(ss)))), wire.ID(ss)
}

// signRC2 signs and commits key n's next rc/2 line.
func (w *world) signRC2(name, n, kind string, body *canon.Object, actor [2]string) string {
	w.t.Helper()
	line, id := w.rc2Line(n, kind, body, actor)
	if _, err := w.s.Commit("publish", [][]byte{line}, nil); err != nil {
		w.t.Fatalf("%s: %v", name, err)
	}
	w.head[n], w.seq[n] = id, w.seq[n]+1
	w.ids[name] = id
	return id
}

// identityOf signs root's inception of an identity and a grant to each worker (authored, any content, amend
// mode amend); each worker must already have signed its first line (the grant names it). It returns I and each
// worker's actor.
func (w *world) identityOf(name, root string, amend canon.Value, workers ...string) (string, map[string][2]string) {
	w.t.Helper()
	i := w.signRC2(name, root, "identity_inception", obj("profile", wire.FixedRootProfile), [2]string{})
	actors := map[string][2]string{}
	for _, wk := range workers {
		if w.seq[wk] == 0 {
			w.t.Fatalf("%s has no first line for a grant to name", wk)
		}
		first := w.ids["first:"+wk]
		perms := canon.Array{obj("kind", "authored", "targets", obj("any_content", true), "amend", amend)}
		g := w.signRC2(name+":grant:"+wk, root, "identity_grant", obj("identity", i,
			"delegate", obj("key", w.signer(wk), "inception", first), "permissions", perms), [2]string{})
		actors[wk] = [2]string{i, g}
	}
	return i, actors
}

// worker signs key n's first line (an rc/1 authored of its own blob), the inception a grant names.
func (w *world) worker(n string) {
	w.t.Helper()
	w.ids["first:"+n] = w.authored("first:"+n, n, "own-"+n)
}

// pullInto pulls this world's store into a fresh one and returns it.
func (w *world) pullInto() *world {
	w.t.Helper()
	pkg := w.t.TempDir()
	copyData(w.t, w.root, pkg)
	dst := newWorld(w.t)
	if r := dst.run("pull", pkg, "--json"); r.code != ExitOK {
		w.t.Fatalf("pull: %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	return dst
}
