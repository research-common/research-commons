package hubcheck

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/wire"
)

// --- rc/2 builders over the hub fixture ----------------------------------------------------------------------

// ids names the statements of one scenario; sign2 records them here.
type idWorld struct {
	s   *signer
	ids map[string]string
}

func newIDWorld() *idWorld { return &idWorld{s: newSigner(), ids: map[string]string{}} }

// put signs a statement of key n and returns its path and line. rc is "rc/1" or "rc/2"; actor names the
// statements an rc/2 line acts under ("" for none). The statement's seq and prev follow n's own log.
func (w *idWorld) put(name, n, rc, kind string, body *canon.Object, actor ...string) (string, []byte) {
	k := w.s.key(n)
	q := w.s.seq[n]
	d := wire.Draft{RC: rc, Kind: kind, Seq: q, Prev: w.s.head[n], TS: fmt.Sprintf("2026-11-13T05:%02d:%02dZ", q/60%60, q%60), Body: body}
	if rc == "rc/2" {
		if _, ok := body.Get(wire.IdentityCrit); !ok {
			d.Body = withMarker(body)
		}
		d.Crit = []string{wire.IdentityCrit}
	}
	env := d.Envelope(k)
	if len(actor) == 2 {
		env = withMember(env, wire.ActorField, obj("grant", w.ids[actor[1]], "identity", w.ids[actor[0]]))
	}
	major := 1
	if rc == "rc/2" {
		major = 2
	}
	ss := wire.PAE(wire.PayloadType(kind, major), canon.Encode(env))
	line := canon.Encode(withMember(env, "sig", canon.String(k.Sign(ss))))
	id := wire.ID(ss)
	w.ids[name], w.s.head[n], w.s.seq[n] = id, id, q+1
	return gate.StatementPath(k.Signer(), id), line
}

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

func withMarker(body *canon.Object) *canon.Object { return withMember(body, wire.IdentityCrit, obj()) }

func (w *idWorld) authored(tag string) *canon.Object {
	return obj("content", contentOf([]byte(tag)), "type", "dataset")
}

// inception, worker genesis (a bare rc/1 line: the delegate's seq 0) and the grant, in the order a hub holds them.
func (w *idWorld) inception(h *hub) {
	p, l := w.put("I", "R", "rc/2", "identity_inception", obj("profile", "fixed-root-v1"))
	h.write(p, l)
}

func (w *idWorld) workerGenesis(h *hub, worker string) {
	p, l := w.put(worker+".0", worker, "rc/1", "authored", w.authored("genesis "+worker))
	h.write(p, l)
}

func (w *idWorld) grant(h *hub, name, worker string) {
	p, l := w.put(name, "R", "rc/2", "identity_grant", obj("identity", w.ids["I"],
		"delegate", obj("key", w.s.key(worker).Signer(), "inception", w.ids[worker+".0"]),
		"permissions", canon.Array{obj("kind", "authored", "targets", obj("any_content", true), "amend", false)}))
	h.write(p, l)
}

func (w *idWorld) cut(h *hub, grant string) {
	p, l := w.put("cut "+grant, "R", "rc/2", "identity_cut", obj("identity", w.ids["I"], "grant", w.ids[grant], "last_good", canon.Null{}, "reason", "key_compromise"))
	h.write(p, l)
}

// act is an actor-bearing authored statement of key n under identity I and the named grant.
func (w *idWorld) act(h *hub, name, n, grant string) string {
	p, l := w.put(name, n, "rc/2", "authored", w.authored(name), "I", grant)
	h.write(p, l)
	return p
}

// actorOf is the actor state a check labelled path with, from the result's typed member and its label.
func actorOf(t *testing.T, res *Result, path string) *gate.ActorAnswer {
	t.Helper()
	r := verdict(t, res, path)
	if r.Verdict != gate.Admitted {
		t.Fatalf("%s: %s %v: the actor label never changes admission\n%s", path, r.Verdict, r.Refusal, res.Render())
	}
	if r.Actor == nil {
		t.Fatalf("%s: no actor answer\n%s", path, res.Render())
	}
	want := "actor: " + r.Actor.State
	if !r.HasLabel(want) {
		t.Fatalf("%s: labels %v lack %q", path, r.Labels, want)
	}
	return r.Actor
}

func wantActor(t *testing.T, res *Result, path, state, reason string) {
	t.Helper()
	a := actorOf(t, res, path)
	if a.State != state {
		t.Fatalf("%s: actor %s %v, want %s\n%s", path, a.State, a.Reasons, state, res.Render())
	}
	if reason != "" && !strings.Contains(strings.Join(a.Reasons, "; "), reason) {
		t.Fatalf("%s: actor %s reasons %v lack %q", path, a.State, a.Reasons, reason)
	}
	if res.Exit() != 0 {
		t.Fatalf("%s: a %s actor changed the exit to %d\n%s", path, state, res.Exit(), res.Render())
	}
}

// TestActorLabels: `hub check` labels the actor state of an added rc/2 statement that names an actor, over the
// evaluated set (the base's lines plus the change's admitted ones). A label only: every one of these statements is
// admitted and the exit stays 0 (I8: the hub admits, readers count).
func TestActorLabels(t *testing.T) {
	conformance.Partial(t, "C-id-02", "hub check labels an added actor statement eligible over the evidence of the base and the change, through git; the label is the evaluator's answer, admission and exit unchanged")
	conformance.Partial(t, "C-id-05", "hub check labels an act by a key the grant does not name, and an act under a cut grant, denied with the evaluator's reason; a label only")

	// the base holds the identity, a worker's genesis and the grant; the change adds one act
	t.Run("eligible act", func(t *testing.T) {
		w, h := newIDWorld(), newHub(t, "")
		w.inception(h)
		w.workerGenesis(h, "W")
		w.grant(h, "G", "W")
		h.commit("base: identity and grant")
		h.branch("act")
		p := w.act(h, "A", "W", "G")
		h.commit("an act")
		res := h.check("main")
		wantActor(t, res, p, "eligible", "")
		if a := actorOf(t, res, p); a.Identity != w.ids["I"] || a.Grant != w.ids["G"] {
			t.Fatalf("the answer names %s/%s, want the statement's own actor", a.Identity, a.Grant)
		}
	})

	t.Run("outsider key", func(t *testing.T) {
		w, h := newIDWorld(), newHub(t, "")
		w.inception(h)
		w.workerGenesis(h, "W")
		w.workerGenesis(h, "S") // a stranger with a genesis of its own: the grant names W, not S
		w.grant(h, "G", "W")
		h.commit("base")
		h.branch("act")
		p := w.act(h, "X", "S", "G")
		h.commit("an outsider claims the grant")
		res := h.check("main")
		wantActor(t, res, p, "denied", "")
		if a := actorOf(t, res, p); !strings.Contains(strings.Join(a.Reasons, "; "), "no issuer-authenticated binding") && !strings.Contains(strings.Join(a.Reasons, "; "), "binds to no identity") {
			t.Fatalf("an outsider's act is denied without saying it is bound to no identity: %v", a.Reasons)
		}
	})

	t.Run("cut grant", func(t *testing.T) {
		w, h := newIDWorld(), newHub(t, "")
		w.inception(h)
		w.workerGenesis(h, "W")
		w.grant(h, "G", "W")
		w.cut(h, "G")
		h.commit("base: the grant is cut")
		h.branch("act")
		p := w.act(h, "A", "W", "G")
		h.commit("an act under the cut grant")
		wantActor(t, h.check("main"), p, "denied", "cut_excluded")
	})

	t.Run("a change brings its own inception, grant and act", func(t *testing.T) {
		w, h := newIDWorld(), newHub(t, "")
		h.commit("empty base")
		h.branch("all")
		w.inception(h)
		w.workerGenesis(h, "W")
		w.grant(h, "G", "W")
		p := w.act(h, "A", "W", "G")
		h.commit("inception, grant and an act in one change")
		res := h.check("main")
		// authority is the root key's signature on the inception and grant the change carries, not the hub's held
		// set: the change is judged eligible by its own evidence
		wantActor(t, res, p, "eligible", "")
		// and the same tree checked in full (no base) says the same
		full := h.check("")
		wantActor(t, full, p, "eligible", "")
	})

	t.Run("an act whose grant is nowhere", func(t *testing.T) {
		w, h := newIDWorld(), newHub(t, "")
		w.inception(h)
		w.workerGenesis(h, "W")
		// the grant is signed but never written: the act names evidence no one holds
		pg, _ := w.put("G", "R", "rc/2", "identity_grant", obj("identity", w.ids["I"],
			"delegate", obj("key", w.s.key("W").Signer(), "inception", w.ids["W.0"]),
			"permissions", canon.Array{obj("kind", "authored", "targets", obj("any_content", true), "amend", false)}))
		_ = pg
		h.commit("base: the grant is missing")
		h.branch("act")
		p := w.act(h, "A", "W", "G")
		h.commit("an act under a grant nobody holds")
		wantActor(t, h.check("main"), p, "unknown", "")
	})

	t.Run("rc/1 and bare rc/2 statements carry no label", func(t *testing.T) {
		w, h := newIDWorld(), newHub(t, "")
		h.commit("empty base")
		h.branch("bare")
		w.workerGenesis(h, "W")
		pb, lb := w.put("B", "W", "rc/2", "authored", w.authored("bare rc/2"))
		h.write(pb, lb)
		h.commit("a bare rc/1 and a marker-only rc/2 statement")
		res := h.check("main")
		for _, r := range res.Results {
			if r.Actor != nil || r.HasLabel("actor: eligible") || r.HasLabel("actor: denied") || r.HasLabel("actor: unknown") {
				t.Fatalf("%s carries an actor label though it names no actor: %v", r.Path, r.Labels)
			}
		}
		if res.Exit() != 0 {
			t.Fatalf("exit %d\n%s", res.Exit(), res.Render())
		}
	})

	t.Run("an invalid rc/2 statement is labelled invalid statement", func(t *testing.T) {
		w, h := newIDWorld(), newHub(t, "")
		w.inception(h)
		h.commit("base")
		h.branch("bad")
		// a raw key event stays rc/1 in this profile: signed rc/2 revoke_key breaks a profile rule
		p, l := w.put("V", "R", "rc/2", "revoke_key", obj("reason", "key_compromise"))
		h.write(p, l)
		h.commit("an rc/2 revoke_key")
		res := h.check("main")
		r := verdict(t, res, p)
		if r.Verdict != gate.Admitted || !r.HasLabel("invalid statement") || r.HasLabel("invalid") || res.Exit() != 0 {
			t.Fatalf("%s %v exit %d\n%s", r.Verdict, r.Labels, res.Exit(), res.Render())
		}
	})
}
