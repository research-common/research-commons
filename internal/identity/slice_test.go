package identity_test

// The signed vertical slice: every statement below is signed with a disposable synthetic key, serialized to the
// exact line a peer would send, and admitted through wire.IdentityReader + identity.Admit. No test constructs an
// identitymodel.Fact or sets an authentication flag.

import (
	"crypto/sha256"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/identitymodel"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

const ts = "2026-10-21T00:00:00Z"

func key(name string, eip bool) wire.Key {
	h := sha256.Sum256([]byte("research-commons go test identity slice key " + name))
	if eip {
		return wire.EIP191Key{Scalar: h[:]}
	}
	return wire.Ed25519Key{Seed: h[:]}
}

func obj(kv ...any) *canon.Object {
	o := &canon.Object{Members: map[string]canon.Value{}}
	for i := 0; i < len(kv); i += 2 {
		var v canon.Value
		switch x := kv[i+1].(type) {
		case string:
			v = canon.String(x)
		case int:
			v = canon.Int(x)
		case bool:
			v = canon.Bool(x)
		case nil:
			v = canon.Null{}
		case []string:
			a := canon.Array{}
			for _, s := range x {
				a = append(a, canon.String(s))
			}
			v = a
		case canon.Value:
			v = x
		default:
			panic("obj")
		}
		o.Keys = append(o.Keys, kv[i].(string))
		o.Members[kv[i].(string)] = v
	}
	return o
}

func digest(b byte) string { return "sha256:" + strings.Repeat(string("0123456789abcdef"[b%16]), 64) }

// stmt is one statement to sign. parent "" means seq 0; otherwise the named line is prev and seq is its seq+1.
type stmt struct {
	name, by, parent string
	rc, kind         string
	body             *canon.Object
	actor            [2]string // names of identity inception and grant
	merges           []string
	crit             []string
	noMarker         bool
}

type world struct {
	t     *testing.T
	keys  map[string]wire.Key
	ids   map[string]string
	seqs  map[string]int64
	lines map[string][]byte
	order []string
}

func newWorld(t *testing.T) *world {
	w := &world{t: t, keys: map[string]wire.Key{}, ids: map[string]string{}, seqs: map[string]int64{}, lines: map[string][]byte{}}
	w.keys["R"] = key("root", true) // EIP-191 root, Ed25519 workers: both required algorithms on the path
	w.keys["K1"] = key("worker-1", false)
	w.keys["K2"] = key("worker-2", false)
	w.keys["S"] = key("stranger", false)
	return w
}

func (w *world) signer(name string) string { return w.keys[name].Signer() }

// sign builds the exact envelope, signs PAE(type major, JCS(envelope)) and stores the received line.
func (w *world) sign(s stmt) string {
	w.t.Helper()
	k := w.keys[s.by]
	rc := s.rc
	if rc == "" {
		rc = "rc/2"
	}
	body := s.body
	crit := s.crit
	if rc == "rc/2" && !s.noMarker {
		if _, ok := body.Get(wire.IdentityCrit); !ok {
			body = withField(body, wire.IdentityCrit, obj())
		}
		if crit == nil {
			crit = []string{wire.IdentityCrit}
		}
	}
	d := wire.Draft{RC: rc, Kind: s.kind, TS: ts, Crit: crit, Body: body}
	if s.parent != "" {
		d.Prev, d.Seq = w.ids[s.parent], w.seqs[s.parent]+1
	}
	for _, m := range s.merges {
		d.Merges = append(d.Merges, w.ids[m])
	}
	slices.Sort(d.Merges)
	env := d.Envelope(k)
	if s.actor[0] != "" {
		env = withField(env, wire.ActorField, obj("grant", w.ids[s.actor[1]], "identity", w.ids[s.actor[0]]))
	}
	major := 1
	switch rc {
	case "rc/2":
		major = 2
	case "rc/3":
		major = 3
	}
	ss := wire.PAE(wire.PayloadType(s.kind, major), canon.Encode(env))
	line := canon.Encode(withField(env, "sig", canon.String(k.Sign(ss))))
	w.ids[s.name], w.seqs[s.name], w.lines[s.name] = wire.ID(ss), d.Seq, line
	w.order = append(w.order, s.name)
	return wire.ID(ss)
}

func withField(o *canon.Object, k string, v canon.Value) *canon.Object {
	out := &canon.Object{Members: map[string]canon.Value{}}
	for _, x := range o.Keys {
		if x != k {
			out.Keys = append(out.Keys, x)
			out.Members[x] = o.Members[x]
		}
	}
	out.Keys = append(out.Keys, k)
	out.Members[k] = v
	return out
}

func authoredBody(b byte) *canon.Object {
	return obj("content", obj("digest", digest(b), "size", 10), "type", "dataset")
}

func (w *world) grantBody(worker string, perms ...canon.Value) *canon.Object {
	slices.SortFunc(perms, func(a, b canon.Value) int { return canon.CompareKeys(string(canon.Encode(a)), string(canon.Encode(b))) })
	return obj("identity", w.ids["I"], "delegate", obj("key", w.signer(worker), "inception", w.ids[worker+".0"]),
		"permissions", canon.Array(perms))
}

func authoredAny() canon.Value {
	return obj("kind", "authored", "targets", obj("any_content", true), "amend", false)
}

func cutBody(w *world, grant, lastGood string) *canon.Object {
	var lg any
	if lastGood != "" {
		lg = w.ids[lastGood]
	}
	return obj("identity", w.ids["I"], "grant", w.ids[grant], "last_good", lg, "reason", "key_compromise")
}

// base is §D steps 1–2: root inception, two worker inceptions and grants, worker acts for I.
//
//	R:  I(0) ── G1(1) ── G2(2)
//	K1: K1.0(0, bare rc/1) ── A1(1, I/G1) ── A2(2, I/G1)
//	                     └─── A1x(1, I/G1)   sibling fork
//	K2: K2.0(0, bare rc/1) ── B1(1, I/G2, content 0x2) ── B2(2, I/G2, content 0x3: out of scope)
func base(t *testing.T) *world {
	w := newWorld(t)
	w.sign(stmt{name: "I", by: "R", kind: "identity_inception", body: obj("profile", "fixed-root-v1")})
	w.sign(stmt{name: "K1.0", by: "K1", rc: "rc/1", kind: "authored", body: authoredBody(9)})
	w.sign(stmt{name: "K2.0", by: "K2", rc: "rc/1", kind: "authored", body: authoredBody(8)})
	w.sign(stmt{name: "G1", by: "R", parent: "I", kind: "identity_grant", body: w.grantBody("K1", authoredAny())})
	w.sign(stmt{name: "G2", by: "R", parent: "G1", kind: "identity_grant", body: w.grantBody("K2",
		obj("kind", "authored", "targets", obj("contents", []string{digest(2)}), "amend", false))})
	w.sign(stmt{name: "A1", by: "K1", parent: "K1.0", kind: "authored", body: authoredBody(1), actor: [2]string{"I", "G1"}})
	w.sign(stmt{name: "A2", by: "K1", parent: "A1", kind: "authored", body: authoredBody(4), actor: [2]string{"I", "G1"}})
	w.sign(stmt{name: "A1x", by: "K1", parent: "K1.0", kind: "authored", body: authoredBody(5), actor: [2]string{"I", "G1"}})
	w.sign(stmt{name: "B1", by: "K2", parent: "K2.0", kind: "authored", body: authoredBody(2), actor: [2]string{"I", "G2"}})
	w.sign(stmt{name: "B2", by: "K2", parent: "B1", kind: "authored", body: authoredBody(3), actor: [2]string{"I", "G2"}})
	return w
}

func (w *world) admit(names ...string) *identity.Snapshot {
	w.t.Helper()
	if names == nil {
		names = w.order
	}
	var lines [][]byte
	for _, n := range names {
		lines = append(lines, w.lines[n])
	}
	s, err := identity.Admit(lines)
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

func without(all []string, drop ...string) []string {
	var out []string
	for _, n := range all {
		if !slices.Contains(drop, n) {
			out = append(out, n)
		}
	}
	return out
}

func (w *world) expect(s *identity.Snapshot, name string, want identitymodel.Status, code string) identitymodel.Result {
	w.t.Helper()
	r := s.Evaluate(w.ids[name])
	if r.Status != want {
		w.t.Fatalf("%s: status %s, want %s; reasons %+v", name, r.Status, want, r.Reasons)
	}
	if code != "" && !hasReason(r, code) {
		w.t.Fatalf("%s: no reason %q in %+v", name, code, r.Reasons)
	}
	if r.Freshness != identitymodel.NotEstablished {
		w.t.Fatalf("%s: freshness %q claimed", name, r.Freshness)
	}
	return r
}

func hasReason(r identitymodel.Result, code string) bool {
	for _, x := range r.Reasons {
		if x.Code == code {
			return true
		}
	}
	return false
}

// Steps 1–2: transported, signed evidence authorizes explicit acts for I, per grant and scope.
func TestSliceGrantsAuthorizeExplicitActs(t *testing.T) {
	w := base(t)
	s := w.admit()
	if n := len(s.Refused()); n != 0 {
		t.Fatalf("refused %d lines: %+v", n, s.Refused())
	}
	for _, n := range []string{"A1", "A2", "A1x", "B1"} {
		r := w.expect(s, n, identitymodel.Eligible, "")
		if r.Actor.Kind != identitymodel.IdentitySubject || string(r.Actor.Identity) != w.ids["I"] {
			t.Fatalf("%s: actor %+v", n, r.Actor)
		}
		if string(r.Signer) == w.signer("R") {
			t.Fatalf("%s: actual signer replaced by root", n)
		}
	}
	w.expect(s, "B2", identitymodel.Denied, "scope_excluded")
	// Bare statements are not identity acts: the legacy evaluator owns them.
	r := w.expect(s, "K1.0", identitymodel.Denied, "no_identity_actor")
	if r.Actor.Kind != identitymodel.KeySubject {
		t.Fatalf("bare actor %+v", r.Actor)
	}
	// Admin statements are not delegable operations.
	if st, verified := s.Status(w.ids["G1"]); st != wire.Valid || !verified {
		t.Fatalf("grant read as %s verified=%v", st, verified)
	}
}

// Step 3: an exact cut preserves L's inclusive ancestry, excludes descendants and siblings, spares other grants.
func TestSliceCutAtExactLine(t *testing.T) {
	w := base(t)
	w.sign(stmt{name: "C1", by: "R", parent: "G2", kind: "identity_cut", body: cutBody(w, "G1", "A1")})
	s := w.admit()
	w.expect(s, "A1", identitymodel.Eligible, "")
	w.expect(s, "A2", identitymodel.Denied, "cut_excluded")
	w.expect(s, "A1x", identitymodel.Denied, "cut_excluded")
	w.expect(s, "B1", identitymodel.Eligible, "")
	r := s.Evaluate(w.ids["A2"])
	if !slices.Contains(r.RelevantCuts, identitymodel.ID(w.ids["C1"])) {
		t.Fatalf("cut not explained: %+v", r.RelevantCuts)
	}
	// A null cut preserves nothing; a later wider cut does not reopen (intersection).
	w.sign(stmt{name: "C0", by: "R", parent: "C1", kind: "identity_cut", body: cutBody(w, "G1", "")})
	w.sign(stmt{name: "Cwide", by: "R", parent: "C0", kind: "identity_cut", body: cutBody(w, "G1", "A2")})
	s = w.admit()
	w.expect(s, "A1", identitymodel.Denied, "cut_excluded")
	w.expect(s, "A2", identitymodel.Denied, "cut_excluded")
	w.expect(s, "B1", identitymodel.Eligible, "")
}

// Step 4: the worker's own revocation does not erase opted-in history; bare-key behavior stays legacy.
func TestSliceWorkerSelfRevocation(t *testing.T) {
	w := base(t)
	w.sign(stmt{name: "Krev", by: "K1", rc: "rc/1", parent: "A2", kind: "revoke_key", body: obj("reason", "key_compromise", "last_good", w.ids["K1.0"])})
	w.sign(stmt{name: "K1.after", by: "K1", rc: "rc/1", parent: "Krev", kind: "authored", body: authoredBody(7)})
	s := w.admit()
	r := w.expect(s, "A2", identitymodel.Eligible, "")
	if len(r.Warnings) == 0 || r.Warnings[0].Code != "delegate_self_event" {
		t.Fatalf("self-revocation not visible: %+v", r.Warnings)
	}
	w.expect(s, "A1", identitymodel.Eligible, "")

	// The unchanged legacy reader on the same bytes: rc/2 is retained unverified, the rc/1 revoke chains through
	// it, and the bare-key counting rule is untouched.
	store := keylog.NewStore()
	for _, n := range w.order {
		if !strings.HasPrefix(n, "K1") && n != "A1" && n != "A2" && n != "A1x" && n != "Krev" {
			continue
		}
		if _, err := store.Log(w.signer("K1")).Add(w.lines[n]); err != nil {
			t.Fatalf("legacy add %s: %v", n, err)
		}
	}
	res := resolve.New(store)
	if p, ok := res.Statement(w.ids["K1.after"]); !ok || p.Counts() {
		t.Fatalf("bare line after hard revoke counts in legacy reader: %+v", p)
	}
	if p, ok := res.Statement(w.ids["A2"]); !ok || p.Evaluable || p.St.Verified {
		t.Fatalf("legacy reader evaluated an rc/2 line: %+v", p)
	}
	if p, ok := res.Statement(w.ids["K1.0"]); !ok || !p.Counts() {
		t.Fatalf("bare line within last_good lost legacy standing: %+v", p)
	}
}

// Step 5: wrong root/key/lineage/scope/actor or tampering never passes; missing evidence never falls back.
func TestSliceNegatives(t *testing.T) {
	t.Run("stranger-issued grant naming I", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "S.0", by: "S", rc: "rc/1", kind: "authored", body: authoredBody(6)})
		w.sign(stmt{name: "Gs", by: "S", parent: "S.0", kind: "identity_grant", body: w.grantBody("K2", authoredAny())})
		w.sign(stmt{name: "B3", by: "K2", parent: "B2", kind: "authored", body: authoredBody(6), actor: [2]string{"I", "Gs"}})
		w.expect(w.admit(), "B3", identitymodel.Denied, "wrong_signer")
	})
	t.Run("grant used by another key", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "B3", by: "K2", parent: "B2", kind: "authored", body: authoredBody(6), actor: [2]string{"I", "G1"}})
		w.expect(w.admit(), "B3", identitymodel.Denied, "wrong_delegate")
	})
	t.Run("same key, other lineage", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "K1.new", by: "K1", rc: "rc/1", kind: "authored", body: authoredBody(11)})
		w.sign(stmt{name: "A9", by: "K1", parent: "K1.new", kind: "authored", body: authoredBody(12), actor: [2]string{"I", "G1"}})
		w.expect(w.admit(), "A9", identitymodel.Denied, "wrong_lineage")
	})
	t.Run("actor names grant as identity", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: authoredBody(12), actor: [2]string{"G1", "G1"}})
		w.expect(w.admit(), "A9", identitymodel.Denied, "invalid_identity_inception")
	})
	t.Run("operation kind outside grant", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "H", by: "K1", parent: "A2", kind: "holds", body: obj("content", obj("digest", digest(1), "size", 10)), actor: [2]string{"I", "G1"}})
		w.expect(w.admit(), "H", identitymodel.Denied, "scope_excluded")
	})
	t.Run("tampered actor bytes", func(t *testing.T) {
		w := base(t)
		forged := strings.Replace(string(w.lines["B1"]), w.ids["G2"], w.ids["G1"], 1)
		s, err := identity.Admit([][]byte{[]byte(forged)})
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Refused()) != 1 {
			t.Fatalf("tampered line admitted: %+v", s.Refused())
		}
	})
	t.Run("bad-signature copy cannot shadow a real grant", func(t *testing.T) {
		w := base(t)
		real := string(w.lines["G1"])
		i := strings.Index(real, `"sig":"0x`) + len(`"sig":"0x`)
		bad := real[:i] + map[bool]string{true: "1", false: "0"}[real[i] == '0'] + real[i+1:]
		lines := [][]byte{[]byte(bad)}
		for _, n := range w.order {
			lines = append(lines, w.lines[n])
		}
		s, err := identity.Admit(lines)
		if err != nil {
			t.Fatal(err)
		}
		if r := s.Evaluate(w.ids["A1"]); r.Status != identitymodel.Eligible {
			t.Fatalf("bad copy displaced the real grant: %+v", r.Reasons)
		}
	})
	t.Run("missing grant: unknown, no key fallback", func(t *testing.T) {
		w := base(t)
		r := w.expect(w.admit(without(w.order, "G1")...), "A1", identitymodel.Unknown, "missing_evidence")
		if r.Actor.Kind != identitymodel.IdentitySubject {
			t.Fatalf("fell back to key subject: %+v", r.Actor)
		}
	})
	t.Run("missing worker ancestry: unknown", func(t *testing.T) {
		w := base(t)
		w.expect(w.admit(without(w.order, "A1")...), "A2", identitymodel.Unknown, "missing_evidence")
	})
	t.Run("rc/1 envelope actor is never upgraded", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "A9", by: "K1", rc: "rc/1", parent: "A2", kind: "authored", body: authoredBody(12), actor: [2]string{"I", "G1"}})
		w.expect(w.admit(), "A9", identitymodel.Denied, "no_identity_actor")
	})
	t.Run("actor without critical marker", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: authoredBody(12), actor: [2]string{"I", "G1"}, noMarker: true})
		s := w.admit()
		if st, verified := s.Status(w.ids["A9"]); st != wire.Invalid || !verified {
			t.Fatalf("read as %s/%v", st, verified)
		}
		w.expect(s, "A9", identitymodel.Denied, "invalid_actor_binding")
	})
	t.Run("unknown extra critical feature", func(t *testing.T) {
		w := base(t)
		b := withField(authoredBody(12), "x_future", obj())
		w.sign(stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: b, actor: [2]string{"I", "G1"},
			crit: []string{"x_future", wire.IdentityCrit}})
		w.expect(w.admit(), "A9", identitymodel.Unknown, "unsupported_actor_binding")
	})
	t.Run("amendment needs amend:true", func(t *testing.T) {
		w := base(t)
		amend := obj("amends", []string{w.ids["A1"]})
		w.sign(stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: withField(authoredBody(1), wire.IdentityCrit, amend), actor: [2]string{"I", "G1"}})
		w.expect(w.admit(), "A9", identitymodel.Denied, "scope_excluded")
		w2 := base(t)
		w2.sign(stmt{name: "G9", by: "R", parent: "G2", kind: "identity_grant", body: w2.grantBody("K1",
			obj("kind", "authored", "targets", obj("any_content", true), "amend", true))})
		w2.sign(stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: withField(authoredBody(1), wire.IdentityCrit, obj("amends", []string{w2.ids["A1"]})), actor: [2]string{"I", "G9"}})
		w2.expect(w2.admit(), "A9", identitymodel.Eligible, "")
	})
	t.Run("unknown permission kind is not broader", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "G9", by: "R", parent: "G2", kind: "identity_grant", body: w.grantBody("K2", authoredAny(), obj("kind", "zz_future"))})
		w.sign(stmt{name: "B3", by: "K2", parent: "B2", kind: "authored", body: authoredBody(6), actor: [2]string{"I", "G9"}})
		w.expect(w.admit(), "B3", identitymodel.Unknown, "unsupported_evidence")
	})
}

// Step 6: a known authenticated unresolved or malformed cut blocks a clean pass; an unseen cut is the documented
// evidence-relative limitation (no freshness claim).
func TestSliceCutUncertainty(t *testing.T) {
	t.Run("cut whose last_good is not held", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "C1", by: "R", parent: "G2", kind: "identity_cut", body: cutBody(w, "G1", "A1")})
		w.expect(w.admit(without(w.order, "A1")...), "A1x", identitymodel.Unknown, "missing_evidence")
	})
	t.Run("authenticated malformed cut addressed to G1", func(t *testing.T) {
		w := base(t)
		b := cutBody(w, "G1", "A1")
		b.Members["reason"] = canon.String("Not A Token")
		w.sign(stmt{name: "Cbad", by: "R", parent: "G2", kind: "identity_cut", body: b})
		if old, err := wire.Read(w.lines["Cbad"]); err != nil || old.Verified {
			t.Fatalf("precondition: the unchanged reader retains rc/2 unverified: %+v %v", old, err)
		}
		s := w.admit()
		if st, verified := s.Status(w.ids["Cbad"]); st != wire.Invalid || !verified {
			t.Fatalf("malformed cut read as %s/%v", st, verified)
		}
		w.expect(s, "A1", identitymodel.Denied, "invalid_evidence")
		w.expect(s, "B1", identitymodel.Eligible, "")
	})
	t.Run("authenticated cut with no readable grant", func(t *testing.T) {
		w := base(t)
		b := cutBody(w, "G1", "A1")
		b.Members["grant"] = canon.String("not-an-id")
		w.sign(stmt{name: "Cbad", by: "R", parent: "G2", kind: "identity_cut", body: b})
		s := w.admit()
		w.expect(s, "A1", identitymodel.Unknown, "unsupported_root_event")
		w.expect(s, "B1", identitymodel.Unknown, "unsupported_root_event")
	})
	t.Run("unseen cut", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "C1", by: "R", parent: "G2", kind: "identity_cut", body: cutBody(w, "G1", "")})
		r := w.expect(w.admit(without(w.order, "C1")...), "A2", identitymodel.Eligible, "")
		if r.Freshness != identitymodel.NotEstablished {
			t.Fatal("freshness claimed")
		}
	})
	t.Run("forged root cut from a stranger", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "S.0", by: "S", rc: "rc/1", kind: "authored", body: authoredBody(6)})
		w.sign(stmt{name: "Cs", by: "S", parent: "S.0", kind: "identity_cut", body: cutBody(w, "G1", "")})
		w.expect(w.admit(), "A2", identitymodel.Eligible, "")
	})
}

// Step 7: root-terminal events, reverse/duplicate delivery, rebuild and explanations.
func TestSliceRootTerminalAndDelivery(t *testing.T) {
	t.Run("valid root revoke is terminal for all history", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "Rrev", by: "R", rc: "rc/1", parent: "G2", kind: "revoke_key", body: obj("reason", "superseded", "last_good", w.ids["G2"])})
		s := w.admit()
		for _, n := range []string{"A1", "B1"} {
			w.expect(s, n, identitymodel.Denied, "root_retired")
		}
	})
	t.Run("valid root rotate is terminal; no successor", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "Rrot", by: "R", rc: "rc/1", parent: "G2", kind: "rotate_key", body: obj("successor", w.signer("S"))})
		w.expect(w.admit(), "A1", identitymodel.Denied, "root_retired")
	})
	t.Run("malformed root key event is unknown, not ineffective", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "Rrev", by: "R", rc: "rc/1", parent: "G2", kind: "revoke_key", body: obj("reason", "Bad Reason")})
		if _, err := wire.Read(w.lines["Rrev"]); err == nil {
			t.Fatal("precondition: the unchanged reader refuses (drops) this authentic line")
		}
		w.expect(w.admit(), "A1", identitymodel.Unknown, "unsupported_root_event")
	})
	t.Run("rc/2 root key event is outside the profile: unknown", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "Rrev", by: "R", parent: "G2", kind: "revoke_key", body: obj("reason", "superseded")})
		w.expect(w.admit(), "A1", identitymodel.Unknown, "unsupported_root_event")
	})
	t.Run("vouched future-major root line is unknown for every grant", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "R3", by: "R", rc: "rc/3", parent: "G2", kind: "identity_cut", body: obj("future", true)})
		w.sign(stmt{name: "Rdesc", by: "R", rc: "rc/1", parent: "R3", kind: "describes", body: obj("about", obj("statement", w.ids["I"]), "note", "ops")})
		s := w.admit()
		if st, verified := s.Status(w.ids["R3"]); st != wire.Unsupported || verified {
			t.Fatalf("rc/3 read as %s/%v", st, verified)
		}
		w.expect(s, "A1", identitymodel.Unknown, "unsupported_root_event")
		w.expect(s, "B1", identitymodel.Unknown, "unsupported_root_event")
		// Unvouched, the same bytes are indistinguishable from a forgery naming R as signer: no effect.
		w.expect(w.admit(without(w.order, "Rdesc")...), "A1", identitymodel.Eligible, "")
	})
	t.Run("vouched future-major worker line is ancestry", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "K3", by: "K1", rc: "rc/3", parent: "A2", kind: "authored", body: obj("future", true)})
		w.sign(stmt{name: "A3", by: "K1", parent: "K3", kind: "authored", body: authoredBody(12), actor: [2]string{"I", "G1"}})
		w.expect(w.admit(), "A3", identitymodel.Eligible, "")
	})
	t.Run("root describes is inert", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "Rdesc", by: "R", rc: "rc/1", parent: "G2", kind: "describes", body: obj("about", obj("statement", w.ids["I"]), "note", "ops")})
		w.expect(w.admit(), "A1", identitymodel.Eligible, "")
	})
	t.Run("order, duplicates and rebuild", func(t *testing.T) {
		w := base(t)
		w.sign(stmt{name: "C1", by: "R", parent: "G2", kind: "identity_cut", body: cutBody(w, "G1", "A1")})
		ref := w.admit()
		rng := rand.New(rand.NewPCG(7, 21))
		for i := 0; i < 12; i++ {
			names := slices.Clone(w.order)
			names = append(names, names[rng.IntN(len(names))], names[rng.IntN(len(names))])
			rng.Shuffle(len(names), func(a, b int) { names[a], names[b] = names[b], names[a] })
			if i == 0 {
				slices.Reverse(names)
			}
			s := w.admit(names...)
			if s.Receipt() != ref.Receipt() || s.EvidenceDigest() != ref.EvidenceDigest() {
				t.Fatalf("permutation %d changed digests", i)
			}
			for _, n := range w.order {
				if !reflect.DeepEqual(s.Evaluate(w.ids[n]), ref.Evaluate(w.ids[n])) {
					t.Fatalf("permutation %d changed %s", i, n)
				}
			}
		}
	})
	t.Run("explanations carry exact basis", func(t *testing.T) {
		w := base(t)
		r := w.expect(w.admit(), "A2", identitymodel.Eligible, "")
		for _, n := range []string{"I", "G1", "K1.0", "A1", "A2"} {
			if !slices.Contains(r.Basis, identitymodel.ID(w.ids[n])) {
				t.Fatalf("basis lacks %s: %v", n, r.Basis)
			}
		}
		if string(r.Grant) != w.ids["G1"] || string(r.DelegateInception) != w.ids["K1.0"] || string(r.RootLineage) != w.ids["I"] {
			t.Fatalf("pins: %+v", r)
		}
	})
}
