package keylog

import (
	"crypto/sha256"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/wire"
)

func obj(kv ...any) *canon.Object {
	o := &canon.Object{Members: map[string]canon.Value{}}
	for i := 0; i < len(kv); i += 2 {
		k := kv[i].(string)
		o.Keys = append(o.Keys, k)
		switch v := kv[i+1].(type) {
		case string:
			o.Members[k] = canon.String(v)
		case int:
			o.Members[k] = canon.Int(v)
		case canon.Value:
			o.Members[k] = v
		}
	}
	slices.SortFunc(o.Keys, canon.CompareKeys)
	return o
}

func ts(seq int64) string {
	return "2026-10-16T01:" + string(rune('0'+seq/10%6)) + string(rune('0'+seq%10)) + ":00Z"
}

func signed(k wire.Key, kind string, seq int64, prev string, body *canon.Object, merges ...string) line {
	b, id := wire.Sign(wire.Draft{Kind: kind, Seq: seq, Prev: prev, TS: ts(seq), Merges: merges, Body: body}, k)
	return line{b, id}
}

func rotate(k wire.Key, seq int64, prev string, to wire.Key, merges ...string) line {
	return signed(k, "rotate_key", seq, prev, obj("successor", to.Signer()), merges...)
}

func revoke(k wire.Key, seq int64, prev, reason string) line {
	return signed(k, "revoke_key", seq, prev, obj("reason", reason, "last_good", prev))
}

func authored(k wire.Key, seq int64, prev string, tag byte) line {
	d := sha256.Sum256([]byte{tag})
	c := obj("digest", "sha256:"+hexs(d[:]), "size", 1)
	return signed(k, "authored", seq, prev, obj("content", canon.Value(c), "type", "dataset"))
}

func hexs(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, x := range b {
		out = append(out, h[x>>4], h[x&15])
	}
	return string(out)
}

func edKey(name string) wire.Key {
	h := sha256.Sum256([]byte("research-commons go test ed key " + name))
	return wire.Ed25519Key{Seed: h[:]}
}

func eipKey(name string) wire.Key {
	h := sha256.Sum256([]byte("research-commons go test eip key " + name))
	return wire.EIP191Key{Scalar: h[:]}
}

// TestCrossAlgorithmRotation: C-core-144 (a). An authored by an Ed25519 key, a rotate_key by that key to a
// secp256k1 key, an authored by the successor. All three verify, the rotation is in force, the successor
// statement chains in its own log, and the succession is reported across algorithms. Every delivery order
// (into either log first) gives the same answer.
func TestCrossAlgorithmRotation(t *testing.T) {
	conformance.Partial(t, "C-core-144", "(a) cross-algorithm rotation chain: checked here; (b), (c): see the wire tests; verdicts across two Ed25519 libraries not run")
	old, succ := edKey("old"), eipKey("successor")
	a0 := authored(old, 0, "", 1)
	r1 := rotate(old, 1, a0.id, succ)
	b0 := authored(succ, 0, "", 2)
	type d struct {
		k wire.Key
		l line
	}
	all := []d{{old, a0}, {old, r1}, {succ, b0}}
	var want string
	for _, p := range perms(len(all)) {
		s := NewStore()
		for _, i := range p {
			st, err := s.Log(all[i].k.Signer()).Add(all[i].l.bytes)
			if err != nil || !st.Verified {
				t.Fatalf("%v (verified %v)", err, st != nil && st.Verified)
			}
		}
		ov, sv := s.Log(old.Signer()).View(), s.Log(succ.Signer()).View()
		for _, v := range []View{ov, sv} {
			for _, ln := range v.Lines {
				if ln.State != Chained {
					t.Fatalf("%s", v.Render())
				}
			}
		}
		ks := ov.KeyState()
		if len(ks.Events) != 1 || !ks.Events[0].InForce || ks.Events[0].Successor != succ.Signer() || ks.Events[0].St.Alg != wire.AlgEd25519 {
			t.Fatalf("%+v\n%s", ks.Events, ov.Render())
		}
		got := s.Successions()
		if len(got) != 1 || got[0] != (Succession{From: old.Signer(), To: succ.Signer(), Event: r1.id}) {
			t.Fatalf("%+v", got)
		}
		r := ov.Render() + sv.Render()
		if want == "" {
			want = r
		} else if r != want {
			t.Fatalf("order %v renders differently:\n%s\nvs\n%s", p, r, want)
		}
	}
	if !strings.Contains(want, "rotate_key to "+succ.Signer()+", in force") {
		t.Fatalf("%s", want)
	}
}

// TestRotationWaitsForMergedTip: C-core-127b, rotate_key variant. L (a rotate_key) and S fork at one point;
// M follows S and merges L. A reader holding S and M but not L: M is detached naming L, no FORK, the rotation
// is not known at all, and nothing is "after" it. When L arrives: the fork shows cleared, the rotation is in
// force, and it applies to M and its descendants (the lines after L as the log orders them), never to S.
func TestRotationWaitsForMergedTip(t *testing.T) {
	conformance.Partial(t, "C-core-127b", "rotate_key variant at the log layer: rotation not known while L is missing, in force on arrival, after-L = M and its descendants and never S, nothing rewritten, every order: checked; evaluating the clearing line under the C-core-143 gap rules needs the resolver")
	a, succ := key("A"), key("Z")
	base := chain(a, 2)
	L := rotate(a, 2, base[1].id, succ)
	S := mk(a, 2, base[1].id, 0xbb, "")
	M := mk(a, 3, S.id, 0xcc, "", L.id)
	N := mk(a, 4, M.id, 0xdd, "")

	s := NewStore()
	deliver(t, s, a, base[0], base[1], S, M, N)
	v := s.Log(a.Signer()).View()
	ks := v.KeyState()
	if len(v.Forks) != 0 || len(ks.Events) != 0 || len(ks.After) != 0 {
		t.Fatalf("before L:\n%s", v.Render())
	}
	for _, ln := range v.Lines {
		want := Chained
		if ln.St.ID == M.id || ln.St.ID == N.id {
			want = Detached
		}
		if ln.State != want {
			t.Fatalf("seq %d is %s:\n%s", ln.St.Seq, ln.State, v.Render())
		}
	}
	if !strings.Contains(v.Render(), "detached: waiting for "+L.id) {
		t.Fatalf("%s", v.Render())
	}
	before := map[string]State{}
	for _, ln := range v.Lines {
		if ln.State == Chained {
			before[ln.St.ID] = ln.State
		}
	}

	deliver(t, s, a, L)
	v = s.Log(a.Signer()).View()
	ks = v.KeyState()
	if len(v.Forks) != 1 || !v.Forks[0].Cleared() || v.Forks[0].ClearedBy != M.id {
		t.Fatalf("after L:\n%s", v.Render())
	}
	if len(ks.Events) != 1 || !ks.Events[0].InForce || ks.Events[0].St.ID != L.id {
		t.Fatalf("%+v", ks.Events)
	}
	for _, id := range []string{M.id, N.id} {
		if !slices.Equal(ks.After[id], []string{L.id}) {
			t.Fatalf("%s after %v:\n%s", Short(id), ks.After[id], v.Render())
		}
	}
	for _, id := range []string{base[0].id, base[1].id, S.id, L.id} {
		if len(ks.After[id]) != 0 {
			t.Fatalf("%s is not after L in the log's order:\n%s", Short(id), v.Render())
		}
	}
	// Nothing decided while waiting is rewritten: every line chained before is still chained.
	for _, ln := range v.Lines {
		if _, was := before[ln.St.ID]; was && ln.State != Chained {
			t.Fatalf("%s changed state", Short(ln.St.ID))
		}
	}
	// Same answer in every delivery order.
	out, _ := renderAll(t, a, []line{base[0], base[1], L, S, M, N}, nil)
	if out != v.Render() {
		t.Fatalf("%s\nvs\n%s", out, v.Render())
	}
}

// TestRevocationWaitsForGap: C-core-143 at the key-event layer. seq 40 is revoke_key (key_compromise), seq 41
// follows. With 40 missing: 41 is detached, no event is known, nothing is after anything. With 40 held: the
// revocation is in force, reports its reason and last_good, and seq 41 is after it. Variant: 40 never
// arrives and nothing is refused.
func TestRevocationWaitsForGap(t *testing.T) {
	conformance.Partial(t, "C-core-143", "revocation not in force while seq 40 is missing, in force after, seq 41 after it, no refusal while waiting: checked; the observed counting toward nothing and the edition not applied need the resolver")
	k := key("K")
	ls := chain(k, 40)
	rv := revoke(k, 40, ls[39].id, "key_compromise")
	l41 := mk(k, 41, rv.id, 41, "")
	s := NewStore()
	deliver(t, s, k, ls...)
	deliver(t, s, k, l41)
	v := s.Log(k.Signer()).View()
	if ks := v.KeyState(); len(ks.Events) != 0 || len(ks.After) != 0 || len(v.Refused) != 0 {
		t.Fatalf("%s", v.Render())
	}
	deliver(t, s, k, rv)
	v = s.Log(k.Signer()).View()
	ks := v.KeyState()
	if len(ks.Events) != 1 || !ks.Events[0].InForce || ks.Events[0].Reason != "key_compromise" ||
		ks.Events[0].LastGood != ls[39].id || !ks.Events[0].Hard() {
		t.Fatalf("%+v", ks.Events)
	}
	if !slices.Equal(ks.After[l41.id], []string{rv.id}) || len(ks.After) != 1 {
		t.Fatalf("%v\n%s", ks.After, v.Render())
	}
	if !strings.Contains(v.Render(), "revoke_key (key_compromise, hard) last_good "+Short(ls[39].id)+", in force") {
		t.Fatalf("%s", v.Render())
	}
}

// TestDetachedEventNotInForce: a key event that is itself detached is listed and not in force (§7: "a
// detached rotate_key or revoke_key is not yet in force"); nothing is after it.
func TestDetachedEventNotInForce(t *testing.T) {
	k, z := key("K"), key("Z")
	ls := chain(k, 3)
	r := rotate(k, 3, ls[2].id, z)
	after := mk(k, 4, r.id, 4, "")
	s := NewStore()
	deliver(t, s, k, ls[0], ls[1], r, after)
	v := s.Log(k.Signer()).View()
	ks := v.KeyState()
	if len(ks.Events) != 1 || ks.Events[0].InForce || len(ks.After) != 0 || len(s.Successions()) != 0 {
		t.Fatalf("%+v\n%s", ks, v.Render())
	}
	if !strings.Contains(v.Render(), "not in force (detached)") {
		t.Fatalf("%s", v.Render())
	}
}

// TestEventScopedToBranch: on an uncleared fork, a revocation on one branch applies to that branch's
// descendants only; the other branch is not "after" it. Two rotations on two branches are both reported.
func TestEventScopedToBranch(t *testing.T) {
	k := key("K")
	base := chain(k, 2)
	rv := revoke(k, 2, base[1].id, "superseded")
	other := mk(k, 2, base[1].id, 0x22, "")
	below := mk(k, 3, rv.id, 0x33, "")
	beside := mk(k, 3, other.id, 0x44, "")
	out, v := renderAll(t, k, []line{base[0], base[1], rv, other, below, beside}, nil)
	ks := v.KeyState()
	if len(v.Forks) != 1 || v.Forks[0].Cleared() {
		t.Fatalf("%s", out)
	}
	if !slices.Equal(ks.After[below.id], []string{rv.id}) || len(ks.After[beside.id]) != 0 || len(ks.After[other.id]) != 0 {
		t.Fatalf("%v\n%s", ks.After, out)
	}
	s := NewStore()
	a, b := key("Za"), key("Zb")
	deliver(t, s, k, base[0], base[1], rotate(k, 2, base[1].id, a), rotate(k, 2, base[1].id, b))
	if got := s.Successions(); len(got) != 2 || got[0].To == got[1].To {
		t.Fatalf("%+v", got)
	}
}

// TestCritEventIgnored: a rotate_key whose crit names an extension this reader lacks is evaluated under no
// interpretation (wire §6): it chains as a line but is not a key event.
func TestCritEventIgnored(t *testing.T) {
	k, z := key("K"), key("Z")
	l0 := mk(k, 0, "", 0, "")
	body := obj("successor", z.Signer(), "x_escrow", "v")
	b, id := wire.Sign(wire.Draft{Kind: "rotate_key", Seq: 1, Prev: l0.id, TS: ts(1), Crit: []string{"x_escrow"}, Body: body}, k)
	s := NewStore()
	deliver(t, s, k, l0, line{b, id})
	v := s.Log(k.Signer()).View()
	if ks := v.KeyState(); len(ks.Events) != 0 || len(v.Lines) != 2 || v.Lines[1].State != Chained {
		t.Fatalf("%s", v.Render())
	}
}

// TestPropertyKeyEventsPermutation: P-01 over generated logs with key events, forks, merges and gaps: the
// key-event view (events, in force, after) is the same in every delivery order.
func TestPropertyKeyEventsPermutation(t *testing.T) {
	conformance.Partial(t, "P-01", "key-event views are order-independent over generated logs; derived answers (defaults, grades) need the resolver")
	k, z := key("A"), key("Z")
	for seed := uint64(1); seed <= 40; seed++ {
		ls := genEventLog(k, z, seed)
		var want string
		for p := uint64(0); p < 15; p++ {
			s := NewStore()
			for _, i := range shuffle(len(ls), seed*7919+p) {
				_, _ = s.Log(k.Signer()).Add(ls[i].bytes)
			}
			v := s.Log(k.Signer()).View()
			ks := v.KeyState()
			got := v.Render()
			for _, id := range sortedKeys(ks.After) {
				got += id + ":" + strings.Join(ks.After[id], ",") + "\n"
			}
			if p == 0 {
				want = got
			} else if got != want {
				t.Fatalf("seed %d order %d:\n%s\nvs\n%s", seed, p, got, want)
			}
		}
	}
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func genEventLog(k, z wire.Key, seed uint64) []line {
	x := seed*0x9e3779b97f4a7c15 + 7
	rnd := func(n int) int { x ^= x << 13; x ^= x >> 7; x ^= x << 17; return int(x % uint64(n)) }
	all := []line{mk(k, 0, "", 0, "")}
	seqOf := map[string]int64{all[0].id: 0}
	n := 3 + rnd(8)
	for i := 1; i < n; i++ {
		p := all[rnd(len(all))]
		seq := seqOf[p.id] + 1
		var merges []string
		if rnd(3) == 0 && len(all) > 1 {
			if m := all[rnd(len(all))]; m.id != p.id && seqOf[m.id] < seq {
				merges = []string{m.id}
			}
		}
		var l line
		switch rnd(4) {
		case 0:
			l = rotate(k, seq, p.id, z, merges...)
		case 1:
			b, id := wire.Sign(wire.Draft{Kind: "revoke_key", Seq: seq, Prev: p.id, TS: ts(seq), Merges: merges,
				Body: obj("reason", "unspecified", "note", string(rune('a'+i)))}, k)
			l = line{b, id}
		default:
			l = mk(k, seq, p.id, byte(i), "", merges...)
		}
		seqOf[l.id] = seq
		all = append(all, l)
	}
	var out []line
	for _, l := range all {
		if rnd(5) != 0 {
			out = append(out, l)
		}
	}
	return out
}
