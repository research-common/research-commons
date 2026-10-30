package keylog

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/dag"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

func key(name string) wire.Key {
	h := sha256.Sum256([]byte("research-commons go test key " + name))
	if name[0]%2 == 0 {
		return wire.EIP191Key{Scalar: h[:]}
	}
	return wire.Ed25519Key{Seed: h[:]}
}

func holds(b byte) *canon.Object {
	d := canon.String("sha256:" + strings.Repeat(fmt.Sprintf("%02x", b), 32))
	return &canon.Object{Keys: []string{"content"}, Members: map[string]canon.Value{
		"content": &canon.Object{Keys: []string{"digest", "size"}, Members: map[string]canon.Value{"digest": d, "size": canon.Int(1)}}}}
}

// line signs a holds statement; tag makes otherwise identical lines distinct.
type line struct {
	bytes []byte
	id    string
}

func mk(k wire.Key, seq int64, prev string, tag byte, ts string, merges ...string) line {
	if ts == "" {
		ts = fmt.Sprintf("2026-10-15T00:%02d:00Z", seq%60)
	}
	b, id := wire.Sign(wire.Draft{Kind: "holds", Seq: seq, Prev: prev, TS: ts, Merges: merges, Body: holds(tag)}, k)
	return line{b, id}
}

func chain(k wire.Key, n int) []line {
	var out []line
	prev := ""
	for i := 0; i < n; i++ {
		l := mk(k, int64(i), prev, byte(i), "")
		out = append(out, l)
		prev = l.id
	}
	return out
}

func deliver(t *testing.T, s *Store, k wire.Key, ls ...line) {
	t.Helper()
	for _, l := range ls {
		if _, err := s.Log(k.Signer()).Add(l.bytes); err != nil {
			t.Fatalf("unexpected refusal: %v", err)
		}
	}
}

func wantRefused(t *testing.T, err error, reason, detail string) {
	t.Helper()
	var r *refusal.Refusal
	if !errors.As(err, &r) || r.Class != refusal.Intrinsic || r.Reason != reason || !strings.Contains(r.Detail, detail) {
		t.Fatalf("got %v, want intrinsic: %s …%s…", err, reason, detail)
	}
}

// permutations of n indices, all of them for n <= 6, else a seeded sample.
func perms(n int) [][]int {
	var out [][]int
	var rec func(p []int, used []bool)
	rec = func(p []int, used []bool) {
		if len(p) == n {
			out = append(out, slices.Clone(p))
			return
		}
		for i := 0; i < n; i++ {
			if !used[i] {
				used[i] = true
				rec(append(p, i), used)
				used[i] = false
			}
		}
	}
	rec(nil, make([]bool, n))
	return out
}

// renderAll delivers ls in every order into fresh stores and returns the one rendering, failing if any order
// renders differently. Refusals at Add are allowed (a log-relative rule may refuse when its witness is held).
func renderAll(t *testing.T, k wire.Key, ls []line, extra func(*Store)) (string, View) {
	t.Helper()
	var first string
	var view View
	for _, p := range perms(len(ls)) {
		s := NewStore()
		if extra != nil {
			extra(s)
		}
		for _, i := range p {
			_, _ = s.Log(k.Signer()).Add(ls[i].bytes)
		}
		v := s.Log(k.Signer()).View()
		r := v.Render()
		if first == "" {
			first, view = r, v
		} else if r != first {
			t.Fatalf("order %v renders differently:\n%s\nvs\n%s", p, r, first)
		}
	}
	return first, view
}

// TestVectorLog: V1–V12 delivered as one log: chained, fork at V9 (V10 and V11), cleared by V12 (§9).
func TestVectorLog(t *testing.T) {
	v, err := conformance.LoadVectors()
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore()
	var ids []string
	for _, x := range v.Positive {
		parts := strings.SplitN(x.SignedString, " ", 5)
		ln := []byte(parts[4][:len(parts[4])-1] + `,"sig":"` + x.Sig + `"}`)
		if _, err := s.Log(v.EIP191Address).Add(ln); err != nil {
			t.Fatalf("%s: %v", x.Name, err)
		}
		ids = append(ids, x.ID)
	}
	view := s.Log(v.EIP191Address).View()
	for _, ln := range view.Lines {
		if ln.State != Chained {
			t.Fatalf("%s is %s", Short(ln.St.ID), ln.State)
		}
	}
	want := []dag.Fork{{At: ids[8], Branches: sorted(ids[9], ids[10]), Tips: []string{ids[11]}, ClearedBy: ids[11]}}
	if fmt.Sprint(view.Forks) != fmt.Sprint(want) || !slices.Equal(view.Tips, []string{ids[11]}) {
		t.Fatalf("forks %+v tips %v\n%s", view.Forks, view.Tips, view.Render())
	}
}

func sorted(x ...string) []string { slices.Sort(x); return x }

// TestOwnership: a valid line delivered into another key's log is refused (intrinsic: line in another key's
// log), not kept, and the log is unchanged; a line naming A as signer but signed by B fails at the signature.
func TestOwnership(t *testing.T) {
	conformance.Covers(t, "C-core-14")
	v, _ := conformance.LoadVectors()
	n5 := v.Negative[4]
	s := NewStore()
	a, b := key("A"), key("B")
	deliver(t, s, a, chain(a, 3)...)
	before := s.Log(a.Signer()).View().Render()

	_, err := s.Log(n5.Log).Add([]byte(n5.Delivered))
	wantRefused(t, err, refusal.WrongLog, "scope this line")
	if got := s.Log(n5.Log).View(); len(got.Lines)+len(got.Refused) != 0 {
		t.Fatal("the refused N5 line was kept")
	}
	_, err = s.Log(a.Signer()).Add(chain(b, 1)[0].bytes)
	wantRefused(t, err, refusal.WrongLog, "in the log of "+a.Signer())

	// signer field names A, signature by B: the envelope names A, so it reaches A's log and Read refuses it.
	env := wire.Draft{Kind: "holds", Seq: 3, Prev: chain(a, 3)[2].id, TS: "2026-10-15T00:03:00Z", Body: holds(9)}.Envelope(a)
	ss := wire.PAE(wire.PayloadType("holds", wire.Major), canon.Encode(env))
	bk := wire.EIP191Key{Scalar: func() []byte { h := sha256.Sum256([]byte("x")); return h[:] }()}
	env.Keys = append(env.Keys, "sig")
	if a.Alg() == wire.AlgEd25519 {
		env.Members["sig"] = canon.String(wire.Ed25519Key{Seed: make([]byte, 32)}.Sign(ss))
	} else {
		env.Members["sig"] = canon.String(bk.Sign(ss))
	}
	_, err = s.Log(a.Signer()).Add(canon.Encode(env))
	wantRefused(t, err, refusal.BadSignature, "")
	if after := s.Log(a.Signer()).View().Render(); after != before {
		t.Fatalf("A's log changed:\n%s\nvs\n%s", after, before)
	}
}

// TestDuplicateIsNoOp: a second delivery of a line, in another signature encoding included, is one line.
func TestDuplicateIsNoOp(t *testing.T) {
	conformance.Partial(t, "C-core-10", "one log line per statement whatever the encoding; one count in every projection needs projections")
	v, _ := conformance.LoadVectors()
	s := NewStore()
	v1 := v.Positive[0]
	body := strings.SplitN(v1.SignedString, " ", 5)[4]
	for _, enc := range []string{v.Equivalent.Canonical, v.Equivalent.V01, v.Equivalent.HighS, v.Equivalent.Canonical} {
		if _, err := s.Log(v.EIP191Address).Add([]byte(body[:len(body)-1] + `,"sig":"` + enc + `"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(s.Log(v.EIP191Address).View().Lines); n != 1 {
		t.Fatalf("%d lines", n)
	}
}

// TestFork: two lines from one sequence point are both retained and the log shows FORK naming both.
func TestFork(t *testing.T) {
	conformance.Partial(t, "C-core-127", "two lines signed from one sequence point by one key: both kept, FORK shown; two OS processes racing on one store needs the storage layer")
	a := key("A")
	base := chain(a, 2)
	l := mk(a, 2, base[1].id, 0xaa, "")
	sl := mk(a, 2, base[1].id, 0xbb, "")
	out, v := renderAll(t, a, append(base, l, sl), nil)
	if len(v.Lines) != 4 || len(v.Forks) != 1 || v.Forks[0].Cleared() || !slices.Equal(v.Forks[0].Branches, sorted(l.id, sl.id)) {
		t.Fatalf("%s", out)
	}
	if !strings.Contains(out, "FORK at "+Short(base[1].id)) || len(v.Tips) != 2 {
		t.Fatalf("%s", out)
	}
}

// TestForkClearing: C-core-127a (a)–(d), each in every delivery order.
func TestForkClearing(t *testing.T) {
	conformance.Partial(t, "C-core-127a", "(a)–(d) and permutation invariance checked on the log; \"displayed as merged\" is the log display only (no surface yet)")
	a, other := key("A"), key("B")
	base := chain(a, 2)
	P := base[1].id
	L := mk(a, 2, P, 0xaa, "")
	S := mk(a, 2, P, 0xbb, "")

	t.Run("a follows one tip", func(t *testing.T) {
		n := mk(a, 3, S.id, 0xcc, "")
		out, v := renderAll(t, a, []line{base[0], base[1], L, S, n}, nil)
		if len(v.Forks) != 1 || v.Forks[0].Cleared() || !slices.Equal(v.Forks[0].Tips, sorted(L.id, n.id)) {
			t.Fatalf("%s", out)
		}
		if !strings.Contains(out, "FORK at "+Short(P)+": branches "+strings.Join(shorts(sorted(L.id, S.id)), ",")) {
			t.Fatalf("FORK does not name L and S:\n%s", out)
		}
	})
	t.Run("b names the other tip", func(t *testing.T) {
		m := mk(a, 3, S.id, 0xcc, "", L.id)
		out, v := renderAll(t, a, []line{base[0], base[1], L, S, m}, nil)
		if len(v.Forks) != 1 || !v.Forks[0].Cleared() || v.Forks[0].ClearedBy != m.id ||
			!slices.Equal(v.Tips, []string{m.id}) || len(v.Lines) != 5 {
			t.Fatalf("%s", out)
		}
		if !strings.Contains(out, "(merged)") || !strings.Contains(out, "merges "+Short(L.id)) {
			t.Fatalf("not displayed as merged:\n%s", out)
		}
	})
	t.Run("c three-way, one merged", func(t *testing.T) {
		T := mk(a, 2, P, 0xdd, "")
		m := mk(a, 3, S.id, 0xcc, "", L.id)
		out, v := renderAll(t, a, []line{base[1], L, S, T, m}, func(s *Store) { deliver(t, s, a, base[0]) })
		if len(v.Forks) != 1 || v.Forks[0].Cleared() || !slices.Contains(v.Forks[0].Tips, T.id) {
			t.Fatalf("%s", out)
		}
	})
	t.Run("d malformed merges", func(t *testing.T) {
		B0 := chain(other, 1)[0]
		hiS := mk(a, 3, S.id, 0xee, "")
		lineLocal := map[string]struct {
			d      wire.Draft
			detail string
		}{
			"own predecessor": {wire.Draft{Seq: 3, Prev: S.id, Merges: []string{S.id}}, "contains prev"},
			"duplicate":       {wire.Draft{Seq: 3, Prev: S.id, Merges: []string{L.id, L.id}}, "sorted and duplicate-free"},
			"unsorted":        {wire.Draft{Seq: 3, Prev: S.id, Merges: []string{"ff" + L.id[2:], "00" + L.id[2:]}}, "sorted and duplicate-free"},
		}
		for name, c := range lineLocal {
			t.Run(name, func(t *testing.T) {
				s := NewStore()
				deliver(t, s, a, base[0], base[1], L, S)
				before := s.Log(a.Signer()).View().Render()
				d := c.d
				d.Kind, d.TS, d.Body = "holds", "2026-10-15T00:03:00Z", holds(0xcc)
				b, _ := wire.Sign(d, a)
				_, err := s.Log(a.Signer()).Add(b)
				wantRefused(t, err, refusal.MalformedStatement, c.detail)
				if s.Log(a.Signer()).View().Render() != before {
					t.Fatal("log changed")
				}
			})
		}
		relative := map[string]struct {
			bad    line
			detail string
			extra  func(*Store)
		}{
			"another key's line": {mk(a, 3, S.id, 0xcc, "", B0.id), "merges names a line of another key",
				func(s *Store) { deliver(t, s, other, B0) }},
			"seq not lower": {mk(a, 3, S.id, 0xcc, "", hiS.id), "not lower than this line's seq 3", nil},
		}
		for name, c := range relative {
			t.Run(name, func(t *testing.T) {
				ls := []line{base[1], L, S, c.bad}
				if name == "seq not lower" {
					ls = append(ls, hiS)
				}
				out, v := renderAll(t, a, ls, func(s *Store) {
					deliver(t, s, a, base[0])
					if c.extra != nil {
						c.extra(s)
					}
				})
				if len(v.Refused) != 1 || v.Refused[0].St.ID != c.bad.id || !strings.Contains(v.Refused[0].Reason.Detail, c.detail) ||
					v.Refused[0].Reason.Reason != refusal.MalformedStatement {
					t.Fatalf("%s", out)
				}
				// The rest of A's log is what it was without the refused line.
				s := NewStore()
				if c.extra != nil {
					c.extra(s)
				}
				deliver(t, s, a, base[0])
				for _, l := range ls {
					if l.id != c.bad.id {
						deliver(t, s, a, l)
					}
				}
				want := s.Log(a.Signer()).View()
				if placed(want) != placed(v) || fmt.Sprint(want.Forks) != fmt.Sprint(v.Forks) {
					t.Fatal("refusing the line changed the rest of the log")
				}
				// Delivered last, Add itself reports the refusal.
				s2 := NewStore()
				if c.extra != nil {
					c.extra(s2)
				}
				deliver(t, s2, a, base[0])
				for _, l := range ls {
					if l.id != c.bad.id {
						deliver(t, s2, a, l)
					}
				}
				_, err := s2.Log(a.Signer()).Add(c.bad.bytes)
				wantRefused(t, err, refusal.MalformedStatement, c.detail)
			})
		}
	})
}

// placed is a pointer-free summary of the placed lines: id, state, gap, incoherence.
func placed(v View) string {
	var b strings.Builder
	for _, ln := range v.Lines {
		fmt.Fprintf(&b, "%s %s %+v %v\n", ln.St.ID, ln.State, ln.Waiting, ln.Incoherent)
	}
	return b.String()
}

func shorts(ids []string) []string {
	out := make([]string, len(ids))
	for i, x := range ids {
		out[i] = Short(x)
	}
	return out
}

// TestMergeWaitsForUnheldTip: C-core-127b. The reader holds S and the clearing line M, not L. M is detached
// naming L; no FORK is shown. When L arrives, the fork shows as cleared and M chains.
func TestMergeWaitsForUnheldTip(t *testing.T) {
	conformance.Partial(t, "C-core-127b", "detached naming L, no FORK, then cleared on arrival: checked; the rotate_key variant is TestRotationWaitsForMergedTip; evaluating the clearing line needs the resolver")
	a := key("A")
	base := chain(a, 2)
	L := mk(a, 2, base[1].id, 0xaa, "")
	S := mk(a, 2, base[1].id, 0xbb, "")
	M := mk(a, 3, S.id, 0xcc, "", L.id)
	s := NewStore()
	deliver(t, s, a, base[0], base[1], S, M)
	v := s.Log(a.Signer()).View()
	if len(v.Forks) != 0 {
		t.Fatalf("a FORK the reader has not seen:\n%s", v.Render())
	}
	m := v.Lines[len(v.Lines)-1]
	if m.St.ID != M.id || m.State != Detached || !slices.Equal(m.Waiting.IDs, []string{L.id}) || m.Waiting.HasSeq {
		t.Fatalf("%s", v.Render())
	}
	if !strings.Contains(v.Render(), "detached: waiting for "+L.id) {
		t.Fatalf("the gap does not name L by id:\n%s", v.Render())
	}
	deliver(t, s, a, L)
	v = s.Log(a.Signer()).View()
	if len(v.Forks) != 1 || !v.Forks[0].Cleared() {
		t.Fatalf("%s", v.Render())
	}
	for _, ln := range v.Lines {
		if ln.State != Chained {
			t.Fatalf("%s", v.Render())
		}
	}
}

// TestGap: C-core-143 at the log layer. seq 0–39 and 41 held: 41 is detached waiting for seq 40 of K; then
// 40 arrives and 41 chains. Variant: 40 never arrives, nothing is refused.
func TestGap(t *testing.T) {
	conformance.Partial(t, "C-core-143", "detached naming seq 40 of K, chained once it arrives, no refusal while waiting: checked; the observed counting toward nothing and the edition not applied need the resolver")
	k := key("K")
	ls := chain(k, 42)
	s := NewStore()
	for i, l := range ls {
		if i != 40 {
			deliver(t, s, k, l)
		}
	}
	v := s.Log(k.Signer()).View()
	last := v.Lines[len(v.Lines)-1]
	if last.State != Detached || !last.Waiting.HasSeq || last.Waiting.FromSeq != 40 || last.Waiting.ToSeq != 40 || len(v.Refused) != 0 {
		t.Fatalf("%+v", last)
	}
	if !strings.Contains(v.Render(), "detached: waiting for seq 40 of "+k.Signer()) {
		t.Fatalf("%s", v.Render())
	}
	deliver(t, s, k, ls[40])
	for _, ln := range s.Log(k.Signer()).View().Lines {
		if ln.State != Chained {
			t.Fatalf("seq %d still %s", ln.St.Seq, ln.State)
		}
	}
	// A longer gap is named as a range; a detached line above another detached line names the same stretch.
	s = NewStore()
	deliver(t, s, k, ls[0], ls[1], ls[5], ls[6])
	v = s.Log(k.Signer()).View()
	for _, ln := range v.Lines[2:] {
		if ln.Waiting.FromSeq != 2 || ln.Waiting.ToSeq != 4 {
			t.Fatalf("seq %d waits for %d–%d", ln.St.Seq, ln.Waiting.FromSeq, ln.Waiting.ToSeq)
		}
	}
}

// TestIncoherent: a line whose ts is earlier than its prev's is flagged incoherent; its signature is valid.
func TestIncoherent(t *testing.T) {
	conformance.Partial(t, "C-core-106", "flagged incoherent with the signature still valid; discarding its time bound for every use needs anchors and priority")
	k := key("A")
	l0 := mk(k, 0, "", 0, "2026-10-15T00:10:00Z")
	l1 := mk(k, 1, l0.id, 1, "2026-10-15T00:09:59.999999999Z")
	l2 := mk(k, 2, l1.id, 2, "2026-10-15T00:10:00Z")
	_, v := renderAll(t, k, []line{l0, l1, l2}, nil)
	got := []bool{v.Lines[0].Incoherent, v.Lines[1].Incoherent, v.Lines[2].Incoherent}
	if !slices.Equal(got, []bool{false, true, false}) || v.Lines[1].St.Status != wire.Valid {
		t.Fatalf("%v\n%s", got, v.Render())
	}
}

// TestPrevSeqMismatch: a line whose prev is held at a seq other than its own minus 1 is refused, scoped to it.
func TestPrevSeqMismatch(t *testing.T) {
	k := key("A")
	base := chain(k, 3)
	bad := mk(k, 5, base[1].id, 9, "")
	s := NewStore()
	deliver(t, s, k, base...)
	_, err := s.Log(k.Signer()).Add(bad.bytes)
	wantRefused(t, err, refusal.MalformedStatement, "seq is prev's plus 1")
}

// unknownAlg builds a well-formed line of key k under an algorithm no reader implements: its id is computable
// (the PAE hash does not depend on the alg), its signature cannot be checked.
func unknownAlg(k wire.Key, seq int64, prev string, tag byte) line {
	env := wire.Draft{Kind: "holds", Seq: seq, Prev: prev, TS: fmt.Sprintf("2026-10-15T00:%02d:00Z", seq), Body: holds(tag)}.Envelope(k)
	env.Members["alg"] = canon.String("ml-dsa-65")
	id := wire.ID(wire.PAE(wire.PayloadType("holds", wire.Major), canon.Encode(env)))
	env.Keys = append(env.Keys, "sig")
	env.Members["sig"] = canon.String("00")
	return line{canon.Encode(env), id}
}

// TestUnverifiedRetained: an unknown rc major or alg is retained and shown. An unknown-alg line nobody of
// its key vouches for is never placed: it cannot draw a FORK on the log.
func TestUnverifiedRetained(t *testing.T) {
	k := key("A")
	base := chain(k, 2)
	b, _ := wire.Sign(wire.Draft{RC: "rc/2", Kind: "holds", Seq: 1, Prev: base[0].id, TS: "2026-10-15T00:00:00Z", Body: holds(7)}, k)
	rogue := unknownAlg(k, 1, base[0].id, 8) // a second line after seq 0, by someone without A's key
	s := NewStore()
	deliver(t, s, k, base...)
	deliver(t, s, k, line{b, ""}, rogue)
	v := s.Log(k.Signer()).View()
	if len(v.Forks) != 0 || len(v.Retained) != 2 || !strings.Contains(v.Render(), "unsupported: rc/2") ||
		!strings.Contains(v.Render(), "unsupported: alg ml-dsa-65") {
		t.Fatalf("%s", v.Render())
	}
}

// TestVouchedUnknownAlgChains: a verified line of the key naming an unknown-alg line in prev places it, so
// the verified line and everything after it chain (§6: "a valid signed line and still chains"). Vouching is
// transitive through prev, works through merges, and is the same in every delivery order.
func TestVouchedUnknownAlgChains(t *testing.T) {
	k := key("A")
	l0 := mk(k, 0, "", 0, "")
	u1 := unknownAlg(k, 1, l0.id, 1)
	u2 := unknownAlg(k, 2, u1.id, 2)
	l3 := mk(k, 3, u2.id, 3, "")
	l4 := mk(k, 4, l3.id, 4, "")
	out, v := renderAll(t, k, []line{l0, u1, u2, l3, l4}, nil)
	if len(v.Lines) != 5 || len(v.Retained) != 0 || len(v.Forks) != 0 {
		t.Fatalf("%s", out)
	}
	for _, ln := range v.Lines {
		if ln.State != Chained {
			t.Fatalf("%s", out)
		}
	}
	if !strings.Contains(out, "[unsupported: alg ml-dsa-65]") {
		t.Fatalf("a vouched line must still show as unsupported:\n%s", out)
	}
	// Without u2, l3 waits for it by seq: the gap is real.
	s := NewStore()
	deliver(t, s, k, l0, u1, l3)
	if ln := s.Log(k.Signer()).View().Lines; ln[len(ln)-1].State != Detached {
		t.Fatal("l3 chained across a missing line")
	}
	// Through merges: a fork whose second branch is an unknown-alg line clears when a verified line names it.
	f := unknownAlg(k, 1, l0.id, 9)
	l1 := mk(k, 1, l0.id, 1, "")
	m := mk(k, 2, l1.id, 2, "", f.id)
	out, v = renderAll(t, k, []line{l0, l1, f, m}, nil)
	if len(v.Forks) != 1 || !v.Forks[0].Cleared() || v.Forks[0].ClearedBy != m.id {
		t.Fatalf("%s", out)
	}
	// Another key's unknown-alg line is never placed in A's log: A's line naming it is a link to another key's
	// line, refused and scoped to that line (its id covers its signer field, so the owner is known).
	other := unknownAlg(key("B"), 1, l0.id, 5)
	s = NewStore()
	deliver(t, s, k, l0)
	_, err := s.Log(k.Signer()).Add(other.bytes)
	wantRefused(t, err, refusal.WrongLog, "in the log of "+k.Signer())
	_, _ = s.Log(key("B").Signer()).Add(other.bytes) // held in B's log, as it should be
	_, err = s.Log(k.Signer()).Add(mk(k, 2, other.id, 6, "").bytes)
	wantRefused(t, err, refusal.MalformedStatement, "prev names a line of another key")
	if v := s.Log(k.Signer()).View(); len(v.Lines) != 1 {
		t.Fatalf("%s", v.Render())
	}
}

// TestOtherMajorChains: under the linkage contract (wire §6) a line of another major has an id this reader
// computes and links it reads, so a verified line of the key naming it places it, and the key's log continues
// across the major in both directions. Unvouched it is retained and never placed; a line of another major in
// the wrong key's log is refused like any other; a malformed linkage field is malformed.
func TestOtherMajorChains(t *testing.T) {
	k := key("A")
	l0 := mk(k, 0, "", 0, "")
	b1, id1 := wire.Sign(wire.Draft{RC: "rc/2", Kind: "holds", Seq: 1, Prev: l0.id, TS: "2026-10-16T00:00:00Z", Body: holds(7)}, k)
	n1 := line{b1, id1}
	l2 := mk(k, 2, id1, 2, "")
	l3 := mk(k, 3, l2.id, 3, "")
	out, v := renderAll(t, k, []line{l0, n1, l2, l3}, nil)
	if len(v.Lines) != 4 || len(v.Retained) != 0 || len(v.Forks) != 0 {
		t.Fatalf("%s", out)
	}
	for _, ln := range v.Lines {
		if ln.State != Chained {
			t.Fatalf("%s", out)
		}
	}
	if !strings.Contains(out, "[unsupported: rc/2]") {
		t.Fatalf("a placed rc/2 line still shows as unsupported:\n%s", out)
	}
	st, err := wire.Read(b1)
	if err != nil || st.ID != id1 || st.Verified || st.Kind != "holds" || st.Prev != l0.id {
		t.Fatalf("%+v %v", st, err)
	}
	// Unvouched (nothing names it), it is retained and draws no FORK beside a verified seq 1.
	s := NewStore()
	deliver(t, s, k, l0, mk(k, 1, l0.id, 1, ""), n1)
	if v := s.Log(k.Signer()).View(); len(v.Forks) != 0 || len(v.Retained) != 1 {
		t.Fatalf("%s", v.Render())
	}
	// Another key's rc/2 line is refused in A's log.
	bo, _ := wire.Sign(wire.Draft{RC: "rc/2", Kind: "holds", Seq: 0, TS: "2026-10-16T00:00:00Z", Body: holds(8)}, key("B"))
	_, err = NewStore().Log(k.Signer()).Add(bo)
	wantRefused(t, err, refusal.WrongLog, "in the log of "+k.Signer())
	// A linkage field that breaks the contract is malformed, whatever the major.
	bad, _ := wire.Sign(wire.Draft{RC: "rc/2", Kind: "holds", Seq: 1, TS: "2026-10-16T00:00:00Z", Body: holds(9)}, k)
	_, err = wire.Read(bad)
	wantRefused(t, err, refusal.MalformedStatement, "prev null at seq 1")
	bad, _ = wire.Sign(wire.Draft{RC: "rc/2", Kind: "holds", Seq: 1, Prev: "sha256:" + l0.id, TS: "2026-10-16T00:00:00Z", Body: holds(9)}, k)
	_, err = wire.Read(bad)
	wantRefused(t, err, refusal.MalformedStatement, "is not a statement id")
	bad, _ = wire.Sign(wire.Draft{RC: "rc/2", Kind: "holds", Seq: 0, Prev: l0.id, TS: "2026-10-16T00:00:00Z", Body: holds(9)}, k)
	_, err = wire.Read(bad)
	wantRefused(t, err, refusal.MalformedStatement, "prev set at seq 0")
}

// TestUnknownMajorDedupe: two deliveries of one rc/2 line differing only in whitespace and key order are one
// retained entry (P-02), though the reader cannot compute its id.
func TestUnknownMajorDedupe(t *testing.T) {
	k := key("A")
	b, _ := wire.Sign(wire.Draft{RC: "rc/2", Kind: "holds", Seq: 0, TS: "2026-10-15T00:00:00Z", Body: holds(7)}, k)
	o, _ := canon.Parse(b)
	obj := o.(*canon.Object)
	var messy strings.Builder
	messy.WriteString("{ ")
	for i := len(obj.Keys) - 1; i >= 0; i-- {
		fmt.Fprintf(&messy, "%q : %s", obj.Keys[i], canon.Encode(obj.Members[obj.Keys[i]]))
		if i > 0 {
			messy.WriteString(" , ")
		}
	}
	messy.WriteString(" }")
	s := NewStore()
	for _, x := range [][]byte{b, []byte(messy.String())} {
		if _, err := s.Log(k.Signer()).Add(x); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(s.Log(k.Signer()).View().Retained); n != 1 {
		t.Fatalf("%d retained entries", n)
	}
}

// TestPropertyLogPermutation (P-01 at the log layer): over generated logs with forks, merges, gaps and
// malformed links, every delivery order gives the same view.
func TestPropertyLogPermutation(t *testing.T) {
	conformance.Partial(t, "P-01", "log views are order-independent over generated logs with forks, merges and gaps; derived answers (defaults, grades) need the resolver")
	k := key("A")
	for seed := uint64(1); seed <= 60; seed++ {
		ls := genLog(k, seed)
		var want string
		for p := uint64(0); p < 20; p++ {
			s := NewStore()
			for _, i := range shuffle(len(ls), seed*1000+p) {
				_, _ = s.Log(k.Signer()).Add(ls[i].bytes)
			}
			got := s.Log(k.Signer()).View().Render()
			if p == 0 {
				want = got
			} else if got != want {
				t.Fatalf("seed %d order %d:\n%s\nvs\n%s", seed, p, got, want)
			}
		}
	}
}

// genLog builds a log of up to 10 lines: each new line follows a random earlier line (so forks occur), may
// merge a random other earlier line, and some lines are withheld to make gaps.
func genLog(k wire.Key, seed uint64) []line {
	x := seed*0x9e3779b97f4a7c15 + 1
	rnd := func(n int) int { x ^= x << 13; x ^= x >> 7; x ^= x << 17; return int(x % uint64(n)) }
	all := []line{mk(k, 0, "", 0, "")}
	seqOf := map[string]int64{all[0].id: 0}
	n := 2 + rnd(9)
	for i := 1; i < n; i++ {
		p := all[rnd(len(all))]
		var merges []string
		if rnd(3) == 0 && len(all) > 1 {
			m := all[rnd(len(all))]
			if m.id != p.id {
				merges = []string{m.id}
			}
		}
		l := mk(k, seqOf[p.id]+1, p.id, byte(i), "", merges...)
		seqOf[l.id] = seqOf[p.id] + 1
		all = append(all, l)
	}
	var out []line
	for _, l := range all {
		if rnd(6) != 0 {
			out = append(out, l)
		}
	}
	return out
}

func shuffle(n int, seed uint64) []int {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	x := seed*6364136223846793005 + 1442695040888963407
	for i := n - 1; i > 0; i-- {
		x = x*6364136223846793005 + 1442695040888963407
		j := int((x >> 33) % uint64(i+1))
		p[i], p[j] = p[j], p[i]
	}
	return p
}

// anchorsLine signs an `anchors` line of k at seq after prev, covering `covered`, with merges.
func anchorsLine(k wire.Key, seq int64, prev, covered string, merges ...string) line {
	return signed(k, "anchors", seq, prev, obj("covered", covered, "proof", "sha256:"+strings.Repeat("ab", 32), "proof_format", "ots-detached-v1"), merges...)
}

// TestAnchorCoveredOutsideItsPrefix: C-btc-09 and bitcoin-time §4 check 2. An `anchors` whose `covered` is a line of
// the signer's own log that the anchor line does not reach is refused (intrinsic, invalid-anchor), scoped to that
// statement; the rest of the log is what it was without it. The boundary: a covered that is the anchor's prev, an
// older line of its prefix, or reached only through `merges` is accepted; a covered on a sibling branch, or at a
// seq the anchor cannot reach, is refused. A covered not held, or a prefix with a gap the covered may sit behind,
// refuses nothing (wire §5: it bounds nothing until it arrives), so every delivery order reaches the same view.
func TestAnchorCoveredOutsideItsPrefix(t *testing.T) {
	conformance.Covers(t, "C-btc-09")
	a := key("A")
	base := chain(a, 3)                     // seq 0, 1, 2
	side := mk(a, 2, base[1].id, 0x77, "")  // a sibling of base[2] on the same prev
	sideNext := mk(a, 3, side.id, 0x78, "") // continues the sibling branch
	ahead := mk(a, 3, base[2].id, 0x79, "") // another line at the anchor's own seq
	merged := mk(a, 3, base[2].id, 0x7a, "", side.id)
	for _, c := range []struct {
		name    string
		lines   []line
		anchor  line
		refused bool
	}{
		{"covered is prev", base, anchorsLine(a, 3, base[2].id, base[2].id), false},
		{"covered is an older line of the prefix", base, anchorsLine(a, 3, base[2].id, base[0].id), false},
		{"covered reached only through merges", []line{base[0], base[1], base[2], side, merged}, anchorsLine(a, 4, merged.id, side.id), false},
		// the sibling is held and the anchor's prefix does not reach it: seq 3 after base[2], covering seq 2' (the boundary)
		{"covered on a sibling branch", []line{base[0], base[1], base[2], side}, anchorsLine(a, 3, base[2].id, side.id), true},
		{"covered on a sibling branch, deeper", []line{base[0], base[1], base[2], side, sideNext}, anchorsLine(a, 3, base[2].id, sideNext.id), true},
		{"covered at the anchor's own seq", []line{base[0], base[1], base[2], ahead}, anchorsLine(a, 3, base[2].id, ahead.id), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			ls := append(slices.Clone(c.lines), c.anchor)
			out, v := renderAll(t, a, ls, nil)
			if c.refused {
				if len(v.Refused) != 1 || v.Refused[0].St.ID != c.anchor.id || v.Refused[0].Reason.Reason != refusal.InvalidAnchor ||
					v.Refused[0].Reason.Class != refusal.Intrinsic || !strings.Contains(v.Refused[0].Reason.Detail, "scope this anchor") {
					t.Fatalf("not refused as invalid-anchor:\n%s", out)
				}
				// scoped to the statement: the other lines are what they were without it
				s := NewStore()
				for _, l := range c.lines {
					deliver(t, s, a, l)
				}
				if want := s.Log(a.Signer()).View(); placed(want) != placed(v) || fmt.Sprint(want.Forks) != fmt.Sprint(v.Forks) {
					t.Fatal("refusing the anchor changed the rest of the log")
				}
				// delivered last, Add itself reports the refusal, and keeps the line (a view)
				s2 := NewStore()
				for _, l := range c.lines {
					deliver(t, s2, a, l)
				}
				_, err := s2.Log(a.Signer()).Add(c.anchor.bytes)
				wantRefused(t, err, refusal.InvalidAnchor, "not in the anchor's own prefix")
			} else if len(v.Refused) != 0 {
				t.Fatalf("an anchor over its own prefix was refused:\n%s", out)
			}
		})
	}

	t.Run("covered not held bounds nothing and refuses nothing", func(t *testing.T) {
		ls := []line{base[0], base[1], base[2], anchorsLine(a, 3, base[2].id, side.id)} // side is never delivered
		out, v := renderAll(t, a, ls, nil)
		if len(v.Refused) != 0 || len(v.Lines) != 4 {
			t.Fatalf("an unheld covered was refused:\n%s", out)
		}
		// the covered line then arrives: now the held lines decide, and the anchor is refused in every order
		_, v = renderAll(t, a, append(ls, side), nil)
		if len(v.Refused) != 1 || v.Refused[0].Reason.Reason != refusal.InvalidAnchor {
			t.Fatalf("after the covered arrived:\n%s", v.Render())
		}
		// and arrives as a line the anchor does reach: accepted
		_, v = renderAll(t, a, []line{base[0], base[1], base[2], anchorsLine(a, 3, base[2].id, base[1].id)}, nil)
		if len(v.Refused) != 0 {
			t.Fatalf("an anchor over an older line was refused:\n%s", v.Render())
		}
	})

	t.Run("a gap under the anchor leaves the prefix undecided", func(t *testing.T) {
		// base[2] is missing: the walk from the anchor stops at an unheld prev, which may lead to the covered line
		anc := anchorsLine(a, 3, base[2].id, base[0].id)
		out, v := renderAll(t, a, []line{base[0], base[1], anc}, nil)
		if len(v.Refused) != 0 {
			t.Fatalf("refused across a gap:\n%s", out)
		}
		_, v = renderAll(t, a, []line{base[0], base[1], base[2], anc}, nil)
		if len(v.Refused) != 0 {
			t.Fatalf("refused once the gap filled with the covered in its prefix:\n%s", v.Render())
		}
		// a covered on a sibling branch behind the same gap: undecided until the gap fills, then refused
		anc2 := anchorsLine(a, 3, base[2].id, side.id)
		_, v = renderAll(t, a, []line{base[0], base[1], side, anc2}, nil)
		if len(v.Refused) != 0 {
			t.Fatalf("refused across a gap:\n%s", v.Render())
		}
		_, v = renderAll(t, a, []line{base[0], base[1], base[2], side, anc2}, nil)
		if len(v.Refused) != 1 || v.Refused[0].St.ID != anc2.id {
			t.Fatalf("not refused once the gap filled:\n%s", v.Render())
		}
	})
}
