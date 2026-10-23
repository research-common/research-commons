package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// --- fixture language for blobs ----------------------------------------------------------------------------

// dig is the content digest of a named blob ("X" → sha256 of "X").
func dig(name string) string {
	h := sha256.Sum256([]byte(name))
	return "sha256:" + hex.EncodeToString(h[:])
}

func contentOf(name string) *canon.Object { return obj("digest", dig(name), "size", len(name)) }

// authored signs an `authored` by key n for blob x. kv adds body fields; "prov" takes a [workflow, inputs...]
// list of blob names.
func (w *world) authored(name, n, x string, kv ...any) string {
	b := []any{"content", canon.Value(contentOf(x))}
	if !slices.Contains(kv, any("type")) {
		b = append(b, "type", "dataset")
	}
	for i := 0; i < len(kv); i += 2 {
		if kv[i] == "prov" {
			p := kv[i+1].([]string)
			in := []string{}
			for _, y := range p[1:] {
				in = append(in, dig(y))
			}
			b = append(b, "provenance", canon.Value(obj("workflow", dig(p[0]), "inputs", in)))
			continue
		}
		b = append(b, kv[i], kv[i+1])
	}
	return w.sign(name, n, "authored", obj(b...))
}

// workflow publishes workflow blob wf by key n with a replication mode ("" = undeclared) and comparator name.
func (w *world) workflow(n, wf, mode, comparator string) string {
	kv := []any{"type", "workflow"}
	if mode != "" {
		kv = append(kv, "replication", mode)
	}
	if comparator != "" {
		kv = append(kv, "comparator", dig(comparator))
	}
	return w.authored("wf:"+wf+":"+n, n, wf, kv...)
}

// anchor signs an `anchors` by key n covering its current head. The proof blob names the anchor's height for
// the fake verifier: "btc:<height>" is verified at that height, anything else is not.
func (w *world) anchor(name, n, proof string) string {
	return w.sign(name, n, "anchors", obj("covered", w.head[n], "proof", dig(proof), "proof_format", "ots-detached-v1"))
}

// fakeBitcoin verifies proofs named "btc:<height>" (by digest) and nothing else.
type fakeBitcoin struct{ heights map[string]int64 }

func newFakeBitcoin(heights ...int64) fakeBitcoin {
	f := fakeBitcoin{heights: map[string]int64{}}
	for _, h := range heights {
		f.heights[dig("btc:"+strconv.FormatInt(h, 10))] = h
	}
	return f
}

func (f fakeBitcoin) Verify(a *wire.Statement) Bound {
	if h, ok := f.heights[str(a.Body, "proof")]; ok {
		return Bound{Quality: Bitcoin, Anchor: a.ID, Network: "mainnet", Height: h}
	}
	return NoTimeVerifier{}.Verify(a)
}

// fakeComparator matches outputs whose blob names share the part before "~" ("r~1" matches "r~2").
type fakeComparator struct{ names map[string]string }

func newFakeComparator(blobs ...string) fakeComparator {
	f := fakeComparator{names: map[string]string{}}
	for _, b := range blobs {
		f.names[dig(b)] = b
	}
	return f
}

func (f fakeComparator) Compare(_, a, b string) (string, string) {
	x, y := f.names[a], f.names[b]
	if x == "" || y == "" {
		return "not comparable", "unknown output"
	}
	if strings.Split(x, "~")[0] == strings.Split(y, "~")[0] {
		return "match", ""
	}
	return "diverged", ""
}

// store delivers the world's lines in order (all, when nil) and builds a resolver.
func (w *world) store(order []int, opts ...Option) *Resolver {
	w.t.Helper()
	s := keylog.NewStore()
	if order == nil {
		for i := range w.lines {
			order = append(order, i)
		}
	}
	for _, i := range order {
		st, err := wire.Read(w.lines[i])
		if err != nil {
			w.t.Fatalf("line %d: %v", i, err)
		}
		if kept, err := s.Log(st.Signer).Add(w.lines[i]); err != nil && kept == nil {
			w.t.Fatalf("line %d refused: %v", i, err) // a log-relative refusal keeps the line; that is a view
		}
	}
	return New(s, opts...)
}

// everyOrderArtifact resolves blob x under every delivery order (all permutations up to 6 lines, else a seeded
// sample) and requires one rendering.
func everyOrderArtifact(t *testing.T, w *world, x string, check func(*Artifact), opts ...Option) {
	t.Helper()
	n := len(w.lines)
	orders := [][]int{nil}
	if n <= 6 {
		orders = permutations(n)
	} else {
		orders = append(orders, sampleOrders(n, uint64(n)*7919, 120)...)
	}
	var first string
	for _, o := range orders {
		a := w.store(o, opts...).Artifact(dig(x))
		check(a)
		if got := a.Render(); first == "" {
			first = got
		} else if got != first {
			t.Fatalf("order %v changed the answer:\n%s\nvs\n%s", o, got, first)
		}
	}
}

// sampledOrderArtifact is everyOrderArtifact over a seeded sample of 24 delivery orders plus file order, for
// tests whose rule is not order itself: order-independence over every permutation is the property tests' job
// (P-01), and a full sweep of 7+ lines costs minutes under -race.
func sampledOrderArtifact(t *testing.T, w *world, x string, check func(*Artifact), opts ...Option) {
	t.Helper()
	var first string
	for _, o := range append([][]int{nil}, sampleOrders(len(w.lines), uint64(len(w.lines))*4099, 24)...) {
		a := w.store(o, opts...).Artifact(dig(x))
		check(a)
		if out := a.Render(); first == "" {
			first = out
		} else if out != first {
			t.Fatalf("order %v changed the answer:\n%s\nvs\n%s", o, out, first)
		}
	}
}

func wantAuthorship(t *testing.T, a *Artifact, want AuthorshipState) {
	t.Helper()
	if a.State != want {
		t.Fatalf("authorship %s, want %s\n%s", a.State, want, a.Render())
	}
}

func wantField(t *testing.T, a *Artifact, name string, state FieldState, value string) {
	t.Helper()
	f := a.Field(name)
	if f.State != state {
		t.Fatalf("field %s: %s, want %s\n%s", name, f.State, state, a.Render())
	}
	if value != "" {
		if v, _ := f.Default(); v != value {
			t.Fatalf("field %s default %q, want %q", name, v, value)
		}
	}
}

func wantExit(t *testing.T, a *Artifact, want int, cause string) {
	t.Helper()
	got, why := a.VerifyExit()
	if got != want || (cause != "" && !strings.Contains(strings.Join(why, "; "), cause)) {
		t.Fatalf("verify %d %q, want %d citing %q\n%s", got, why, want, cause, a.Render())
	}
}

func has(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("missing %q in\n%s", sub, s)
	}
}

func hasNot(t *testing.T, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Fatalf("unexpected %q in\n%s", sub, s)
	}
}

// --- §5.1 / §5.2 constructions -----------------------------------------------------------------------------

// TestSoleAuthor: C-core-17. One verified authored with licence, availability and description; no rival.
func TestSoleAuthor(t *testing.T) {
	conformance.Covers(t, "C-core-17")
	w := newWorld(t)
	st := w.authored("A1", "A", "X", "licence", "CC0-1.0", "description", "readings",
		"availability", obj("redistribution", "permitted", "obtainable", true))
	a := w.store(nil).Artifact(dig("X"))
	wantAuthorship(t, a, SoleAuthor)
	wantField(t, a, "licence", FieldDefault, `"CC0-1.0"`)
	wantField(t, a, "description", FieldDefault, `"readings"`)
	wantField(t, a, "availability", FieldDefault, `{"obtainable":true,"redistribution":"permitted"}`)
	for _, f := range []string{"licence", "description", "availability"} {
		if fl := a.Field(f); fl.From[0].Statement != st || fl.From[0].Signer != w.signer("A") || len(fl.Rivals) != 0 {
			t.Fatalf("%s: %+v", f, fl)
		}
	}
	wantExit(t, a, 0, "")
	hasNot(t, a.Render(), "contested")
}

// TestRivalLicence: C-core-16 and C-core-142. A rival authored by B on the same bytes, with another licence and
// a reproduced: the author's licence stays the default only when authorship resolves to A (here by a verified
// bound); the rival is listed with its signer; B's reproduced is a reproduction, never authorship.
func TestRivalLicence(t *testing.T) {
	conformance.Covers(t, "C-core-16", "C-core-142")
	for _, verified := range []bool{true, false} {
		w := newWorld(t)
		w.authored("A1", "A", "X", "licence", "CC-BY-4.0")
		w.anchor("AA", "A", "btc:100")
		w.authored("B1", "BB", "X", "licence", "MIT")
		w.sign("BR", "BB", "reproduced", obj("of", w.ids["A1"], "result", "match", "content", contentOf("X"),
			"provenance", obj("workflow", dig("W"), "inputs", []string{})))
		var opts []Option
		if verified {
			opts = append(opts, WithTimeVerifier(newFakeBitcoin(100)))
		}
		everyOrderArtifact(t, w, "X", func(a *Artifact) {
			lic := a.Field("licence")
			var mit []Source
			for _, r := range lic.Rivals {
				if r.Value == `"MIT"` {
					mit = append(mit, r)
				}
			}
			if len(mit) != 1 || mit[0].Signer != w.signer("BB") {
				t.Fatalf("rival licence not listed with its signer: %+v", lic)
			}
			if verified {
				wantAuthorship(t, a, Priority)
				wantField(t, a, "licence", FieldDefault, `"CC-BY-4.0"`)
			} else {
				wantAuthorship(t, a, ContestedAuthorship)
				wantField(t, a, "licence", FieldNoDefault, "")
			}
			for _, u := range a.Units {
				for _, c := range u.Claims {
					if slices.Contains(c.Statements, w.ids["BR"]) {
						t.Fatal("a reproduced counted as authorship")
					}
				}
			}
			if len(a.Units) != 2 {
				t.Fatalf("units %d", len(a.Units))
			}
			has(t, a.Render(), "held reproduced "+keylog.Short(w.ids["BR"]))
		}, opts...)
	}
}

// TestTwoClaimantsContested: C-core-18 and C-core-08 (the resolver part). Identical bytes, no provenance, no
// Bitcoin evidence: both listed, contested, exit 3, the same display in both orders. Neither claim is marked
// superseded; both lines stay in their own logs.
func TestTwoClaimantsContested(t *testing.T) {
	conformance.Covers(t, "C-core-18")
	conformance.Partial(t, "C-core-08", "one blob and both lines kept in their own logs, in the resolver; the blob store half needs store+pull")
	w := newWorld(t)
	w.authored("A1", "A", "X")
	w.authored("B1", "BB", "X")
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, ContestedAuthorship)
		wantExit(t, a, 3, "authorship: contested")
		if len(a.Claims) != 2 || a.Default != nil {
			t.Fatalf("claims %d default %v", len(a.Claims), a.Default)
		}
		hasNot(t, a.Render(), "superseded")
	})
}

// TestLocalAnchorsDoNotRank: C-core-19 and C-core-107. Local anchors an hour apart; one local and one none; a
// body claiming bitcoin quality the reader cannot verify: contested every time, and explain shows each bound
// as (local, self-declared) and says local quality does not rank.
func TestLocalAnchorsDoNotRank(t *testing.T) {
	conformance.Covers(t, "C-core-19", "C-core-107")
	for _, variant := range []string{"both local", "one local", "label in a file"} {
		w := newWorld(t)
		w.authored("A1", "A", "X")
		if variant == "label in a file" {
			// a quality label riding in the anchor body grants nothing: only the verifier decides
			w.sign("AA", "A", "anchors", obj("covered", w.head["A"], "proof", dig("unverifiable"), "proof_format", "ots-detached-v1", "x_quality", "bitcoin"))
		} else {
			w.anchor("AA", "A", "local:early")
		}
		w.authored("B1", "BB", "X")
		if variant == "both local" {
			w.anchor("BA", "BB", "local:late")
		}
		everyOrderArtifact(t, w, "X", func(a *Artifact) {
			wantAuthorship(t, a, ContestedAuthorship)
			wantExit(t, a, 3, "contested")
			out := a.Render()
			has(t, out, "(local, self-declared)")
			has(t, out, "local quality does not rank")
			hasNot(t, out, "bitcoin")
			if variant == "label in a file" {
				has(t, out, "not verified by this reader")
			}
		})
	}
}

// TestVerifiedPriority: C-btc-01 and C-btc-02 at the resolver, with a fake verifier standing in for the
// Bitcoin profile: A at n and B at n+1 (and B unanchored) → A default, B later claimant, exit 0; both at n →
// contested, exit 3, no default field.
func TestVerifiedPriority(t *testing.T) {
	conformance.Partial(t, "C-btc-01", "resolver ranking under a stand-in verifier; OTS proof verification is the bitcoin-time profile")
	conformance.Partial(t, "C-btc-02", "resolver ranking under a stand-in verifier; OTS proof verification is the bitcoin-time profile")
	for _, c := range []struct {
		name      string
		a, b      string
		heights   []int64
		want      AuthorshipState
		exit      int
		relation  string
		licenceOK bool
	}{
		{"n vs n+1", "btc:100", "btc:101", []int64{100, 101}, Priority, 0, "earlier-commitment", true},
		{"verified vs unanchored", "btc:100", "", []int64{100}, Priority, 0, "earliest verified claim", true},
		{"verified vs local", "btc:100", "local", []int64{100}, Priority, 0, "earliest verified claim", true},
		{"same block", "btc:100", "btc:100", []int64{100}, ContestedAuthorship, 3, "same-block", false},
	} {
		w := newWorld(t)
		w.authored("A1", "A", "X", "licence", "CC0-1.0")
		w.anchor("AA", "A", c.a)
		w.authored("B1", "BB", "X", "licence", "MIT")
		if c.b != "" {
			w.anchor("BA", "BB", c.b)
		}
		everyOrderArtifact(t, w, "X", func(a *Artifact) {
			wantAuthorship(t, a, c.want)
			wantExit(t, a, c.exit, "")
			has(t, a.Render(), c.relation)
			if c.licenceOK {
				wantField(t, a, "licence", FieldDefault, `"CC0-1.0"`)
				if len(a.Later) != 1 || a.Later[0].Claims[0].Signer != w.signer("BB") {
					t.Fatalf("%s: later %v", c.name, a.Later)
				}
				has(t, a.Render(), "later claimant")
				has(t, a.Render(), "bitcoin mainnet height 100")
			} else {
				wantField(t, a, "licence", FieldNoDefault, "")
			}
		}, WithTimeVerifier(newFakeBitcoin(c.heights...)))
	}
}

// TestNonInterference: C-core-05 and C-core-13 (resolver half). C publishes describes, refutes and holds about
// A's blob, and an unknown kind asserting authorship-like fields: A's defaults, grade and exit are unchanged;
// explain lists C's statements as held, not as inputs.
func TestNonInterference(t *testing.T) {
	conformance.Covers(t, "C-core-05")
	conformance.Partial(t, "C-core-13", "defaults, grade and verify exit unchanged by an unknown kind; membership and corroboration land with their views")
	base := newWorld(t)
	base.authored("A1", "A", "X", "licence", "CC0-1.0")
	before := base.store(nil).Artifact(dig("X"))

	w := newWorld(t)
	a1 := w.authored("A1", "A", "X", "licence", "CC0-1.0")
	w.sign("CD", "C", "describes", obj("about", obj("content", dig("X")), "note", "looks off"))
	w.sign("CR", "C", "refutes", obj("of", a1, "evidence", dig("E")))
	w.sign("CH", "C", "holds", obj("content", contentOf("X")))
	w.sign("CU", "C", "endorses", obj("content", contentOf("X"), "licence", "MIT", "author", w.signer("C")))
	after := w.store(nil).Artifact(dig("X"))
	if before.Outcome() != after.Outcome() || before.Grade != after.Grade {
		t.Fatalf("a key with no authority changed the result:\n%s\nvs\n%s", before.Render(), after.Render())
	}
	b1, _ := before.VerifyExit()
	b2, _ := after.VerifyExit()
	if b1 != b2 {
		t.Fatalf("exit %d vs %d", b1, b2)
	}
	out := after.Render()
	has(t, out, "held describes "+keylog.Short(w.ids["CD"]))
	has(t, out, "held refutes "+keylog.Short(w.ids["CR"]))
	has(t, out, "not an input to any default")
	has(t, out, "holders "+shortKey(w.signer("C")))
	hasNot(t, out, "MIT")
}

// TestAmendment: C-core-11 (resolver half). The same key's later authored on the same blob amends the earlier:
// both lines kept, the later one current, the display points at both, and the earlier bound still counts.
func TestAmendment(t *testing.T) {
	conformance.Covers(t, "C-core-11")
	w := newWorld(t)
	first := w.authored("A1", "A", "X", "licence", "CC0-1.0")
	w.anchor("AA", "A", "btc:100")
	second := w.authored("A2", "A", "X", "licence", "CC-BY-4.0")
	w.authored("B1", "BB", "X")
	w.anchor("BA", "BB", "btc:101")
	r := w.store(nil, WithTimeVerifier(newFakeBitcoin(100, 101)))
	a := r.Artifact(dig("X"))
	if first == second {
		t.Fatal("two bodies, one id")
	}
	wantAuthorship(t, a, Priority)
	wantField(t, a, "licence", FieldDefault, `"CC-BY-4.0"`)
	c := a.Default.Claims[0]
	if !slices.Equal(c.Current, []string{second}) || !slices.Equal(c.Amends[second], []string{first}) || len(c.Statements) != 2 {
		t.Fatalf("claim %+v", c)
	}
	has(t, a.Render(), "authored "+keylog.Short(second)+" by "+shortKey(w.signer("A"))+" (amends "+keylog.Short(first)+")")
	for _, id := range []string{first, second} {
		if p, ok := r.Statement(id); !ok || !p.Counts() {
			t.Fatalf("line %s not retained", keylog.Short(id))
		}
	}
}

// TestDisclosuresMissing: C-core-67 (a), C-core-69 (the artifact's own field). Missing licence reads unknown,
// never open; missing sampling reads undeclared; no default licence text is written.
func TestDisclosuresMissing(t *testing.T) {
	conformance.Partial(t, "C-core-67", "(a) missing licence shows unknown; (b) unparsable SPDX and (c) LicenseRef citation need the licence parser")
	conformance.Partial(t, "C-core-69", "the artifact's own sampling shows undeclared; the aggregate n over inputs lands with scoped summaries")
	w := newWorld(t)
	w.authored("A1", "A", "X")
	a := w.store(nil).Artifact(dig("X"))
	out := a.Render()
	has(t, out, "licence: unknown")
	has(t, out, "sampling: undeclared")
	has(t, out, "pre_registration: undeclared")
	hasNot(t, out, "CC0")
}

// TestKeyEventsReachAuthorship: C-core-143a for authorship (the sibling rule applies to every use that grants
// standing, claims §4.1). A's authored on a branch its revocation does not include counts toward nothing: B's
// claim is the sole author, and A's line is still shown, attributed, with why.
func TestKeyEventsReachAuthorship(t *testing.T) {
	conformance.Partial(t, "C-core-143a", "edition approvals (resource_test) and authorship here; quorum uses land with tasks")
	w := newWorld(t)
	w.authored("A0", "A", "Y")
	fork, seq := w.head["A"], w.seq["A"]
	w.revoke("REV", "A", "key_compromise")
	w.head["A"], w.seq["A"] = fork, seq
	stolen := w.authored("A1", "A", "X")
	w.authored("B1", "BB", "X")
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, SoleAuthor)
		if a.Default.Claims[0].Signer != w.signer("BB") || len(a.NotCounted) != 1 || a.NotCounted[0].Statement != stolen {
			t.Fatalf("%s", a.Render())
		}
		has(t, a.Render(), "not counted: on a branch revoke_key")
	})
}

// --- derivation groups (§5.2) ------------------------------------------------------------------------------

// TestDerivationGroupNoPriority: C-core-20 (and the bitcoin-time note's C-btc-26, which CONFORMANCE.md does not list yet). Two derivers of W on the same inputs,
// both bitcoin-verified, A earlier: one group, no default author, no later claimant, no contested.
func TestDerivationGroupNoPriority(t *testing.T) {
	conformance.Covers(t, "C-core-20")
	w := newWorld(t)
	w.workflow("A", "W", "bytes", "")
	w.authored("A1", "A", "X", "prov", []string{"W", "I"})
	w.anchor("AA", "A", "btc:100")
	w.authored("B1", "BB", "X", "prov", []string{"W", "I"})
	w.anchor("BA", "BB", "btc:200")
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, Derived)
		out := a.Render()
		has(t, out, "derived by 2 under wf-"+shortDigest(dig("W")))
		has(t, out, "priority is not computed within a derivation group")
		hasNot(t, out, "default author")
		hasNot(t, out, "later claimant")
		hasNot(t, out, "contested")
	}, WithTimeVerifier(newFakeBitcoin(100, 200)))
}

// groupWorld: W by its author declaring mode/comparator; derivers publish authored for their outputs.
func groupWorld(t *testing.T, mode, comparator string, outputs map[string]string) *world {
	w := newWorld(t)
	w.workflow("WA", "W", mode, comparator)
	for _, k := range sortedKeys(outputs) {
		w.authored(k+"1", k, outputs[k], "prov", []string{"W", "I"})
	}
	return w
}

// TestBytesIdentical: C-core-21. replication bytes, identical outputs: T0, derived by 2, defaults by agreement.
func TestBytesIdentical(t *testing.T) {
	conformance.Covers(t, "C-core-21")
	w := newWorld(t)
	w.workflow("WA", "W", "bytes", "")
	w.authored("A1", "A", "X", "prov", []string{"W", "I"}, "licence", "CC0-1.0")
	w.authored("B1", "BB", "X", "prov", []string{"W", "I"}, "licence", "CC0-1.0")
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		if a.Grade.Tier != "T0" || a.Step.Tier != "T0" {
			t.Fatalf("grade %s\n%s", a.Grade, a.Render())
		}
		has(t, a.Render(), "derived by 2: byte-identical re-derivation (T0)")
		wantField(t, a, "licence", FieldDefault, `"CC0-1.0"`)
		if len(a.Field("licence").From) != 2 {
			t.Fatal("agreement should cite both derivers")
		}
		wantExit(t, a, 0, "")
	})
}

// TestBytesDifferent: C-core-22. replication bytes, different outputs: diverged on the group, no member wrong,
// no contested, no priority; explain says an environment differs or the determinism claim is wrong.
func TestBytesDifferent(t *testing.T) {
	conformance.Covers(t, "C-core-22")
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "Y"})
	for _, x := range []string{"X", "Y"} {
		everyOrderArtifact(t, w, x, func(a *Artifact) {
			out := a.Render()
			has(t, out, "derived by 2: diverged (2 different outputs)")
			has(t, out, "an environment differs or the determinism claim is wrong")
			hasNot(t, out, "contested")
			hasNot(t, out, "later claimant")
			if a.Step.Why != DivergedToken {
				t.Fatalf("step %s", a.Step)
			}
			wantExit(t, a, 1, "diverged")
		})
	}
}

// TestProtocolIdentical: C-core-23. protocol, identical bytes: no T0, no reproduced implied, no copy flag.
func TestProtocolIdentical(t *testing.T) {
	conformance.Covers(t, "C-core-23")
	w := groupWorld(t, "protocol", "K", map[string]string{"A": "X", "BB": "X"})
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		out := a.Render()
		has(t, out, IdenticalProto)
		has(t, out, "claims §9.3")
		hasNot(t, out, "T0")
		hasNot(t, out, "reproduced ")
		hasNot(t, out, "copied")
		hasNot(t, out, "later claimant")
		if a.Grade.Tier != "" {
			t.Fatalf("grade %s", a.Grade)
		}
	})
}

// TestProtocolComparator: C-core-24. protocol with comparator K; A, B, C derive different bytes; K matches A–B
// and not C: derived by 3: 2 match, 1 diverged; A and B T1 under K; C diverged; not contested.
func TestProtocolComparator(t *testing.T) {
	conformance.Covers(t, "C-core-24")
	w := groupWorld(t, "protocol", "K", map[string]string{"A": "r~1", "BB": "r~2", "C": "s~1"})
	cmp := WithComparator(newFakeComparator("r~1", "r~2", "s~1"))
	for _, c := range []struct{ blob, grade string }{{"r~1", "T1 under " + shortDigest(dig("K"))}, {"r~2", "T1"}, {"s~1", DivergedToken}} {
		everyOrderArtifact(t, w, c.blob, func(a *Artifact) {
			has(t, a.Render(), "derived by 3: 2 match, 1 diverged")
			if !strings.HasPrefix(a.Step.String(), c.grade) {
				t.Fatalf("%s: step %s\n%s", c.blob, a.Step, a.Render())
			}
			hasNot(t, a.Render(), "contested")
		}, cmp)
	}
	// with no comparator runner configured the reader made no comparison: unchecked, never a default verdict
	a := w.store(nil).Artifact(dig("r~1"))
	if a.Step.Why != UncheckedToken {
		t.Fatalf("no runner: %s", a.Step)
	}
}

// TestUndeclaredReplication: C-core-25. No replication on W's authored: identical and different both unchecked;
// neither T0 nor T1; verify exits 3.
func TestUndeclaredReplication(t *testing.T) {
	conformance.Covers(t, "C-core-25")
	for _, outs := range []map[string]string{{"A": "X", "BB": "X"}, {"A": "X", "BB": "Y"}} {
		w := groupWorld(t, "", "", outs)
		a := w.store(nil).Artifact(dig("X"))
		if a.Step.Why != UncheckedToken || a.Grade.Tier != "" {
			t.Fatalf("step %s\n%s", a.Step, a.Render())
		}
		has(t, a.Render(), "declares no replication")
		wantExit(t, a, 3, "derivation: unchecked")
	}
	// a protocol workflow with no comparator is unchecked too, and says so
	w := groupWorld(t, "protocol", "", map[string]string{"A": "X", "BB": "Y"})
	a := w.store(nil).Artifact(dig("X"))
	has(t, a.Render(), "no comparator")
	wantExit(t, a, 3, "unchecked")
}

// TestAcrossWorkflows: C-core-26. Same bytes under different workflows: no group is formed, §5.2 (2) applies,
// one blob, a reproduced across workflows links them, W1's authored unchanged.
func TestAcrossWorkflows(t *testing.T) {
	conformance.Covers(t, "C-core-26")
	w := newWorld(t)
	w.workflow("WA", "W1", "bytes", "")
	w.workflow("WB", "W2", "bytes", "")
	a1 := w.authored("A1", "A", "X", "prov", []string{"W1", "I"}, "licence", "CC0-1.0")
	w.anchor("AA", "A", "btc:100")
	w.authored("B1", "BB", "X", "prov", []string{"W2", "I"})
	w.anchor("BA", "BB", "btc:101")
	w.sign("BR", "BB", "reproduced", obj("of", a1, "result", "match", "content", contentOf("X"),
		"provenance", obj("workflow", dig("W2"), "inputs", []string{dig("I")})))
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, Priority)
		if len(a.Units) != 2 || a.Default.Claims[0].Signer != w.signer("A") || a.Group.Provenance.Workflow != dig("W1") {
			t.Fatalf("%s", a.Render())
		}
		out := a.Render()
		has(t, out, "later claimant")
		has(t, out, "held reproduced "+keylog.Short(w.ids["BR"]))
		has(t, out, "across workflows")
		wantField(t, a, "licence", FieldDefault, `"CC0-1.0"`)
		// the reproduced is a run of neither group
		for _, run := range a.Group.Runs {
			if run.Statement == w.ids["BR"] {
				t.Fatal("cross-workflow reproduced counted as a run")
			}
		}
	}, WithTimeVerifier(newFakeBitcoin(100, 101)))
}

// TestFieldContestedInGroup: C-core-27. Within one group A says CC-BY-4.0 and B says MIT, both the same
// availability: licence contested listing both, availability by agreement, group display intact, verify 3
// citing only the licence.
func TestFieldContestedInGroup(t *testing.T) {
	conformance.Covers(t, "C-core-27")
	w := newWorld(t)
	w.workflow("WA", "W", "bytes", "")
	av := obj("redistribution", "permitted", "obtainable", true)
	w.authored("A1", "A", "X", "prov", []string{"W", "I"}, "licence", "CC-BY-4.0", "availability", av)
	w.authored("B1", "BB", "X", "prov", []string{"W", "I"}, "licence", "MIT", "availability", av)
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		wantField(t, a, "licence", FieldContested, "")
		wantField(t, a, "availability", FieldDefault, "")
		lic := a.Field("licence")
		if len(lic.From) != 2 || lic.From[0].Signer == lic.From[1].Signer {
			t.Fatalf("licence %+v", lic)
		}
		has(t, a.Render(), "derived by 2: byte-identical re-derivation (T0)")
		code, why := a.VerifyExit()
		if code != 3 || len(why) != 1 || why[0] != "field licence: contested" {
			t.Fatalf("verify %d %q", code, why)
		}
	})
}

// TestHoldersAreNotDerivers: C-core-28. H publishes only holds: listed under holders, never as a deriver.
func TestHoldersAreNotDerivers(t *testing.T) {
	conformance.Covers(t, "C-core-28")
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X"})
	w.sign("HH", "H", "holds", obj("content", contentOf("X"), "locations", []string{"https://mirror.example/x"}))
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		if !slices.Equal(a.Group.Derivers, w.controllers("A", "BB")) || !slices.Equal(a.Holders, []string{w.signer("H")}) {
			t.Fatalf("derivers %v holders %v", a.Group.Derivers, a.Holders)
		}
		has(t, a.Render(), "derived by 2")
	})
	// a later withdrawn holds by the same key takes it off the holders list; the earlier line stays in its log
	w.sign("HW", "H", "holds", obj("content", contentOf("X"), "withdrawn", true))
	a := w.store(nil).Artifact(dig("X"))
	if len(a.Holders) != 0 {
		t.Fatalf("withdrawn holder still listed: %v", a.Holders)
	}
}

// TestReproducedJoinsGroup: C-exec-01 (resolver half). A's own re-run is a reproduced, not a second authored:
// the group shows derived by 1 plus the reproduction, and a byte-identical reproduction under bytes is T0.
func TestReproducedJoinsGroup(t *testing.T) {
	conformance.Partial(t, "C-exec-01", "the group display; emitting reproduced instead of authored is run --publish")
	w := newWorld(t)
	w.workflow("WA", "W", "bytes", "")
	a1 := w.authored("A1", "A", "X", "prov", []string{"W", "I"})
	w.sign("AR", "A", "reproduced", obj("of", a1, "result", "match", "content", contentOf("X"),
		"provenance", obj("workflow", dig("W"), "inputs", []string{dig("I")})))
	a := w.store(nil).Artifact(dig("X"))
	if len(a.Group.Derivers) != 1 || len(a.Group.Runs) != 2 || a.Step.Tier != "T0" {
		t.Fatalf("%s", a.Render())
	}
	has(t, a.Render(), "derived by 1: byte-identical re-derivation (T0)")
	has(t, a.Render(), "reproduced "+keylog.Short(w.ids["AR"]))
}

// --- §7 grades ---------------------------------------------------------------------------------------------

// TestWeakestLinkAndObservations: C-core-64. A byte-identical re-derivation whose only input is an observation
// contradicted once: grade T0, the summary beside it, exit unchanged. Plus the weakest-link rule over a derived
// input and the refutation exemption (claims §7).
func TestWeakestLinkAndObservations(t *testing.T) {
	conformance.Covers(t, "C-core-64")
	w := newWorld(t)
	obsID := w.sign("O1", "O", "observed", obj("content", contentOf("OBS"), "class", "none-yet", "referent", obj(),
		"capture", obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted")))
	w.sign("CC", "C", "corroborates", obj("of", obsID, "result", strings.Repeat("ab", 32), "verdict", "contradicts",
		"model", "bounds/1", "cohort", obj("rule", "climate record")))
	w.workflow("WA", "W", "bytes", "")
	w.authored("A1", "A", "X", "prov", []string{"W", "OBS"})
	w.authored("B1", "BB", "X", "prov", []string{"W", "OBS"})
	a := w.store(nil).Artifact(dig("X"))
	if a.Grade.Tier != "T0" {
		t.Fatalf("grade %s\n%s", a.Grade, a.Render())
	}
	has(t, a.Render(), "rests on 1 observation(s): 1 contradicted within statements you hold")
	wantExit(t, a, 0, "")

	// weakest link: Z derives from X (T0) under a protocol workflow with no comparator → unchecked; and from a
	// T1 input → T1
	w.workflow("WA2", "P", "protocol", "K")
	w.authored("A2", "A", "r~1", "prov", []string{"P", "I"})
	w.authored("B2", "BB", "r~2", "prov", []string{"P", "I"})
	w.workflow("WA3", "Z", "bytes", "")
	w.authored("A3", "A", "OUT", "prov", []string{"Z", "X", "r~1"})
	w.authored("B3", "BB", "OUT", "prov", []string{"Z", "X", "r~1"})
	r := w.store(nil, WithComparator(newFakeComparator("r~1", "r~2")))
	out := r.Artifact(dig("OUT"))
	if out.Step.Tier != "T0" || out.Grade.Tier != "T1" {
		t.Fatalf("step %s grade %s\n%s", out.Step, out.Grade, out.Render())
	}
	has(t, out.Render(), "weakest derivation step")

	// the refutation exemption: the same blob as a refutation's evidence keeps its own step
	w.sign("RF", "C", "refutes", obj("of", w.ids["A1"], "evidence", dig("OUT")))
	ref := w.store(nil, WithComparator(newFakeComparator("r~1", "r~2"))).Artifact(dig("OUT"))
	if ref.Grade.Tier != "T0" {
		t.Fatalf("refutation grade %s", ref.Grade)
	}
	has(t, ref.Render(), "exempt from the weakest-link rule")
}

// TestDisclosureNeverGrades: C-core-65 over the disclosures the artifact view carries today. Fix a T0 artifact;
// mutate one disclosure at a time across its value set (incl. missing): grade and exit never change, the
// displayed value does.
func TestDisclosureNeverGrades(t *testing.T) {
	conformance.Partial(t, "C-core-65", "licence, availability, replication on the output, sampling, shelf life, pre-registration; capture evidence, corroboration, selection, referent status and finality land with their views")
	values := map[string][]canon.Value{
		"licence":          {canon.String("CC0-1.0"), canon.String("MIT"), canon.String("LicenseRef-x AND CC-BY-4.0"), canon.String("not spdx")},
		"availability":     {obj("redistribution", "permitted", "obtainable", true), obj("redistribution", "withheld", "obtainable", false, "withheld_until", "task")},
		"replication":      {canon.String("bytes"), canon.String("protocol"), canon.String("none")},
		"sampling":         {obj("n", 30, "unit", "runs"), obj("n", 2, "unit", "slots", "groups", canon.Array{obj("name", "a", "n", 1), obj("name", "b", "n", 1)})},
		"shelf_life_days":  {canon.Int(0), canon.Int(365)},
		"pre_registration": {canon.String("exploratory")},
	}
	build := func(field string, v canon.Value) *Artifact {
		w := newWorld(t)
		w.workflow("WA", "W", "bytes", "")
		var kv []any
		if v != nil {
			kv = []any{field, v}
		}
		w.authored("A1", "A", "X", append([]any{"prov", []string{"W", "I"}}, kv...)...)
		w.authored("B1", "BB", "X", append([]any{"prov", []string{"W", "I"}}, kv...)...)
		return w.store(nil).Artifact(dig("X"))
	}
	for _, field := range sortedKeys(values) {
		var displays []string
		for _, v := range append([]canon.Value{nil}, values[field]...) {
			a := build(field, v)
			code, _ := a.VerifyExit()
			if a.Grade.Tier != "T0" || code != 0 {
				t.Fatalf("%s=%v moved the grade or exit: %s %d", field, v, a.Grade, code)
			}
			line := ""
			for _, l := range strings.Split(a.Render(), "\n") {
				if strings.HasPrefix(l, "  "+field+":") {
					line = l
				}
			}
			if line == "" {
				t.Fatalf("%s not shown beside the grade\n%s", field, a.Render())
			}
			displays = append(displays, line)
		}
		if len(slices.Compact(slices.Clone(displays))) < 2 {
			t.Fatalf("%s: display did not change: %v", field, displays)
		}
	}
}

// --- properties --------------------------------------------------------------------------------------------

// genAuthorship draws a world of authored/holds/describes/reproduced/anchors statements over a few blobs, keys
// and two workflows, with amendments.
func genAuthorship(t *testing.T, seed uint64) (*world, []string) {
	w := newWorld(t)
	rnd := func(n int) int {
		seed = seed*6364136223846793005 + 1442695040888963407
		return int((seed >> 33) % uint64(n))
	}
	keys := []string{"A", "BB", "C"}
	blobs := []string{"X", "Y", "r~1", "r~2"}
	w.workflow("A", "W", []string{"bytes", "protocol", ""}[rnd(3)], "K")
	for i := 0; i < 4+rnd(8); i++ {
		k, x := keys[rnd(3)], blobs[rnd(4)]
		name := fmt.Sprint("s", i)
		switch op := rnd(10); {
		case op < 4:
			kv := []any{"licence", []string{"CC0-1.0", "MIT"}[rnd(2)]}
			if rnd(2) == 0 {
				kv = append(kv, "prov", []string{"W", "I"})
			}
			w.authored(name, k, x, kv...)
		case op < 6 && w.head[k] != "":
			w.anchor(name, k, fmt.Sprint("btc:", 100+rnd(3)))
		case op == 6:
			w.sign(name, k, "holds", obj("content", contentOf(x)))
		case op == 7:
			w.sign(name, k, "describes", obj("about", obj("content", dig(x)), "note", "n"))
		default:
			if id, ok := w.ids[fmt.Sprint("s", rnd(i+1))]; ok && w.by[id] != "" {
				w.sign(name, k, "reproduced", obj("of", id, "result", "match", "content", contentOf(x),
					"provenance", obj("workflow", dig("W"), "inputs", []string{dig("I")})))
			}
		}
	}
	return w, blobs
}

// TestArtifactPermutationProperty: P-01 over the artifact view.
func TestArtifactPermutationProperty(t *testing.T) {
	conformance.Partial(t, "P-01", "artifacts: authorship, defaults, groups and grades; other views as they land")
	opts := []Option{WithTimeVerifier(newFakeBitcoin(100, 101)), WithComparator(newFakeComparator("X", "Y", "r~1", "r~2"))}
	for seed := uint64(1); seed <= 40; seed++ {
		w, blobs := genAuthorship(t, seed)
		for _, x := range blobs {
			first := w.store(nil, opts...).Artifact(dig(x)).Render()
			for _, o := range sampleOrders(len(w.lines), seed, 12) {
				if got := w.store(o, opts...).Artifact(dig(x)).Render(); got != first {
					t.Fatalf("seed %d blob %s order %v:\n%s\nvs\n%s", seed, x, o, got, first)
				}
			}
		}
	}
}

// TestDuplicatesProperty: P-02 over the artifact view. Delivering every line twice changes nothing.
func TestDuplicatesProperty(t *testing.T) {
	conformance.Partial(t, "P-02", "duplicate delivery over the artifact view; equivalent signature encodings are covered for resources (TestKOfNDuplicates)")
	for seed := uint64(1); seed <= 20; seed++ {
		w, blobs := genAuthorship(t, seed)
		order := make([]int, 0, 2*len(w.lines))
		for i := range w.lines {
			order = append(order, i, i)
		}
		for _, x := range blobs {
			once := w.store(nil).Artifact(dig(x)).Render()
			if twice := w.store(order).Artifact(dig(x)).Render(); twice != once {
				t.Fatalf("seed %d: duplicates changed the answer", seed)
			}
		}
	}
}

// TestNonInterferenceProperty: P-03 over authorship. For generated states S and a statement L by a fresh key
// with no authority over blob X (holds, describes, a rival authored on another blob), result_X(S+L) equals
// result_X(S), explanation included.
func TestNonInterferenceProperty(t *testing.T) {
	conformance.Partial(t, "P-03", "authorship, defaults and grades of blobs; resources and tasks as they land")
	opts := []Option{WithTimeVerifier(newFakeBitcoin(100, 101, 102))}
	for seed := uint64(1); seed <= 30; seed++ {
		for _, add := range []func(w *world){
			func(w *world) { w.sign("L", "Q", "holds", obj("content", contentOf("X"))) },
			func(w *world) {
				w.sign("L", "Q", "describes", obj("about", obj("content", dig("X")), "tags", []string{"bad"}))
			},
			func(w *world) { w.authored("L", "Q", "OTHER", "licence", "MIT") },
		} {
			w, _ := genAuthorship(t, seed)
			before := w.store(nil, opts...).Artifact(dig("X"))
			add(w)
			after := w.store(nil, opts...).Artifact(dig("X"))
			if before.Outcome() != after.Outcome() || before.Grade != after.Grade || strings.Join(before.Explain, "\n") != strings.Join(after.Explain, "\n") {
				t.Fatalf("seed %d: an unrelated statement changed X:\n%s\nvs\n%s", seed, before.Render(), after.Render())
			}
		}
	}
}

// TestLocalAnchorsOrderNothing: P-06. Adding any local-quality anchor changes no default and no priority outcome.
func TestLocalAnchorsOrderNothing(t *testing.T) {
	conformance.Covers(t, "P-06")
	for seed := uint64(1); seed <= 40; seed++ {
		w, blobs := genAuthorship(t, seed)
		var before []string
		for _, x := range blobs {
			before = append(before, w.store(nil).Artifact(dig(x)).Outcome())
		}
		for _, k := range []string{"A", "BB", "C"} {
			if w.head[k] != "" {
				w.anchor("LOC"+k, k, "local:"+k)
			}
		}
		for i, x := range blobs {
			if got := w.store(nil).Artifact(dig(x)).Outcome(); got != before[i] {
				t.Fatalf("seed %d blob %s: a local anchor changed %q to %q", seed, x, before[i], got)
			}
		}
	}
}

// TestBoundsArePerSigner: C-btc-04 (the log and resolver half) and the `covered` rule of wire §5. A's anchor
// naming B's line is refused in A's log and bounds nothing; B's line shows no anchor; B's log is untouched. An
// anchor whose covered line is on a branch the anchor does not reach bounds nothing either.
func TestBoundsArePerSigner(t *testing.T) {
	conformance.Partial(t, "C-btc-04", "covered naming another key's line; a proof committing to B's prefix under A's anchor needs the OTS verifier")
	w := newWorld(t)
	w.authored("A0", "A", "Z")
	b1 := w.authored("B1", "BB", "X")
	w.sign("AA", "A", "anchors", obj("covered", b1, "proof", dig("btc:100"), "proof_format", "ots-detached-v1"))
	w.authored("C1", "C", "X")
	w.anchor("CA", "C", "btc:101")
	opts := WithTimeVerifier(newFakeBitcoin(100, 101))
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		// C's verified bound outranks B's absent one: if A's misattached anchor had bounded B at 100, B would win
		wantAuthorship(t, a, Priority)
		if a.Default.Claims[0].Signer != w.signer("C") {
			t.Fatalf("%s", a.Render())
		}
		has(t, a.Render(), "later claimant "+shortKey(w.signer("BB"))+", bound no anchor")
	}, opts)
	s := keylog.NewStore()
	for _, l := range w.lines {
		st, _ := wire.Read(l)
		s.Log(st.Signer).Add(l)
	}
	v := s.Log(w.signer("A")).View()
	if len(v.Refused) != 1 || !strings.Contains(v.Refused[0].Reason.Detail, "an anchor bounds only its signer's log") {
		t.Fatalf("A's misattached anchor not refused: %s", v.Render())
	}
	if bv := s.Log(w.signer("BB")).View(); len(bv.Lines) != 1 || len(bv.Refused) != 0 {
		t.Fatalf("B's log changed: %s", bv.Render())
	}

	// a sibling branch: A anchors a line its anchor line does not reach
	w2 := newWorld(t)
	w2.authored("A0", "A", "Y")
	fork, seq := w2.head["A"], w2.seq["A"]
	side := w2.authored("A1", "A", "X")
	w2.head["A"], w2.seq["A"] = fork, seq
	w2.sign("AA", "A", "anchors", obj("covered", side, "proof", dig("btc:100"), "proof_format", "ots-detached-v1"))
	a := w2.store(nil, opts).Artifact(dig("X"))
	if a.Default.Bound.Quality != NoBound {
		t.Fatalf("an anchor bounded a line it does not reach: %s", a.Default.Bound)
	}
}

// TestWorkflowModeFromItsDefault: finding A7. The replication a group reads is the workflow blob's resolved
// default. When a second key claims the workflow with another mode and nobody has a verified bound, the
// workflow's authorship is contested, there is no default mode, and the group is unchecked (fail closed). The
// rival can only downgrade, never upgrade.
func TestWorkflowModeFromItsDefault(t *testing.T) {
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X"})
	if a := w.store(nil).Artifact(dig("X")); a.Step.Tier != "T0" {
		t.Fatalf("control: %s", a.Step)
	}
	w.workflow("Q", "W", "protocol", "")
	a := w.store(nil).Artifact(dig("X"))
	if a.Step.Why != UncheckedToken {
		t.Fatalf("contested workflow: step %s\n%s", a.Step, a.Render())
	}
	has(t, a.Render(), "the workflow's authorship is contested")
	wantExit(t, a, 3, "derivation: unchecked")
}

// TestAuthorshipDoesNotHideGroups: a claim on the bytes outside the derivation group (no provenance, or another
// workflow) can make authorship contested; it never takes the group's evidence off the blob. X stays T0 with the
// group shown, authorship is contested with exit 3 for that reason only, and a downstream result is unchanged.
// Before: grade read "no derivation (no provenance)" and the group vanished from the view.
func TestAuthorshipDoesNotHideGroups(t *testing.T) {
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X"})
	w.authored("C1", "CC", "X")
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, ContestedAuthorship)
		if a.Step.Tier != "T0" || a.Grade.Tier != "T0" || a.Group == nil {
			t.Fatalf("step %s grade %s\n%s", a.Step, a.Grade, a.Render())
		}
		out := a.Render()
		has(t, out, "derived by 2: byte-identical re-derivation (T0)")
		has(t, out, "authorship (contested) does not move it")
		code, why := a.VerifyExit()
		if code != 3 || len(why) != 1 || why[0] != "authorship: contested" {
			t.Fatalf("verify %d %v", code, why)
		}
	})

	// a rival under another workflow: both groups shown, the blob's step is the stronger evidence
	w2 := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X"})
	w2.workflow("WB", "W2", "bytes", "")
	w2.authored("C1", "CC", "X", "prov", []string{"W2", "I"})
	everyOrderArtifact(t, w2, "X", func(a *Artifact) {
		wantAuthorship(t, a, ContestedAuthorship)
		if len(a.Groups) != 2 || a.Step.Tier != "T0" || a.Group.Provenance.Workflow != dig("W") {
			t.Fatalf("groups %d step %s\n%s", len(a.Groups), a.Step, a.Render())
		}
		has(t, a.Render(), "derived by 1, not re-derived")
	})

	// same bytes, verified priority to the outsider: still T0 from the group (priority is credit, not evidence)
	w3 := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X"})
	w3.authored("C1", "CC", "X")
	w3.anchor("CA", "CC", "btc:100")
	a := w3.store(nil, WithTimeVerifier(newFakeBitcoin(100))).Artifact(dig("X"))
	wantAuthorship(t, a, Priority)
	if a.Default.Provenance != nil || a.Step.Tier != "T0" {
		t.Fatalf("outsider default: step %s\n%s", a.Step, a.Render())
	}
	wantExit(t, a, 0, "")
}

// TestNonInterferenceGroupEvidence: I5 as a property over the grade. For a T0 blob, adding any one claim that
// bears only on authorship (a bare authored by a new key, one under another workflow with a fresh input, or an
// amendment by an existing deriver that drops provenance) never lowers the blob's step below T0.
func TestNonInterferenceGroupEvidence(t *testing.T) {
	adds := map[string]func(w *world){
		"bare": func(w *world) { w.authored("C1", "CC", "X") },
		"other wf": func(w *world) {
			w.workflow("WB", "W2", "protocol", "")
			w.authored("C1", "CC", "X", "prov", []string{"W2", "J"})
		},
		"other input": func(w *world) { w.authored("C1", "CC", "X", "prov", []string{"W", "J"}) },
		"licence":     func(w *world) { w.authored("C1", "CC", "X", "licence", "MIT") },
	}
	for _, name := range sortedKeys(adds) {
		w := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X"})
		adds[name](w)
		everyOrderArtifact(t, w, "X", func(a *Artifact) {
			if a.Step.Tier != "T0" {
				t.Fatalf("%s: step %s\n%s", name, a.Step, a.Render())
			}
		})
	}
}

// TestBytesPerOutput: A13. Under `bytes`, an output another run also produced is T0 whatever else the group
// holds; an output no other run produced is diverged. One stray run (anyone can assert a provenance) never turns
// the reproduced bytes into "checked and wrong". The group still shows the divergence beside the grade.
func TestBytesPerOutput(t *testing.T) {
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X", "CC": "Y"})
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		if a.Step.Tier != "T0" {
			t.Fatalf("X step %s\n%s", a.Step, a.Render())
		}
		out := a.Render()
		has(t, out, "derived by 3: diverged (2 different outputs); 1 of them byte-identical across runs (T0)")
		has(t, out, "an environment differs or the determinism claim is wrong")
		wantExit(t, a, 0, "")
	})
	everyOrderArtifact(t, w, "Y", func(a *Artifact) {
		if a.Step.Why != DivergedToken {
			t.Fatalf("Y step %s\n%s", a.Step, a.Render())
		}
		wantExit(t, a, 1, "diverged")
	})

	// a reproduced run counts as a run: A's own re-run of X and B's Y → X T0, Y diverged
	w2 := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "Y"})
	w2.sign("AR", "A", "reproduced", obj("of", w2.ids["A1"], "result", "match", "content", contentOf("X"),
		"provenance", obj("workflow", dig("W"), "inputs", []string{dig("I")})))
	if a := w2.store(nil).Artifact(dig("X")); a.Step.Tier != "T0" {
		t.Fatalf("X with a reproduced: %s\n%s", a.Step, a.Render())
	}
	if a := w2.store(nil).Artifact(dig("Y")); a.Step.Why != DivergedToken {
		t.Fatalf("Y with a reproduced: %s", a.Step)
	}
}

// TestDivergedOutranksUnrederived: a blob diverged in one group and not re-derived in another shows diverged
// (a completed comparison that disagreed beats one that never ran); the other group is shown beside it.
func TestDivergedOutranksUnrederived(t *testing.T) {
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "Y"})
	w.workflow("WB", "W2", "bytes", "")
	w.authored("C1", "CC", "X", "prov", []string{"W2", "I"})
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		if a.Step.Why != DivergedToken || len(a.Groups) != 2 {
			t.Fatalf("step %s groups %d\n%s", a.Step, len(a.Groups), a.Render())
		}
		wantExit(t, a, 1, "diverged")
	})
}

// TestReproducedOutranksOtherGroupsDivergence: X is T0 under W (A and B) and diverged under W2, where two other
// keys claim X and Y. A passed re-derivation is a check of these bytes that passed; a group of someone else's
// choosing that disagrees is shown beside it, never turns X's verify into 1 (I7: otherwise two strangers could
// invent a workflow and flip any blob to "checked and wrong").
func TestReproducedOutranksOtherGroupsDivergence(t *testing.T) {
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X"})
	w.workflow("WB", "W2", "bytes", "")
	w.authored("C1", "CC", "X", "prov", []string{"W2", "I"})
	w.authored("D1", "DD", "Y", "prov", []string{"W2", "I"})
	sampledOrderArtifact(t, w, "X", func(a *Artifact) {
		if a.Step.Tier != "T0" || a.Group.Provenance.Workflow != dig("W") {
			t.Fatalf("step %s\n%s", a.Step, a.Render())
		}
		has(t, a.Render(), "shows these bytes diverged; shown beside the grade")
		wantExit(t, a, 3, "authorship: contested")
	})
}

// tableComparator answers from a table of name pairs ("a|b" → result, either order unless asym) and counts
// every call.
type tableComparator struct {
	names map[string]string
	table map[string]string
	asym  bool
	calls *int
}

func newTableComparator(table map[string]string, blobs ...string) tableComparator {
	c := tableComparator{names: map[string]string{}, table: table, calls: new(int)}
	for _, b := range blobs {
		c.names[dig(b)] = b
	}
	return c
}

func (c tableComparator) Compare(_, a, b string) (string, string) {
	*c.calls++
	x, y := c.names[a], c.names[b]
	if r, ok := c.table[x+"|"+y]; ok {
		return r, ""
	}
	if r, ok := c.table[y+"|"+x]; ok && !c.asym {
		return r, ""
	}
	return "diverged", ""
}

// TestProtocolAllAgree: every pair matched → `all n runs match under K`, each run T1 with every other as partner.
func TestProtocolAllAgree(t *testing.T) {
	w := groupWorld(t, "protocol", "K", map[string]string{"A": "a", "BB": "b", "CC": "c"})
	cmp := WithComparator(newTableComparator(map[string]string{"a|b": "match", "b|c": "match", "a|c": "match"}, "a", "b", "c"))
	everyOrderArtifact(t, w, "a", func(a *Artifact) {
		has(t, a.Render(), "derived by 3: all 3 runs match under "+shortDigest(dig("K")))
		for _, run := range a.Group.Runs {
			if run.Grade.Tier != "T1" || len(run.Partners) != 2 {
				t.Fatalf("run %+v", run)
			}
		}
		wantExit(t, a, 0, "")
	}, cmp)
}

// TestProtocolNotTransitive: A~B, B~C, A≁C. Each run is T1 with its own partners; the summary never says the
// three agree; explain names the pair that diverged.
func TestProtocolNotTransitive(t *testing.T) {
	w := groupWorld(t, "protocol", "K", map[string]string{"A": "a", "BB": "b", "CC": "c"})
	cmp := WithComparator(newTableComparator(map[string]string{"a|b": "match", "b|c": "match"}, "a", "b", "c"))
	everyOrderArtifact(t, w, "a", func(a *Artifact) {
		out := a.Render()
		has(t, out, "derived by 3: 3 match, 0 diverged; matching runs do not all agree (1 cluster; 1 of 3 pairs among them diverged)")
		has(t, out, "tolerance is not transitive; matches are never chained")
		hasNot(t, out, "all 3 runs match")
		for _, run := range a.Group.Runs {
			want := map[string]int{dig("a"): 1, dig("b"): 2, dig("c"): 1}[run.Output]
			if run.Grade.Tier != "T1" || len(run.Partners) != want {
				t.Fatalf("run %s: %s partners %d", shortDigest(run.Output), run.Grade, len(run.Partners))
			}
		}
		wantExit(t, a, 0, "")
	}, cmp)
}

// TestProtocolCamps: A~B and C~D, every cross pair diverged. Four T1 runs; the summary names two clusters and
// four diverged pairs, never "all match".
func TestProtocolCamps(t *testing.T) {
	w := groupWorld(t, "protocol", "K", map[string]string{"A": "a", "BB": "b", "CC": "c", "DD": "d"})
	cmp := WithComparator(newTableComparator(map[string]string{"a|b": "match", "c|d": "match"}, "a", "b", "c", "d"))
	a := w.store(nil, cmp).Artifact(dig("a"))
	has(t, a.Render(), "derived by 4: 4 match, 0 diverged; matching runs do not all agree (2 clusters; 4 of 6 pairs among them diverged)")
}

// TestComparatorCostAndCache: k = 10 outputs. One full view runs each of the 45 pairs once; viewing every blob
// after it runs nothing more (cache). Verify of one blob on a fresh resolver runs at most k-1 = 9 and stops at
// the first match; it gives the full view's exit for every blob.
func TestComparatorCostAndCache(t *testing.T) {
	outs := map[string]string{}
	var blobs []string
	for i := 0; i < 10; i++ {
		b := fmt.Sprintf("o%d", i)
		outs[fmt.Sprintf("K%d", i)] = b
		blobs = append(blobs, b)
	}
	table := map[string]string{"o0|o9": "match", "o3|o4": "match"}
	w := groupWorld(t, "protocol", "K", outs)

	c := newTableComparator(table, blobs...)
	r := w.store(nil, WithComparator(c))
	r.Artifact(dig("o0"))
	if *c.calls != 45 {
		t.Fatalf("full view: %d comparator runs, want 45", *c.calls)
	}
	for _, b := range blobs {
		r.Artifact(dig(b))
	}
	if *c.calls != 45 {
		t.Fatalf("every view: %d comparator runs, want 45 (cached)", *c.calls)
	}

	for _, b := range blobs {
		lazy := newTableComparator(table, blobs...)
		code, why := w.store(nil, WithComparator(lazy)).Verify(dig(b))
		if *lazy.calls > 9 {
			t.Fatalf("verify %s: %d comparator runs, want <= 9", b, *lazy.calls)
		}
		full, fwhy := r.Artifact(dig(b)).VerifyExit()
		if code != full || strings.Join(why, ";") != strings.Join(fwhy, ";") {
			t.Fatalf("verify %s: %d %v, full view %d %v", b, code, why, full, fwhy)
		}
	}
	// an output that matches the first other output it is compared with stops there: o3's first comparison in
	// digest order is with whichever output sorts first, so give o3 a match with every output to pin the stop
	all := map[string]string{}
	for _, b := range blobs {
		if b != "o3" {
			all["o3|"+b] = "match"
		}
	}
	lazy := newTableComparator(all, blobs...)
	if code, _ := w.store(nil, WithComparator(lazy)).Verify(dig("o3")); code != 0 || *lazy.calls != 1 {
		t.Fatalf("verify o3: exit %d after %d comparator runs, want 0 after 1", code, *lazy.calls)
	}
}

// TestComparatorAskedOneWay: an asymmetric comparator (match only when asked a,b) gives one answer whichever
// blob is viewed and in whatever order: the pair is always asked in digest order.
func TestComparatorAskedOneWay(t *testing.T) {
	w := groupWorld(t, "protocol", "K", map[string]string{"A": "a", "BB": "b"})
	c := newTableComparator(map[string]string{"a|b": "match"}, "a", "b")
	c.asym = true
	ga := w.store(nil, WithComparator(c)).Artifact(dig("a")).Step
	gb := w.store(nil, WithComparator(c)).Artifact(dig("b")).Step
	vb, _ := w.store(nil, WithComparator(c)).Verify(dig("b"))
	va, _ := w.store(nil, WithComparator(c)).Verify(dig("a"))
	if ga != gb || va != vb {
		t.Fatalf("asymmetric comparator: a %s / %d, b %s / %d", ga, va, gb, vb)
	}
}

// TestVerifyMatchesView: Verify(d) equals Artifact(d).VerifyExit() across the group fixtures of this file.
func TestVerifyMatchesView(t *testing.T) {
	type fx struct {
		w    *world
		opts []Option
		blob []string
	}
	cmp := WithComparator(newFakeComparator("r~1", "r~2", "s~1"))
	w1 := groupWorld(t, "protocol", "K", map[string]string{"A": "r~1", "BB": "r~2", "C": "s~1"})
	w2 := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X", "CC": "Y"})
	w3 := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X"})
	w3.authored("C1", "CC", "X")
	w4 := groupWorld(t, "", "", map[string]string{"A": "X", "BB": "Y"})
	for i, f := range []fx{{w1, []Option{cmp}, []string{"r~1", "r~2", "s~1"}}, {w1, nil, []string{"r~1"}},
		{w2, nil, []string{"X", "Y"}}, {w3, nil, []string{"X"}}, {w4, nil, []string{"X", "Y"}}} {
		for _, b := range f.blob {
			got, gwhy := f.w.store(nil, f.opts...).Verify(dig(b))
			want, wwhy := f.w.store(nil, f.opts...).Artifact(dig(b)).VerifyExit()
			if got != want || strings.Join(gwhy, ";") != strings.Join(wwhy, ";") {
				t.Fatalf("fixture %d %s: verify %d %v, view %d %v", i, b, got, gwhy, want, wwhy)
			}
		}
	}
}

// TestRowNotComparable: a run whose comparisons are one diverged and one not comparable is `not comparable`,
// never `diverged` (diverged needs every comparison to have run and disagreed; exit 1 is reserved for that).
func TestRowNotComparable(t *testing.T) {
	w := groupWorld(t, "protocol", "K", map[string]string{"A": "a", "BB": "b", "CC": "c"})
	cmp := WithComparator(newTableComparator(map[string]string{"a|b": "not comparable", "a|c": "diverged", "b|c": "diverged"}, "a", "b", "c"))
	a := w.store(nil, cmp).Artifact(dig("a"))
	if a.Step.Why != NotComparable {
		t.Fatalf("step %s\n%s", a.Step, a.Render())
	}
	wantExit(t, a, 3, "not comparable")
	if code, _ := w.store(nil, cmp).Verify(dig("a")); code != 3 {
		t.Fatalf("verify %d", code)
	}
}

// TestNotRederivedExits3: A4. A derivation nobody re-derived is unchecked: verify exits 3 citing it, under every
// replication mode, and the full view and Verify agree. A construction without provenance (C-core-17) still
// exits 0. A second run decides it: identical bytes under `bytes` → 0, different → the stray output 1.
func TestNotRederivedExits3(t *testing.T) {
	for _, mode := range []string{"bytes", "protocol", ""} {
		w := groupWorld(t, mode, "K", map[string]string{"A": "X"})
		everyOrderArtifact(t, w, "X", func(a *Artifact) {
			if a.Step.Why != NotRederived {
				t.Fatalf("mode %q: step %s", mode, a.Step)
			}
			wantExit(t, a, 3, "derivation: not re-derived")
			has(t, a.Render(), "a re-run by the reader, or a `reproduced` by anyone, is what checks it")
		})
		if code, _ := w.store(nil).Verify(dig("X")); code != 3 {
			t.Fatalf("mode %q: Verify %d", mode, code)
		}
	}
	w := newWorld(t)
	w.authored("A1", "A", "X")
	wantExit(t, w.store(nil).Artifact(dig("X")), 0, "")
}

// TestMoreEvidenceNeverPasses: monotonicity (P-A4-mono). From a sole derivation (exit 3), adding a run can move
// the exit to 0 only when the run brings a comparison that passed for these bytes; a run that compares nothing
// or disagrees never turns 3 into 0.
func TestMoreEvidenceNeverPasses(t *testing.T) {
	cases := []struct {
		mode, other string
		want        int
	}{
		{"bytes", "X", 0}, {"bytes", "Y", 1}, // a byte-identical re-run passes; a different one: X has no partner
		{"", "X", 3}, {"", "Y", 3}, // undeclared: nothing compares
		{"protocol", "X", 0}, // identical bytes under protocol: `match (identical bytes)`, no tier (execution §5.3)
		{"protocol", "Y", 3},
	}
	for _, c := range cases {
		w := groupWorld(t, c.mode, "", map[string]string{"A": "X"})
		before, _ := w.store(nil).Artifact(dig("X")).VerifyExit()
		w.authored("B1", "BB", c.other, "prov", []string{"W", "I"})
		after, why := w.store(nil).Artifact(dig("X")).VerifyExit()
		if before != 3 || after != c.want {
			t.Fatalf("mode %q other %s: %d → %d %v, want 3 → %d", c.mode, c.other, before, after, why, c.want)
		}
	}
}

// TestSelfReproduction: the author's own reproduced is a second run: T0, verify 0, and explain says the bytes
// were re-derived by their author only.
func TestSelfReproduction(t *testing.T) {
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X"})
	w.sign("AR", "A", "reproduced", obj("of", w.ids["A1"], "result", "match", "content", contentOf("X"),
		"provenance", obj("workflow", dig("W"), "inputs", []string{dig("I")})))
	a := w.store(nil).Artifact(dig("X"))
	if a.Step.Tier != "T0" {
		t.Fatalf("step %s", a.Step)
	}
	has(t, a.Render(), "re-derived by its author only")
	wantExit(t, a, 0, "")
	w.sign("BR", "BB", "reproduced", obj("of", w.ids["A1"], "result", "match", "content", contentOf("X"),
		"provenance", obj("workflow", dig("W"), "inputs", []string{dig("I")})))
	hasNot(t, w.store(nil).Artifact(dig("X")).Render(), "re-derived by its author only")
}

// TestRunnerSaysIsShownNeverGraded: A5. A runner's `reproduced` result and environment are shown on its run,
// attributed, with the reader's trust stated as not configured; the grade is the reader's own. (a) `bytes`:
// the runner signs `match` for different bytes → its run is diverged, explain names the disagreement, X keeps
// X's own verdict is diverged too (its only partner disagreed). (b) `protocol` with no comparator runner: the runner's `match` is shown; the reader made no
// comparison, so unchecked and exit 3, and no disagreement is claimed.
func TestRunnerSaysIsShownNeverGraded(t *testing.T) {
	env := obj("image_digest", dig("img"), "platform", "linux/amd64")
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X"})
	w.sign("BR", "BB", "reproduced", obj("of", w.ids["A1"], "result", "match", "content", contentOf("Y"),
		"provenance", obj("workflow", dig("W"), "inputs", []string{dig("I")}, "environment", env)))
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		out := a.Render()
		has(t, out, "runner says: match")
		has(t, out, `environment (runner's record): {"image_digest":"`+dig("img")+`","platform":"linux/amd64"}`)
		has(t, out, "your trust in this key: not configured")
		has(t, out, `signed "match"; this reader's comparison: "diverged" (shown, never graded`)
		if a.Step.Why != DivergedToken {
			t.Fatalf("step %s", a.Step)
		}
		wantExit(t, a, 1, "diverged")
	})

	w2 := groupWorld(t, "protocol", "K", map[string]string{"A": "X"})
	w2.sign("BR", "BB", "reproduced", obj("of", w2.ids["A1"], "result", "match", "content", contentOf("Y"),
		"provenance", obj("workflow", dig("W"), "inputs", []string{dig("I")})))
	a := w2.store(nil).Artifact(dig("X"))
	out := a.Render()
	has(t, out, "runner says: match")
	hasNot(t, out, "this reader's comparison")
	if a.Step.Why != UncheckedToken {
		t.Fatalf("step %s", a.Step)
	}
	wantExit(t, a, 3, "derivation: unchecked")

	// an agreeing runner: shown, no disagreement line
	w3 := groupWorld(t, "bytes", "", map[string]string{"A": "X"})
	w3.sign("BR", "BB", "reproduced", obj("of", w3.ids["A1"], "result", "match", "content", contentOf("X"),
		"provenance", obj("workflow", dig("W"), "inputs", []string{dig("I")})))
	out = w3.store(nil).Artifact(dig("X")).Render()
	has(t, out, "runner says: match")
	hasNot(t, out, "this reader's comparison")

	// a runner who signs `diverged` for bytes the reader finds identical: flagged, and X stays T0
	w4 := groupWorld(t, "bytes", "", map[string]string{"A": "X"})
	w4.sign("BR", "BB", "reproduced", obj("of", w4.ids["A1"], "result", "diverged", "content", contentOf("X"),
		"provenance", obj("workflow", dig("W"), "inputs", []string{dig("I")})))
	a = w4.store(nil).Artifact(dig("X"))
	has(t, a.Render(), `signed "diverged"; this reader's comparison: "match"`)
	if a.Step.Tier != "T0" {
		t.Fatalf("step %s", a.Step)
	}
	wantExit(t, a, 0, "")
}

// TestWorkflowModeByAgreement: A7. Two keys hold `authored` on the workflow (an agent published it and a
// maintainer re-signed it) and declare the same mode: the workflow's own fields still show no default
// (authorship contested, C-btc-02), and its groups read the agreed mode, explain saying so. A rival that differs
// in mode, in comparator, or by declaring nothing fails closed (TestWorkflowModeFromItsDefault for the mode).
func TestWorkflowModeByAgreement(t *testing.T) {
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X"})
	w.workflow("Q", "W", "bytes", "")
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		if a.Step.Tier != "T0" {
			t.Fatalf("step %s\n%s", a.Step, a.Render())
		}
		has(t, a.Render(), "all 2 claimants of wf-"+shortDigest(dig("W"))+" declare the same replication and comparator")
		wantExit(t, a, 0, "")
	})
	wf := w.store(nil).Artifact(dig("W"))
	wantAuthorship(t, wf, ContestedAuthorship)
	wantField(t, wf, "replication", FieldNoDefault, "")

	for name, rival := range map[string][2]string{"comparator": {"protocol", "K2"}, "absent": {"", ""}} {
		w := groupWorld(t, "protocol", "K", map[string]string{"A": "X", "BB": "Y"})
		w.workflow("Q", "W", rival[0], rival[1])
		a := w.store(nil, WithComparator(newFakeComparator("X", "Y"))).Artifact(dig("X"))
		if a.Step.Why != UncheckedToken {
			t.Fatalf("%s rival: step %s\n%s", name, a.Step, a.Render())
		}
		has(t, a.Render(), "do not all declare the same replication and comparator")
	}
}

// TestWorkflowModeAmendment: the workflow's author amends `bytes` to `protocol` with a comparator: every group
// under it is read under the new declaration, and explain cites the amendment.
func TestWorkflowModeAmendment(t *testing.T) {
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X"})
	if a := w.store(nil).Artifact(dig("X")); a.Step.Tier != "T0" {
		t.Fatalf("control %s", a.Step)
	}
	w.workflow("WA", "W", "protocol", "K")
	a := w.store(nil).Artifact(dig("X"))
	if a.Step.Why != IdenticalProto {
		t.Fatalf("after amendment: %s\n%s", a.Step, a.Render())
	}
	has(t, a.Render(), "the workflow's author amended its replication or comparator")
}

// forkAt rewinds key n's head to the line it had at the fork point, so the next line is a sibling branch.
func (w *world) forkAt(n, head string, seq int64) { w.head[n], w.seq[n] = head, seq }

// signMerge signs an authored (or describes) by n after its current head that names merge in `merges`.
func (w *world) signMerge(name, n, kind string, body *canon.Object, merge ...string) string {
	k := w.key(n)
	s := w.seq[n]
	line, id := wire.Sign(wire.Draft{Kind: kind, Seq: s, Prev: w.head[n], Merges: merge, TS: fmt.Sprintf("2026-10-16T03:%02d:%02dZ", s/60%60, s%60), Body: body}, k)
	w.head[n], w.seq[n] = id, s+1
	w.lines = append(w.lines, line)
	w.ids[name] = id
	w.by[id] = n
	return id
}

// TestForkedAuthor: A3. A forks its log. On X both branches amend (CC0 vs CC-BY): licence contested, and explain
// names the fork and the fix. Y is amended on one branch only and Z is new on one branch: both resolve normally,
// so nothing is frozen at the fork. A merge by a `describes` leaves X's licence contested; a merge by an
// `authored` on X amends both branches and settles it.
func TestForkedAuthor(t *testing.T) {
	build := func() (*world, string) {
		w := newWorld(t)
		w.authored("X0", "A", "X", "licence", "MIT")
		w.authored("Y0", "A", "Y", "licence", "MIT")
		head, seq := w.head["A"], w.seq["A"]
		w.authored("X1", "A", "X", "licence", "CC0-1.0")
		w.authored("Z1", "A", "Z", "licence", "MIT")
		tip := w.head["A"]
		w.forkAt("A", head, seq)
		w.authored("X2", "A", "X", "licence", "CC-BY-4.0")
		w.authored("Y2", "A", "Y", "licence", "CC0-1.0")
		return w, tip
	}
	w, _ := build()
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, SoleAuthor)
		wantField(t, a, "licence", FieldContested, "")
		has(t, a.Render(), "holds 2 current authored on this blob on separate branches of its log")
		has(t, a.Render(), "a merge that is not an authored amends nothing")
		wantExit(t, a, 3, "field licence: contested")
	})
	r := w.store(nil)
	wantField(t, r.Artifact(dig("Y")), "licence", FieldDefault, `"CC0-1.0"`)
	wantField(t, r.Artifact(dig("Z")), "licence", FieldDefault, `"MIT"`)
	hasNot(t, r.Artifact(dig("Y")).Render(), "separate branches")

	w, tip := build()
	w.signMerge("M", "A", "describes", obj("about", obj("content", dig("X")), "note", "merge"), tip)
	a := w.store(nil).Artifact(dig("X"))
	wantField(t, a, "licence", FieldContested, "")

	w, tip = build()
	w.signMerge("M", "A", "authored", obj("content", contentOf("X"), "type", "dataset", "licence", "CC0-1.0"), tip)
	a = w.store(nil).Artifact(dig("X"))
	wantField(t, a, "licence", FieldDefault, `"CC0-1.0"`)
	hasNot(t, a.Render(), "separate branches")
	wantExit(t, a, 0, "")
}

// TestForkedAuthorTwoProvenances: A forks with a bare authored on X on one branch and one under W on the other,
// and B derives X under W. A's two claims tie (same anchors), so authorship is contested; B's group keeps its
// evidence (A10) and explain names A's fork.
func TestForkedAuthorTwoProvenances(t *testing.T) {
	w := newWorld(t)
	w.workflow("WA", "W", "bytes", "")
	w.authored("A0", "A", "Y")
	head, seq := w.head["A"], w.seq["A"]
	w.authored("A1", "A", "X")
	w.forkAt("A", head, seq)
	w.authored("A2", "A", "X", "prov", []string{"W", "I"})
	w.authored("B1", "BB", "X", "prov", []string{"W", "I"})
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, ContestedAuthorship)
		if a.Step.Tier != "T0" {
			t.Fatalf("step %s\n%s", a.Step, a.Render())
		}
		has(t, a.Render(), "holds 2 current authored on this blob on separate branches")
	})
}

// TestGroupVersusOutsider: A1. A derivation group is one claimant whose bound is the best any member holds.
// (a) A in the group anchored before outsider C: the group is default author, C a later claimant. (b) C anchored
// first: C is default author and the group a later claimant, its evidence still shown (A10). (c) a member who
// joins the group late with no anchor changes neither answer (joining can't lower a group's bound).
func TestGroupVersusOutsider(t *testing.T) {
	for _, c := range []struct {
		name      string
		a, c      string
		late      bool
		groupWins bool
	}{
		{"group first", "btc:100", "btc:150", false, true},
		{"outsider first", "btc:150", "btc:100", false, false},
		{"group first, late joiner", "btc:100", "btc:150", true, true},
		{"outsider first, late joiner", "btc:150", "btc:100", true, false},
	} {
		w := newWorld(t)
		w.workflow("WA", "W", "bytes", "")
		w.authored("A1", "A", "X", "prov", []string{"W", "I"})
		w.anchor("AA", "A", c.a)
		w.authored("B1", "BB", "X", "prov", []string{"W", "I"})
		w.authored("C1", "CC", "X")
		w.anchor("CA", "CC", c.c)
		if c.late {
			w.authored("D1", "DD", "X", "prov", []string{"W", "I"})
		}
		check := func(a *Artifact) {
			wantAuthorship(t, a, Priority)
			if got := a.Default.Provenance != nil; got != c.groupWins {
				t.Fatalf("%s: default %s\n%s", c.name, a.Default.describe(), a.Render())
			}
			if a.Step.Tier != "T0" {
				t.Fatalf("%s: step %s", c.name, a.Step)
			}
		}
		sampledOrderArtifact(t, w, "X", check, WithTimeVerifier(newFakeBitcoin(100, 150)))
	}
}

// TestAmendmentReplacesFields: A2. An amendment is a whole statement, not a patch: a field the amendment omits
// reads undeclared, and the claim keeps the bound of what it amends. An amendment that adds provenance carries
// the earlier bound into the group's unit (P-A2).
func TestAmendmentReplacesFields(t *testing.T) {
	w := newWorld(t)
	w.authored("A1", "A", "X", "licence", "CC0-1.0", "description", "readings")
	w.anchor("AA", "A", "btc:100")
	w.authored("A2", "A", "X", "description", "readings, fixed")
	a := w.store(nil, WithTimeVerifier(newFakeBitcoin(100))).Artifact(dig("X"))
	wantField(t, a, "licence", FieldAbsent, "")
	wantField(t, a, "description", FieldDefault, `"readings, fixed"`)
	if !a.Default.Bound.verified() || a.Default.Bound.Height != 100 {
		t.Fatalf("bound %s", a.Default.Bound)
	}

	w = newWorld(t)
	w.workflow("WA", "W", "bytes", "")
	w.authored("A1", "A", "X")
	w.anchor("AA", "A", "btc:100")
	w.authored("A2", "A", "X", "prov", []string{"W", "I"})
	w.authored("C1", "CC", "X")
	w.anchor("CA", "CC", "btc:150")
	sampledOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, Priority)
		if a.Default.Provenance == nil || a.Default.Bound.Height != 100 {
			t.Fatalf("default %s bound %s\n%s", a.Default.describe(), a.Default.Bound, a.Render())
		}
	}, WithTimeVerifier(newFakeBitcoin(100, 150)))
}
