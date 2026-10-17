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
		if len(a.Units) != 2 || a.Default.Claims[0].Signer != w.signer("A") {
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
