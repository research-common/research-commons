package wire

import (
	"bytes"
	"errors"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
)

// sameRead reports where two reads of one line differ: refusal (class, reason, detail) or the statement as a
// reader holds it (id, status, why, verified, line, links, actor).
func sameRead(a *Statement, aerr error, b *Statement, berr error) string {
	if (aerr == nil) != (berr == nil) {
		return "one refused, the other did not"
	}
	if aerr != nil {
		var ra, rb *refusal.Refusal
		if errors.As(aerr, &ra) != errors.As(berr, &rb) {
			return "refusal types differ"
		}
		if ra != nil && (ra.Class != rb.Class || ra.Reason != rb.Reason || ra.Detail != rb.Detail) {
			return "refusals differ: " + ra.Error() + " vs " + rb.Error()
		}
		if ra == nil && aerr.Error() != berr.Error() {
			return "errors differ"
		}
		return ""
	}
	switch {
	case a.ID != b.ID, a.Status != b.Status, a.Why != b.Why, a.Verified != b.Verified, a.RC != b.RC, a.Kind != b.Kind,
		a.Signer != b.Signer, a.Seq != b.Seq, a.Prev != b.Prev, a.Sig != b.Sig, !bytes.Equal(a.Line(), b.Line()),
		!bytes.Equal(a.SignedString, b.SignedString), len(a.Merges) != len(b.Merges), (a.Actor == nil) != (b.Actor == nil),
		len(a.References()) != len(b.References()), len(a.Unpinned) != len(b.Unpinned):
		return "statements differ"
	}
	return ""
}

// TestDualReaderRC1IsRead: on the whole rc/1 wire-format vector corpus (every positive, every delivered negative,
// both algorithms) the dual reader gives exactly what Read gives: the same refusal, or the same statement. The
// identity reader alone does not (it holds a verified bad body as Invalid), which is why rc/1 goes through Read.
func TestDualReaderRC1IsRead(t *testing.T) {
	conformance.Partial(t, "C-id-01", "wire half: the dual reader reads every rc/1 wire-format vector exactly as Read (same refusal or the same id, status, why, links); the keylog and resolver halves are in internal/resolve")
	v := vectors(t)
	dr := NewDualReader()
	var lines [][]byte
	for _, set := range [][]conformance.Vector{v.Positive, v.EdPositive, v.Negative, v.EdNegative} {
		for _, x := range set {
			switch {
			case x.Delivered != "":
				lines = append(lines, []byte(x.Delivered))
			case x.SignedString != "" && x.Sig != "":
				lines = append(lines, lineFor(t, x.SignedString, x.Sig))
			}
		}
	}
	if len(lines) < 20 {
		t.Fatalf("only %d vector lines", len(lines))
	}
	// The published corpus has no verified rc/1 line with a bad body; add two (a schema break and a bad ts),
	// signed by a test key, so the dispatch boundary is reached: the identity reader alone holds them Invalid.
	key := Ed25519Key{Seed: bytes.Repeat([]byte{49}, 32)}
	badBody, _ := Sign(Draft{Kind: "authored", TS: tTS, Body: body("content", 7)}, key)
	badTS, _ := Sign(Draft{Kind: "authored", TS: "yesterday", Body: minimal("authored")}, key)
	lines = append(lines, badBody, badTS)
	refused, invalidUnderIdentity := 0, 0
	for i, line := range lines {
		old, oerr := Read(line)
		got, gerr := dr.Read(line)
		if d := sameRead(old, oerr, got, gerr); d != "" {
			t.Fatalf("vector line %d: %s\n%s", i, d, line)
		}
		if oerr != nil {
			refused++
			if st, err := NewIdentityReader().Read(line); err == nil && st.Status == Invalid {
				invalidUnderIdentity++
			}
		}
	}
	// the mutation reached the boundary: some refused lines are ones the identity reader alone would have held
	if refused == 0 || invalidUnderIdentity == 0 {
		t.Fatalf("corpus does not exercise the dispatch: %d refused, %d held Invalid by the identity reader alone", refused, invalidUnderIdentity)
	}
}

// TestDualReaderRC2IsIdentityReader: every signed rc/2 vector (positive and negative, both algorithms) reads under
// the dual reader exactly as under the identity reader, actor included; its rc/1 lines exactly as under Read.
func TestDualReaderRC2IsIdentityReader(t *testing.T) {
	conformance.Partial(t, "C-id-36", "the dual reader on the signed rc/2 vectors: each rc/2 line read as the identity reader reads it (verified, actor read), each rc/1 line as Read; the unchanged reader keeps retaining rc/2 unverified")
	v := ivLoad(t)
	dr := NewDualReader()
	n2 := 0
	var lines []string
	for _, x := range v.Positive {
		lines = append(lines, x.Line)
	}
	for _, x := range v.Negative {
		lines = append(lines, x.Delivered)
	}
	for i, l := range lines {
		line := []byte(l)
		got, gerr := dr.Read(line)
		var want *Statement
		var werr error
		if candidateMajorLine(line) {
			n2++
			want, werr = NewIdentityReader().Read(line)
		} else {
			want, werr = Read(line)
		}
		if d := sameRead(want, werr, got, gerr); d != "" {
			t.Fatalf("signed vector line %d: %s", i, d)
		}
		if gerr == nil && got.Actor != nil && (want.Actor.Identity != got.Actor.Identity || want.Actor.Grant != got.Actor.Grant) {
			t.Fatalf("signed vector line %d: actor differs", i)
		}
	}
	if n2 < 10 {
		t.Fatalf("only %d rc/2 lines", n2)
	}
	// and the unchanged reader still retains every positive rc/2 line unverified
	for _, x := range v.Positive {
		if x.RC != "rc/2" {
			continue
		}
		if st, err := Read([]byte(x.Line)); err != nil || st.Verified || st.Status != Unsupported {
			t.Fatalf("%s: Read changed: %+v %v", x.Name, st, err)
		}
	}
}

// TestDualReaderRC1ActorAndCrit: an rc/1 line carrying an envelope x_actor_v1 is read as Read reads it (Valid, no
// actor: rc/1 is never upgraded); an rc/1 line whose crit names x_identity_v1 is unsupported, as Read says.
func TestDualReaderRC1ActorAndCrit(t *testing.T) {
	key := Ed25519Key{Seed: bytes.Repeat([]byte{47}, 32)}
	dr := NewDualReader()
	sign := func(env *canon.Object) []byte {
		ss := PAE(PayloadType("authored", 1), canon.Encode(env))
		return canon.Encode(setField(env, "sig", canon.String(key.Sign(ss))))
	}
	withActor := sign(setField(Draft{Kind: "authored", TS: tTS, Body: minimal("authored")}.Envelope(key), ActorField, body("identity", tID, "grant", tID2)))
	st, err := dr.Read(withActor)
	if err != nil || st.Status != Valid || !st.Verified || st.Actor != nil {
		t.Fatalf("rc/1 envelope actor: %+v %v", st, err)
	}
	b := setField(minimal("authored"), IdentityCrit, body())
	withCrit := sign(Draft{Kind: "authored", TS: tTS, Crit: []string{IdentityCrit}, Body: b}.Envelope(key))
	st, err = dr.Read(withCrit)
	if err != nil || st.Status != Unsupported || st.Why != "crit "+IdentityCrit || st.Actor != nil {
		t.Fatalf("rc/1 crit %s: %+v %v", IdentityCrit, st, err)
	}
	for _, l := range [][]byte{withActor, withCrit} {
		a, aerr := Read(l)
		g, gerr := dr.Read(l)
		if d := sameRead(a, aerr, g, gerr); d != "" {
			t.Fatal(d)
		}
	}
	// control: the same actor on an rc/2 marker body IS read by the dual reader
	d2 := Draft{RC: "rc/2", Kind: "authored", TS: tTS, Crit: []string{IdentityCrit}, Body: b}.Envelope(key)
	d2 = setField(d2, ActorField, body("identity", tID, "grant", tID2))
	ss := PAE(PayloadType("authored", 2), canon.Encode(d2))
	st, err = dr.Read(canon.Encode(setField(d2, "sig", canon.String(key.Sign(ss)))))
	if err != nil || st.Status != Valid || !st.Verified || st.Actor == nil || st.Actor.Identity != tID {
		t.Fatalf("rc/2 actor control: %+v %v", st, err)
	}
}

// TestDualReaderOtherMajors: rc/3 and later stay Read's unknown-major lines; an unparseable line is Read's refusal.
func TestDualReaderOtherMajors(t *testing.T) {
	key := Ed25519Key{Seed: bytes.Repeat([]byte{48}, 32)}
	line, _ := Sign(Draft{RC: "rc/3", Kind: "authored", TS: tTS, Body: minimal("authored")}, key)
	dr := NewDualReader()
	for _, l := range [][]byte{line, []byte(`{"rc":"rc/2"`), []byte(`[]`), []byte(`{"rc":"rc/0","sig":"x"}`)} {
		a, aerr := Read(l)
		g, gerr := dr.Read(l)
		if d := sameRead(a, aerr, g, gerr); d != "" {
			t.Fatalf("%s: %s", l, d)
		}
	}
	if st, err := dr.Read(line); err != nil || st.Verified || st.Status != Unsupported || st.Why != "rc/3" {
		t.Fatalf("rc/3: %+v %v", st, err)
	}
}
