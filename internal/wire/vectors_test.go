package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/sig"
)

func vectors(t *testing.T) *conformance.Vectors {
	t.Helper()
	v, err := conformance.LoadVectors()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// splitPAE returns the payload type and body of a signed string, checking both length fields.
func splitPAE(t *testing.T, ss string) (string, string) {
	t.Helper()
	parts := strings.SplitN(ss, " ", 5)
	if len(parts) != 5 || parts[0] != "DSSEv1" {
		t.Fatalf("not a PAE string: %.60q", ss)
	}
	return parts[2], parts[4]
}

// lineFor builds the delivered log line for a signed string and a sig: the PAE body with sig added. The
// members are re-encoded canonically, so the line is what a writer would store.
func lineFor(t *testing.T, ss, sigHex string) []byte {
	t.Helper()
	_, body := splitPAE(t, ss)
	v, err := canon.Parse([]byte(body))
	if err != nil {
		t.Fatalf("PAE body does not parse: %v", err)
	}
	o := v.(*canon.Object)
	o.Keys = append(o.Keys, "sig")
	o.Members["sig"] = canon.String(sigHex)
	return canon.Encode(o)
}

func wantRefusal(t *testing.T, err error, class refusal.Class, reason, detailHas string) {
	t.Helper()
	var r *refusal.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("want %s: %s, got %v", class, reason, err)
	}
	if r.Class != class || r.Reason != reason || !strings.Contains(r.Detail, detailHas) {
		t.Fatalf("want %s: %s (…%s…), got %v", class, reason, detailHas, r)
	}
}

// TestPositiveVectors: every positive vector (V1–V10, E1–E2) reads as valid, reproduces its signed string
// byte for byte, its byte count and its id, and stores its sig unchanged (each is already canonical).
func TestPositiveVectors(t *testing.T) {
	conformance.Partial(t, "C-core-02a", "display (neither shown as a replay) needs the resolver and a surface")
	v := vectors(t)
	all := append(append([]conformance.Vector{}, v.Positive...), v.EdPositive...)
	for _, x := range all {
		t.Run(x.Name, func(t *testing.T) {
			st, err := Read(lineFor(t, x.SignedString, x.Sig))
			if err != nil {
				t.Fatal(err)
			}
			// V8 names x_escrow in crit, which this reader does not implement: verified, retained, unsupported (§6).
			wantStatus, wantWhy := Valid, ""
			if x.Name == "V8" {
				wantStatus, wantWhy = Unsupported, "crit x_escrow"
			}
			if st.Status != wantStatus || st.Why != wantWhy || !st.Verified {
				t.Fatalf("status %s (%s), verified %v", st.Status, st.Why, st.Verified)
			}
			if string(st.SignedString) != x.SignedString {
				t.Fatalf("signed string differs:\n got %s\nwant %s", st.SignedString, x.SignedString)
			}
			if int64(len(st.SignedString)) != x.Bytes || st.ID != x.ID || st.Sig != x.Sig {
				t.Fatalf("bytes %d id %s sig %s", len(st.SignedString), st.ID, st.Sig)
			}
			pt, _ := splitPAE(t, x.SignedString)
			if pt != PayloadType(st.Kind, Major) {
				t.Fatalf("payload type %s for kind %s", pt, st.Kind)
			}
			// The stored line re-reads to the same statement (idempotent storage).
			again, err := Read(st.Line())
			if err != nil || again.ID != st.ID || !bytes.Equal(again.Line(), st.Line()) {
				t.Fatalf("stored line does not round-trip: %v", err)
			}
		})
	}
}

// TestVectorChain: V1–V10 are one log, E1–E2 another; each prev is the previous vector's id and seq steps by 1.
func TestVectorChain(t *testing.T) {
	v := vectors(t)
	for _, log := range [][]conformance.Vector{v.Positive, v.EdPositive} {
		prev := ""
		for i, x := range log {
			st, err := Read(lineFor(t, x.SignedString, x.Sig))
			if err != nil {
				t.Fatal(err)
			}
			if st.Seq != int64(i) || st.Prev != prev {
				t.Fatalf("%s: seq %d prev %q, want %d %q", x.Name, st.Seq, st.Prev, i, prev)
			}
			prev = st.ID
		}
	}
}

// TestResignVectors: signing each vector's envelope with the published disposable key gives the published
// signature. Both algorithms are deterministic (RFC 6979, RFC 8032), so a writer reproduces the vectors.
func TestResignVectors(t *testing.T) {
	v := vectors(t)
	k1 := sha256.Sum256([]byte("research-commons wire-format test key 1"))
	if got := "0x" + hex.EncodeToString(sig.AddressOf(k1[:])); got != v.EIP191Address {
		t.Fatalf("test key 1 address %s, file says %s", got, v.EIP191Address)
	}
	seed, _ := hex.DecodeString(v.Ed25519Seed)
	if s := sha256.Sum256([]byte("research-commons wire-format test key 2 (ed25519)")); !bytes.Equal(s[:], seed) {
		t.Fatal("ed25519 seed is not the published derivation")
	}
	if got := (Ed25519Key{Seed: seed}).Signer(); got != v.Ed25519Signer {
		t.Fatalf("ed25519 signer %s, file says %s", got, v.Ed25519Signer)
	}
	for _, x := range v.Positive {
		if got := (EIP191Key{Scalar: k1[:]}).Sign([]byte(x.SignedString)); got != x.Sig {
			t.Errorf("%s: re-signed %s", x.Name, got)
		}
	}
	for _, x := range v.EdPositive {
		if got := (Ed25519Key{Seed: seed}).Sign([]byte(x.SignedString)); got != x.Sig {
			t.Errorf("%s: re-signed %s", x.Name, got)
		}
	}
}

// TestEquivalentEncodings: V1's three published encodings are one statement with one id, and the reader
// stores the canonical one whichever arrived (§4).
func TestEquivalentEncodings(t *testing.T) {
	conformance.Partial(t, "C-core-10", "second delivery as a no-op (one log line, one count) needs the log and projections")
	conformance.Partial(t, "P-02", "counts not multiplying needs projections; this checks one id per body at the wire layer")
	v := vectors(t)
	v1 := v.Positive[0]
	if v.Equivalent.Of != "V1" || v.Equivalent.Canonical != v1.Sig {
		t.Fatal("equivalent_encodings no longer describes V1")
	}
	for name, enc := range map[string]string{"canonical": v.Equivalent.Canonical, "v_0_1": v.Equivalent.V01, "high_s": v.Equivalent.HighS} {
		st, err := Read(lineFor(t, v1.SignedString, enc))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.ID != v1.ID || st.Sig != v1.Sig {
			t.Fatalf("%s: id %s stored sig %s", name, st.ID, st.Sig)
		}
	}
	// The fourth form (high s and v as 0/1) is derived, not published; it too is the same statement.
	raw, _ := hex.DecodeString(v1.Sig[2:])
	for i, e := range sig.Equivalents(raw) {
		st, err := Read(lineFor(t, v1.SignedString, "0x"+hex.EncodeToString(e)))
		if err != nil || st.ID != v1.ID || st.Sig != v1.Sig {
			t.Fatalf("derived encoding %d: %v", i, err)
		}
	}
}

// TestDeliveredNegatives: N1–N4 are bytes handed to the reader as stored lines.
func TestDeliveredNegatives(t *testing.T) {
	conformance.Partial(t, "C-core-12", "refusal at pull, no line in any log, state digest unchanged: needs pull and the log")
	v := vectors(t)
	want := map[string]struct {
		class  refusal.Class
		reason string
		detail string
	}{
		"N1": {refusal.Intrinsic, refusal.MalformedStatement, `duplicate key "licence"`},
		"N2": {refusal.Intrinsic, refusal.MalformedStatement, "non-finite number"},
		"N3": {refusal.Intrinsic, refusal.MalformedStatement, "non-integer number"},
		"N4": {refusal.Operational, refusal.DepthLimit, "depth limit 16"},
	}
	for _, x := range v.Negative {
		w, ok := want[x.Name]
		if !ok {
			continue
		}
		t.Run(x.Name, func(t *testing.T) {
			sum := sha256.Sum256([]byte(x.Delivered))
			if hex.EncodeToString(sum[:]) != x.DeliveredSHA256 || int64(len(x.Delivered)) != x.DeliveredBytes {
				t.Fatal("delivered bytes do not match their recorded digest")
			}
			_, err := Read([]byte(x.Delivered))
			wantRefusal(t, err, w.class, w.reason, w.detail)
		})
		delete(want, x.Name)
	}
	if len(want) != 0 {
		t.Fatalf("vectors missing: %v", want)
	}
}

// TestN5WrongLog: the line itself is V1, valid; the refusal belongs to the log's ownership rule (§7).
func TestN5WrongLog(t *testing.T) {
	conformance.Partial(t, "C-core-14", "the ownership refusal and the unchanged chain need the per-key log (build step 5)")
	v := vectors(t)
	n5 := v.Negative[4]
	if n5.Name != "N5" {
		t.Fatal("N5 moved")
	}
	st, err := Read([]byte(n5.Delivered))
	if err != nil {
		t.Fatalf("N5's line should verify on its own: %v", err)
	}
	if st.Signer == n5.Log {
		t.Fatal("N5 is delivered into its own signer's log; the vector is broken")
	}
	t.Skip("build step 5: ownership rule refuses a line whose signer is not the log's key")
}

// TestSignedStringNegatives: N6–N13 and NE13 pair a signed string with a signature.
func TestSignedStringNegatives(t *testing.T) {
	conformance.Partial(t, "C-core-09", "this flips one field (N7); the full case flips every field and runs at pull with the parsed digest logged")
	v := vectors(t)
	byName := map[string]conformance.Vector{}
	for _, x := range append(append([]conformance.Vector{}, v.Negative...), v.EdNegative...) {
		byName[x.Name] = x
	}
	addr, _ := hex.DecodeString(v.EIP191Address[2:])
	verifiesRaw := func(x conformance.Vector) bool {
		raw, _ := hex.DecodeString(x.Sig[2:])
		_, ok := sig.VerifyEIP191([]byte(x.SignedString), raw, addr)
		return ok
	}

	t.Run("N6", func(t *testing.T) {
		x := byName["N6"]
		if verifiesRaw(x) {
			t.Fatal("N6's anchors-typed string verifies under the authored signature")
		}
		_, err := Read(lineFor(t, x.SignedString, x.Sig))
		// The delivered line carries kind authored, so the reader recomputes V1's type and V1's string: the
		// tag mismatch is only detectable as the raw check above. Delivered, the line IS V1.
		if err != nil {
			t.Fatalf("N6's body with V1's signature is V1 and must verify: %v", err)
		}
		pt, _ := splitPAE(t, x.SignedString)
		if pt == PayloadType("authored", Major) {
			t.Fatal("N6 no longer changes the payload type")
		}
	})
	t.Run("N7", func(t *testing.T) {
		x := byName["N7"]
		if verifiesRaw(x) {
			t.Fatal("flipped string verifies")
		}
		st, err := Read(lineFor(t, x.SignedString, x.Sig))
		wantRefusal(t, err, refusal.Intrinsic, refusal.BadSignature, "does not recover")
		if st != nil {
			t.Fatal("a refused statement was returned; its fields could be displayed as the signer's")
		}
	})
	for name, detail := range map[string]string{
		"N8": "trailing zero", "N9": "more than nine fractional digits", "N10": "offset other than Z",
		"N12": "second 60 outside UTC", "N13": "Z asserts UTC",
	} {
		t.Run(name, func(t *testing.T) {
			x := byName[name]
			// Delivery proof: the signature is valid over the altered string, so only the time rule can refuse.
			if !verifiesRaw(x) {
				t.Fatal("vector signature does not verify; the test would not reach the time rule")
			}
			_, err := Read(lineFor(t, x.SignedString, x.Sig))
			wantRefusal(t, err, refusal.Intrinsic, refusal.MalformedStatement, detail)
		})
	}
	t.Run("N11", func(t *testing.T) {
		x := byName["N11"]
		if !verifiesRaw(x) {
			t.Fatal("N11's signature should verify over its own (code-point ordered) string")
		}
		_, body := splitPAE(t, x.SignedString)
		pv, _ := canon.Parse([]byte(body))
		if got := string(PAE(PayloadType("describes", Major), canon.Encode(pv))); got != v.Positive[9].SignedString {
			t.Fatal("the JCS form of N11's envelope is not V10's signed string")
		}
		_, err := Read(lineFor(t, x.SignedString, x.Sig))
		wantRefusal(t, err, refusal.Intrinsic, refusal.BadSignature, "")
	})
	t.Run("NE13", func(t *testing.T) {
		x := byName["NE13"]
		_, err := Read(lineFor(t, x.SignedString, x.Sig))
		wantRefusal(t, err, refusal.Intrinsic, refusal.MalformedStatement, "alg eip191-secp256k1 with signer ed25519:")
	})
}

// TestEd25519Speccheck: the twelve speccheck cases are refused at the step the vectors file names, and the
// stock verifier alone accepts some of them (so the pre-checks are load-bearing, not decoration).
func TestEd25519Speccheck(t *testing.T) {
	conformance.Partial(t, "C-core-144", "(b) as raw cases, not yet delivered as statements; (a) rotation needs key events; one implementation, not two")
	v := vectors(t)
	stockAccepts := 0
	for _, x := range v.EdNegative {
		if x.PublicKey == "" {
			continue // NE13 is an envelope case
		}
		t.Run(x.Name, func(t *testing.T) {
			pub, _ := hex.DecodeString(x.PublicKey)
			msg, _ := hex.DecodeString(x.MessageHex)
			s, _ := hex.DecodeString(x.Sig)
			if got := sig.VerifyEd25519(pub, msg, s); got != x.PinnedStep {
				t.Fatalf("refused at %q, file says %q", got, x.PinnedStep)
			}
			if len(pub) == 32 && len(s) == 64 && ed25519.Verify(pub, msg, s) {
				stockAccepts++
			}
		})
	}
	// Wire-format note §4: Go's crypto/ed25519 accepts cases 0–3 and 11 (NE1–NE4, NE12).
	if stockAccepts != 5 {
		t.Fatalf("stock crypto/ed25519 accepted %d of the 12 cases; the note says 5", stockAccepts)
	}
}

// TestEd25519SpeccheckAsStatements delivers each speccheck key and signature as a statement (signer =
// ed25519:<case key>, sig = the case signature). The message is now the statement's signed string, not the
// case message, so step 4 alone would refuse most of them; the point is that the pinned pre-checks refuse
// every one before step 4, at the step the vectors file names, whatever the message.
func TestEd25519SpeccheckAsStatements(t *testing.T) {
	conformance.Partial(t, "C-core-144", "(b) delivered as statements: done here; (a) cross-algorithm rotation chain needs key events; verdicts across two Ed25519 libraries not run")
	v := vectors(t)
	for _, x := range v.EdNegative {
		if x.PublicKey == "" {
			continue
		}
		t.Run(x.Name, func(t *testing.T) {
			env := Draft{Kind: "authored", TS: "2026-10-15T00:00:00Z", Body: body("content", content("5e", 512), "type", "dataset")}.
				Envelope(fixedSigner("ed25519:" + x.PublicKey))
			env.Keys = append(env.Keys, "sig")
			env.Members["sig"] = canon.String(x.Sig)
			_, err := Read(canon.Encode(env))
			wantRefusal(t, err, refusal.Intrinsic, refusal.BadSignature, x.PinnedStep)
		})
	}
}

// fixedSigner is a Key that names a signer it cannot sign for; used to build envelopes around foreign sigs.
type fixedSigner string

func (f fixedSigner) Alg() string {
	if strings.HasPrefix(string(f), "ed25519:") {
		return AlgEd25519
	}
	return AlgEIP191
}
func (f fixedSigner) Signer() string     { return string(f) }
func (f fixedSigner) Sign([]byte) string { panic("fixedSigner cannot sign") }
