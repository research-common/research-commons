package wire

import (
	"bytes"
	"os"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// rc/1 differential: on every published vector and every delivered negative, the identity reader agrees with the
// unchanged reader whenever the unchanged reader accepts (same id, status, why, line, signer, links), never sets
// Actor, and refuses everything the unchanged reader refuses except a verified-signature body failure, which it
// retains as Invalid.
func TestIdentityReaderMatchesReadOnRC1(t *testing.T) {
	v := vectors(t)
	ir := NewIdentityReader()
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
	for i, line := range lines {
		old, oerr := Read(line)
		got, gerr := ir.Read(line)
		switch {
		case oerr == nil:
			if gerr != nil {
				t.Fatalf("%d: identity reader refused a line Read accepts: %v", i, gerr)
			}
			if got.ID != old.ID || got.Status != old.Status || got.Why != old.Why || got.Verified != old.Verified ||
				!bytes.Equal(got.Line(), old.Line()) || got.Signer != old.Signer || got.Prev != old.Prev || got.Actor != nil {
				t.Fatalf("%d: differs from Read:\n old %+v\n new %+v", i, old, got)
			}
		case gerr == nil:
			if got.Status != Invalid || !got.Verified {
				t.Fatalf("%d: Read refused (%v) but identity reader holds %s verified=%v", i, oerr, got.Status, got.Verified)
			}
		}
	}
}

// Candidate differential: every profile draft vector is re-signed with a real synthetic key (signer/alg replaced
// so the signature verifies) and read by the production identity reader. A vector the candidate schema accepts
// must read Valid or Unsupported (the slice does not implement typed resources/tasks); a rejected draft must never
// read Valid. This binds the production reader to the profile's independently written schema harness.
func TestIdentityReaderAgreesWithCandidateVectors(t *testing.T) {
	schema := frLoad(t, "fixed-root-identity.schema.json")
	b, err := os.ReadFile("../../docs/fixed-root-identity.vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	suite, err := canon.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	ir := NewIdentityReader()
	keys := map[string]Key{AlgEd25519: Ed25519Key{Seed: bytes.Repeat([]byte{51}, 32)}, AlgEIP191: EIP191Key{Scalar: bytes.Repeat([]byte{52}, 32)}}
	checked := 0
	for _, cv := range suite.(*canon.Object).Members["cases"].(canon.Array) {
		c := cv.(*canon.Object)
		name := string(c.Members["name"].(canon.String))
		if string(c.Members["mode"].(canon.String)) != "draft" {
			continue
		}
		env, ok := c.Members["value"].(*canon.Object)
		if !ok {
			continue // raw canonicalization vectors: covered by canon.Parse tests
		}
		accept := bool(c.Members["accept"].(canon.Bool))
		if name == "wrong-algorithm-key-prefix" {
			continue // its defect IS the signer/alg pairing that re-signing replaces; covered by linkageEnvelope refusal
		}
		t.Run(name, func(t *testing.T) {
			alg := AlgEd25519
			if a, ok := env.Members["alg"].(canon.String); ok && string(a) == AlgEIP191 {
				alg = AlgEIP191
			}
			k := keys[alg]
			e := setField(setField(env, "signer", canon.String(k.Signer())), "alg", canon.String(alg))
			if d, ok := e.Members["body"].(*canon.Object); ok {
				// The vectors' illustrative delegate keys may equal no signer; keep self-grant cases self-grants.
				if dl, ok := d.Members["delegate"].(*canon.Object); ok {
					if sk, ok := env.Members["signer"].(canon.String); ok && dl.Members["key"] == sk {
						e = setField(e, "body", setField(d, "delegate", setField(dl, "key", canon.String(k.Signer()))))
					}
				}
			}
			kind, _ := e.Members["kind"].(canon.String)
			major := 2
			if rc, _ := e.Members["rc"].(canon.String); rc == "rc/1" {
				major = 1
			}
			line := canon.Encode(setField(e, "sig", canon.String(k.Sign(PAE(PayloadType(string(kind), major), canon.Encode(e))))))
			_, serr := frValidate(schema, line, true)
			st, rerr := ir.Read(line)
			checked++
			if accept && serr != nil {
				t.Skipf("re-signing changed the candidate verdict (%v); not a reader differential", serr)
			}
			switch {
			case rerr != nil:
				if accept {
					t.Fatalf("accepted vector refused: %v", rerr)
				}
			case accept && st.Status != Valid && st.Status != Unsupported:
				t.Fatalf("accepted vector read %s (%s)", st.Status, st.Why)
			case !accept && major == 2 && candidateNotImplemented[string(kind)]:
				if st.Status != Unsupported {
					t.Fatalf("rejected unimplemented-kind vector read %s (%s)", st.Status, st.Why)
				}
			case !accept && major == 2:
				if st.Status != Invalid || !st.Verified {
					t.Fatalf("rejected vector read %s verified=%v (%s), want verified invalid", st.Status, st.Verified, st.Why)
				}
			case !accept:
				if st.Status == Valid {
					t.Fatalf("rejected rc/1 vector read Valid")
				}
			}
		})
	}
	if checked < 60 {
		t.Fatalf("only %d vectors exercised", checked)
	}
}
