package sig_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/sig"
	"github.com/research-common/research-commons/internal/wire"
)

// C-core-144 as statements, under two readers.
//
// Reader one is the production reader (wire.Read: pinned Ed25519 verifier on filippo.io/edwards25519 plus the
// standard library's step 4). Reader two is refRead below, written for this test from the wire-format note: it
// parses the line, rebuilds the signed string, applies the envelope's alg/signer rule and verifies Ed25519 with
// refVerifyPure, which is math/big and crypto/sha512 only (no Ed25519 library, no edwards25519 package). EIP-191
// has one implementation in this module (secp256k1 recovery), so reader two calls it: the case asks for two
// Ed25519 libraries, and the secp256k1 half is shared by design. Canonical JSON (canon.Encode) and the id hash
// are shared too: they are not what the case varies.

var (
	reRefAddr = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
	reRefEd   = regexp.MustCompile(`^ed25519:[0-9a-f]{64}$`)
	reRefSigE = regexp.MustCompile(`^0x[0-9a-f]{130}$`)
	reRefSigD = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

// refRead is reader two: the verdict on one stored line, "valid", or the refusal reason it would give, and the
// statement id it computed.
func refRead(line []byte) (verdict, id string) {
	v, err := canon.Parse(line)
	if err != nil {
		return refusal.MalformedStatement, ""
	}
	full, ok := v.(*canon.Object)
	if !ok {
		return refusal.MalformedStatement, ""
	}
	env := &canon.Object{Members: map[string]canon.Value{}}
	for _, k := range full.Keys {
		if k != "sig" {
			env.Keys = append(env.Keys, k)
			env.Members[k] = full.Members[k]
		}
	}
	str := func(k string) string { s, _ := env.Members[k].(canon.String); return string(s) }
	sg, _ := full.Members["sig"].(canon.String)
	if str("rc") != "rc/1" {
		return "other major", ""
	}
	signer, alg := str("signer"), str("alg")
	isAddr, isEd := reRefAddr.MatchString(signer), reRefEd.MatchString(signer)
	switch {
	case !isAddr && !isEd:
		return refusal.MalformedStatement, ""
	case alg == wire.AlgEIP191 && !isAddr, alg == wire.AlgEd25519 && !isEd:
		return refusal.MalformedStatement, ""
	}
	pt := "application/vnd.research-commons." + str("kind") + ".v1+json"
	body := canon.Encode(env)
	ss := []byte("DSSEv1 " + strconv.Itoa(len(pt)) + " " + pt + " " + strconv.Itoa(len(body)) + " " + string(body))
	h := sha256.Sum256(ss)
	id = hex.EncodeToString(h[:])
	switch alg {
	case wire.AlgEd25519:
		if !reRefSigD.MatchString(string(sg)) {
			return refusal.MalformedStatement, ""
		}
		pub, _ := hex.DecodeString(strings.TrimPrefix(signer, "ed25519:"))
		raw, _ := hex.DecodeString(string(sg))
		if refVerifyPure(pub, ss, raw, true) != "" {
			return refusal.BadSignature, ""
		}
	case wire.AlgEIP191:
		if !reRefSigE.MatchString(string(sg)) {
			return refusal.MalformedStatement, ""
		}
		raw, _ := hex.DecodeString(string(sg)[2:])
		addr, _ := hex.DecodeString(signer[2:])
		if _, ok := sig.VerifyEIP191(ss, raw, addr); !ok {
			return refusal.BadSignature, ""
		}
	default:
		return "unsupported", id
	}
	return "valid", id
}

// prodRead is reader one's verdict in the same words.
func prodRead(line []byte) (verdict, id string) {
	st, err := wire.Read(line)
	if err != nil {
		if r, ok := err.(*refusal.Refusal); ok {
			return r.Reason, ""
		}
		return err.Error(), ""
	}
	if !st.Verified {
		return "unverified", st.ID
	}
	return "valid", st.ID
}

// fixedSigKey is a key whose signer and alg are as given and whose Sign returns a fixed value: how a statement
// is delivered under a public key whose private half nobody holds, with a signature chosen by the test. It
// records the signed string it was asked to sign.
type fixedSigKey struct {
	alg, signer, sg string
	last            *[]byte
}

func (k fixedSigKey) Alg() string    { return k.alg }
func (k fixedSigKey) Signer() string { return k.signer }
func (k fixedSigKey) Sign(ss []byte) string {
	*k.last = append([]byte{}, ss...)
	return k.sg
}

func cobj(kv ...any) *canon.Object {
	o := &canon.Object{Members: map[string]canon.Value{}}
	for i := 0; i < len(kv); i += 2 {
		k := kv[i].(string)
		o.Keys = append(o.Keys, k)
		switch x := kv[i+1].(type) {
		case string:
			o.Members[k] = canon.String(x)
		case int:
			o.Members[k] = canon.Int(x)
		case canon.Value:
			o.Members[k] = x
		}
	}
	return o
}

func authoredBody(note string) *canon.Object {
	c := cobj("digest", "sha256:"+strings.Repeat("ab", 32), "size", 10)
	return cobj("content", c, "type", "dataset", "description", note)
}

func draft(seq int64, prev, note string) wire.Draft {
	return wire.Draft{Kind: "authored", Seq: seq, Prev: prev, TS: "2026-10-16T01:00:00Z", Body: authoredBody(note)}
}

// TestStatementsTwoImplementations: C-core-144 (a), (b) and (c) delivered as statements, verdicts compared
// between the production reader and reader two.
func TestStatementsTwoImplementations(t *testing.T) {
	conformance.Covers(t, "C-core-144")
	same := func(name string, line []byte, want string) string {
		t.Helper()
		pv, pid := prodRead(line)
		rv, rid := refRead(line)
		if pv != rv || pid != rid {
			t.Fatalf("%s: production says %q (id %s), the second implementation says %q (id %s)", name, pv, pid, rv, rid)
		}
		if pv != want {
			t.Fatalf("%s: both implementations say %q, want %q", name, pv, want)
		}
		return pid
	}

	// (a) an authored by an Ed25519 key, a rotate_key by that key to a secp256k1 key, an authored by the successor
	oldSeed := sha256.Sum256([]byte("c-core-144 old ed25519"))
	succScalar := sha256.Sum256([]byte("c-core-144 successor secp256k1"))
	oldK, succK := wire.Ed25519Key{Seed: oldSeed[:]}, wire.EIP191Key{Scalar: succScalar[:]}
	a0, _ := wire.Sign(draft(0, "", "first"), oldK)
	id0 := same("(a) authored by the Ed25519 key", a0, "valid")
	r1, _ := wire.Sign(wire.Draft{Kind: "rotate_key", Seq: 1, Prev: id0, TS: "2026-10-16T01:01:00Z", Body: cobj("successor", succK.Signer())}, oldK)
	id1 := same("(a) rotate_key to the secp256k1 key", r1, "valid")
	b0, _ := wire.Sign(draft(0, "", "successor"), succK)
	same("(a) authored by the successor", b0, "valid")
	// the rotation chains across algorithms: the production log places both logs' lines and reports the succession;
	// reader two's own reading of the rotation names the same successor, and its prev is the first line's id
	s := keylog.NewStore()
	for _, x := range []struct {
		k    wire.Key
		line []byte
	}{{oldK, a0}, {oldK, r1}, {succK, b0}} {
		if _, err := s.Log(x.k.Signer()).Add(x.line); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []wire.Key{oldK, succK} {
		for _, ln := range s.Log(k.Signer()).View().Lines {
			if ln.State != keylog.Chained {
				t.Fatalf("%s: a line did not chain", k.Alg())
			}
		}
	}
	got := s.Successions()
	if len(got) != 1 || got[0] != (keylog.Succession{From: oldK.Signer(), To: succK.Signer(), Event: id1}) {
		t.Fatalf("succession %+v", got)
	}
	rv, _ := canon.Parse(r1)
	rb := rv.(*canon.Object).Members["body"].(*canon.Object)
	if rb.Members["successor"] != canon.String(succK.Signer()) || rv.(*canon.Object).Members["prev"] != canon.String(id0) {
		t.Fatal("reader two reads a different rotation")
	}

	// (b) the twelve published edge cases delivered as statements by keys that would otherwise verify. A statement's
	// signed string is not the vector's 32-byte message, so each case's public key and signature are kept and the
	// statement body carries a nonce, ground until the standard library's own verifier accepts the signature over
	// the statement's signed string. Every ground statement is one a library-only reader would hold valid; both
	// readers must refuse it `bad signature`.
	v, err := conformance.LoadVectors()
	if err != nil {
		t.Fatal(err)
	}
	var last []byte
	ground, total := 0, 0
	var groundNames []string
	for _, x := range v.EdNegative {
		if x.PublicKey == "" {
			continue // NE13: (c)
		}
		total++
		pub, raw := unhex(t, x.PublicKey), unhex(t, x.Sig)
		k := fixedSigKey{alg: wire.AlgEd25519, signer: "ed25519:" + x.PublicKey, sg: x.Sig, last: &last}
		found := false
		for n := 0; n < 3000 && !found; n++ {
			line, _ := wire.Sign(draft(0, "", "nonce "+strconv.Itoa(n)), k)
			if len(raw) == 64 && ed25519.Verify(ed25519.PublicKey(pub), last, raw) {
				found = true
				ground++
				groundNames = append(groundNames, x.Name)
				same("(b) "+x.Name+" as a statement the stock verifier accepts", line, refusal.BadSignature)
			}
		}
		if !found {
			// no statement the stock verifier accepts exists for this case (or none was found): it is still delivered,
			// and still refused by both
			line, _ := wire.Sign(draft(0, "", "plain"), k)
			same("(b) "+x.Name+" as a statement", line, refusal.BadSignature)
		}
	}
	if total != 12 {
		t.Fatalf("%d edge cases, want 12", total)
	}
	// the boundary: the pre-checks refused something the library alone would have held valid (cf.
	// TestEd25519Speccheck, which counts the stock verifier's acceptances on the vectors' own messages)
	if ground == 0 {
		t.Fatal("no edge case was delivered as a statement the stock verifier accepts: the test did not reach the pre-checks")
	}
	t.Logf("(b): %d of %d edge cases delivered as statements the standard library accepts (%s); the rest delivered as given", ground, total, strings.Join(groundNames, ", "))

	// (c) a statement whose alg names one algorithm and whose signer is the other's form: validly signed by the
	// key the signer names, refused malformed by both readers, in both directions
	edSigner, eipSigner := oldK.Signer(), succK.Signer()
	for _, c := range []struct{ name, alg, signer string }{
		{"alg eip191-secp256k1, ed25519 signer", wire.AlgEIP191, edSigner},
		{"alg ed25519, 0x signer", wire.AlgEd25519, eipSigner},
	} {
		var ss []byte
		line, _ := wire.Sign(draft(0, "", "mismatch"), fixedSigKey{alg: c.alg, signer: c.signer, sg: "", last: &ss})
		// the signature is in the declared alg's form, made by a real key of that algorithm: a reader that skipped
		// the envelope rule would go on to verify it and say `bad signature`, not `malformed statement`
		real := wire.Key(oldK)
		if c.alg == wire.AlgEIP191 {
			real = succK
		}
		o, _ := canon.Parse(line)
		obj := o.(*canon.Object)
		obj.Members["sig"] = canon.String(real.Sign(ss))
		same("(c) "+c.name, canon.Encode(obj), refusal.MalformedStatement)
	}
}
