package conformance

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/research-common/research-commons/internal/canon"
)

// SignedIdentityVectorsPath is the signed rc/2 vectors file of the candidate fixed-root identity profile
// (profile note §9), relative to the repo root. It is the signed counterpart of the unsigned schema vectors.
const SignedIdentityVectorsPath = "docs/fixed-root-identity.signed-vectors.json"

// IdentityVectorKey is one published, test-only key of the signed identity vectors.
type IdentityVectorKey struct {
	Name, Alg, Label string
	Secret           string // hex of sha256(Label): the RFC 8032 seed (ed25519) or the secp256k1 scalar (eip191-secp256k1)
	Signer           string
}

// IdentityPositive is a signed line the production reader must accept: an rc/2 statement, or the rc/1 lines
// around it (the worker's inception and the root's raw key event). JCS (the envelope without sig, which is
// the PAE payload), SignedString (the exact signed bytes), ID and Sig are what a writer reproduces from the key.
type IdentityPositive struct {
	Name, Chain, Alg, RC, Kind, Signer, PayloadType, JCS string
	SignedString                                         string
	Bytes                                                int64
	ID, Sig, Line                                        string
	// EquivalentSigs are the other valid encodings of an EIP-191 Sig (v as 0/1, high s, both); a reader stores
	// the canonical Sig whichever arrives.
	EquivalentSigs []string
	// the production reader's outcome for Line
	Status, Why               string
	ActorIdentity, ActorGrant string
}

// IdentityNegative is a delivered line with the outcome the production reader must give. Of names the positive it
// was derived from; ChangedMembers are the top-level members of the delivered line that differ from that
// positive's line (so the mutation is the one the title says). VerifiedString is the exact byte string the reader
// checks Sig against. SigVerifies says whether Sig is a valid signature by Signer over VerifiedString; Ed25519Step,
// for an Ed25519 Sig that does not verify, is the step ("1".."4") of the pinned rule that refuses it, and
// StockEd25519Accepts records that the standard library's verifier alone would have accepted it. SigOver, when
// present, is the string Sig IS a genuine signature over (so the mutation touched the bytes or domain, not the
// signature). Result is "refused" (Class, Reason, DetailHas) or "read" (Status, Why, ActorRead).
type IdentityNegative struct {
	Name, Chain, Title, Of, Alg, Signer, Source string
	Delivered, VerifiedString, SigOver          string
	Sig                                         string
	SigVerifies, StockEd25519Accepts            bool
	ChangedMembers                              []string
	Ed25519Step                                 string
	Result                                      string
	Class, Reason, DetailHas                    string
	Status, Why                                 string
	ActorRead                                   bool
}

// SignedIdentityVectors is the parsed signed-vectors file.
type SignedIdentityVectors struct {
	Keys     []IdentityVectorKey
	Positive []IdentityPositive
	Negative []IdentityNegative
}

// LoadSignedIdentityVectors reads the signed identity vectors file with the module's strict parser.
func LoadSignedIdentityVectors() (*SignedIdentityVectors, error) {
	root, err := RepoRoot()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(root, SignedIdentityVectorsPath))
	if err != nil {
		return nil, err
	}
	return ParseSignedIdentityVectors(raw)
}

// ParseSignedIdentityVectors parses the bytes of a signed identity vectors file.
func ParseSignedIdentityVectors(raw []byte) (*SignedIdentityVectors, error) {
	v, err := canon.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("signed identity vectors: %w", err)
	}
	d := &decoder{}
	top := d.obj(v)
	out := &SignedIdentityVectors{}
	for _, e := range d.arr(d.get(top, "keys")) {
		o := d.obj(e)
		out.Keys = append(out.Keys, IdentityVectorKey{Name: d.str(o, "name"), Alg: d.str(o, "alg"),
			Label: d.str(o, "label"), Secret: d.str(o, "secret"), Signer: d.str(o, "signer")})
	}
	for _, e := range d.arr(d.get(top, "positive")) {
		o := d.obj(e)
		x := IdentityPositive{Name: d.str(o, "name"), Chain: d.str(o, "chain"), Alg: d.str(o, "alg"), RC: d.str(o, "rc"),
			Kind: d.str(o, "kind"), Signer: d.str(o, "signer"), PayloadType: d.str(o, "payload_type"), JCS: d.str(o, "jcs"),
			SignedString: d.str(o, "signed_string"), Bytes: d.int(o, "bytes"), ID: d.str(o, "id"), Sig: d.str(o, "sig"),
			Line: d.str(o, "line"), EquivalentSigs: d.strs(o, "equivalent_sigs")}
		ex := d.obj(d.get(o, "expect"))
		x.Status, x.Why = d.str(ex, "status"), d.str(ex, "why")
		if av, ok := ex.Get("actor"); ok {
			a := d.obj(av)
			x.ActorIdentity, x.ActorGrant = d.str(a, "identity"), d.str(a, "grant")
		}
		out.Positive = append(out.Positive, x)
	}
	for _, e := range d.arr(d.get(top, "negative")) {
		o := d.obj(e)
		x := IdentityNegative{Name: d.str(o, "name"), Chain: d.str(o, "chain"), Title: d.str(o, "title"), Of: d.str(o, "of"),
			Alg: d.str(o, "alg"), Signer: d.str(o, "signer"), Source: d.str(o, "source"), Delivered: d.str(o, "delivered"),
			VerifiedString: d.str(o, "verified_string"), SigOver: d.str(o, "sig_over"), Sig: d.str(o, "sig"),
			ChangedMembers: d.strs(o, "changed_members"), Ed25519Step: d.str(o, "ed25519_step")}
		x.SigVerifies, x.StockEd25519Accepts = d.boolean(o, "sig_verifies"), d.boolean(o, "stock_ed25519_accepts")
		oc := d.obj(d.get(o, "outcome"))
		x.Result = d.str(oc, "result")
		switch x.Result {
		case "refused":
			x.Class, x.Reason, x.DetailHas = d.str(oc, "class"), d.str(oc, "reason"), d.str(oc, "detail_has")
		case "read":
			x.Status, x.Why = d.str(oc, "status"), d.str(oc, "why")
			x.ActorRead = d.boolean(oc, "actor_read")
		default:
			d.fail("negative %q: outcome.result %q", x.Name, x.Result)
		}
		out.Negative = append(out.Negative, x)
	}
	if d.err != nil {
		return nil, fmt.Errorf("signed identity vectors: %w", d.err)
	}
	return out, nil
}

func (d *decoder) boolean(o *canon.Object, k string) bool {
	v, ok := o.Get(k)
	if !ok {
		return false
	}
	b, ok := v.(canon.Bool)
	if !ok {
		d.fail("%q is not a boolean", k)
	}
	return bool(b)
}

func (d *decoder) strs(o *canon.Object, k string) []string {
	v, ok := o.Get(k)
	if !ok {
		return nil
	}
	a, ok := v.(canon.Array)
	if !ok {
		d.fail("%q is not an array", k)
		return nil
	}
	var out []string
	for _, e := range a {
		x, ok := e.(canon.String)
		if !ok {
			d.fail("%q has a non-string entry", k)
			continue
		}
		out = append(out, string(x))
	}
	return out
}
