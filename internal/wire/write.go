package wire

import (
	"encoding/hex"
	"strconv"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/rctime"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/sig"
)

// MaxFutureSkew is the write-time bound of §2: a ts more than 300 seconds ahead of the writer's clock is
// refused (C-core-105).
const MaxFutureSkew = 300 * time.Second

// Key is a signing key for one of the two required algorithms.
type Key interface {
	Alg() string
	// Signer is the envelope signer value: "ed25519:<hex>" or "0x<address>".
	Signer() string
	// Sign returns the sig value for a signed string, in the canonical encoding.
	Sign(signedString []byte) string
}

// Ed25519Key is a key held as its 32-byte RFC 8032 seed (§4.1).
type Ed25519Key struct{ Seed []byte }

func (k Ed25519Key) Alg() string { return AlgEd25519 }
func (k Ed25519Key) Signer() string {
	pub, _ := sig.SignEd25519(k.Seed, nil)
	return "ed25519:" + hex.EncodeToString(pub)
}
func (k Ed25519Key) Sign(m []byte) string {
	_, s := sig.SignEd25519(k.Seed, m)
	return hex.EncodeToString(s)
}

// EIP191Key is a 32-byte secp256k1 scalar.
type EIP191Key struct{ Scalar []byte }

func (k EIP191Key) Alg() string { return AlgEIP191 }
func (k EIP191Key) Signer() string {
	return "0x" + hex.EncodeToString(sig.AddressOf(k.Scalar))
}
func (k EIP191Key) Sign(m []byte) string {
	return "0x" + hex.EncodeToString(sig.SignEIP191(k.Scalar, m))
}

// Draft is an unsigned statement: everything the signer fills in except signer, alg and sig.
type Draft struct {
	RC   string // "" means rc/1
	Kind string
	Seq  int64
	Prev string // "" means null
	// Merges is written as given (a test may need an unsorted list); nil or empty means absent.
	Merges []string
	TS     string
	Crit   []string
	Body   *canon.Object
	// Actor, when set, is written as the signed envelope member x_actor_v1 (identity profile §2.1): the identity
	// and grant this signature acts for. Only an rc/2 draft carries one; IdentityDraft builds it.
	Actor *Actor
}

// Envelope returns the envelope without sig for key k.
func (d Draft) Envelope(k Key) *canon.Object {
	rc := d.RC
	if rc == "" {
		rc = "rc/1"
	}
	var prev canon.Value = canon.Null{}
	if d.Prev != "" {
		prev = canon.String(d.Prev)
	}
	o := &canon.Object{Members: map[string]canon.Value{
		"rc": canon.String(rc), "kind": canon.String(d.Kind), "signer": canon.String(k.Signer()),
		"alg": canon.String(k.Alg()), "seq": canon.Int(d.Seq), "prev": prev, "ts": canon.String(d.TS),
		"body": d.Body,
	}}
	if len(d.Merges) > 0 {
		m := canon.Array{}
		for _, id := range d.Merges {
			m = append(m, canon.String(id))
		}
		o.Members["merges"] = m
	}
	if d.Actor != nil {
		o.Members[ActorField] = &canon.Object{Keys: []string{"grant", "identity"},
			Members: map[string]canon.Value{"grant": canon.String(d.Actor.Grant), "identity": canon.String(d.Actor.Identity)}}
	}
	if len(d.Crit) > 0 {
		c := canon.Array{}
		for _, n := range d.Crit {
			c = append(c, canon.String(n))
		}
		o.Members["crit"] = c
	}
	for k := range o.Members {
		o.Keys = append(o.Keys, k)
	}
	return o
}

// Sign signs d with k and returns the canonical line (envelope with sig, JCS) and the statement id. It does
// not validate the draft: a test that needs a malformed but validly signed statement builds it here.
func Sign(d Draft, k Key) (line []byte, id string) {
	env := d.Envelope(k)
	major := Major
	if m := reRC.FindStringSubmatch(d.RC); m != nil {
		major, _ = strconv.Atoi(m[1]) // the payload type names the draft's own major (wire §2, §6)
	}
	ss := PAE(PayloadType(d.Kind, major), canon.Encode(env))
	env.Keys = append(env.Keys, "sig")
	env.Members["sig"] = canon.String(k.Sign(ss))
	return canon.Encode(env), ID(ss)
}

// Write is the writer's path: it signs d, refuses a ts more than MaxFutureSkew ahead of now, and reads the
// result back through Read, so nothing leaves the writer that a reader would refuse.
func Write(d Draft, k Key, now time.Time) (*Statement, error) {
	ts, err := rctime.ParseUTC(d.TS)
	if err != nil {
		return nil, err
	}
	limit := now.Add(MaxFutureSkew)
	lim := rctime.Time{Sec: limit.Unix(), Nanos: int32(limit.Nanosecond())}
	if rctime.Compare(ts, lim) > 0 {
		// The bound is the writer's own policy (claims-model §10: "a documented default in the writer's policy,
		// printed with the refusal"); no reader refuses such a line (C-core-106 flags it), so it is not intrinsic.
		return nil, &refusal.Refusal{Class: refusal.Policy, Reason: "future timestamp",
			Detail: "ts " + d.TS + " is more than 300 s ahead of the writer's clock (writer policy: max future skew 300 s); scope this statement"}
	}
	line, _ := Sign(d, k)
	if d.RC == "rc/"+strconv.Itoa(CandidateMajor) {
		// the rc/2 half of the production reader: what the writer signs in the identity profile is read back as
		// every reader reads it (a verified line breaking a profile rule reads Invalid; the caller refuses it)
		return NewIdentityReader().Read(line)
	}
	return Read(line)
}

// --- the writer major of each statement (identity profile §2.1) ---------------------------------------------

// identityAdmin are the profile's three administrative kinds: root-signed raw-key statements, always rc/2.
var identityAdmin = map[string]bool{"identity_inception": true, "identity_grant": true, "identity_cut": true}

// WriterMajor is the major this tool's writer signs a statement of kind in. A statement acting for an identity
// (acting: it carries an x_actor_v1) and the three administrative kinds are written in CandidateMajor, rc/2, with
// crit [x_identity_v1] and the body marker; every other statement stays Major, rc/1, exactly as before. Raw
// rotate_key and revoke_key are always rc/1 (§2.1: an rc/2 key event reads invalid), acting or not, so a caller
// asking for one with acting set gets 0: no major writes it.
func WriterMajor(kind string, acting bool) int {
	switch {
	case kind == "rotate_key" || kind == "revoke_key":
		if acting {
			return 0
		}
		return Major
	case identityAdmin[kind]:
		if acting {
			return 0 // administrative statements are raw-key statements and take no actor (§2.3)
		}
		return CandidateMajor
	case acting:
		if kind == "genesis" || kind == "describes" {
			return 0 // raw-key statements in this profile (§2.3)
		}
		return CandidateMajor
	}
	return Major
}

// IdentityDraft returns d prepared for the rc/2 writer (identity profile §2.1, §2.3): rc/2, crit
// [x_identity_v1], the body marker (marker, or {} when nil) added to a copy of the body, and actor as the signed
// envelope's x_actor_v1 (nil for an administrative statement or a marker-only line). It refuses what no reader
// would read as written: a kind WriterMajor does not write in rc/2 with this actor, a body that already carries a
// marker, or an actor whose ids are not statement ids. It does not check the body schema: Write reads the signed
// line back through the identity reader, which does.
func IdentityDraft(d Draft, actor *Actor, marker *canon.Object) (Draft, error) {
	if WriterMajor(d.Kind, actor != nil) != CandidateMajor {
		why := d.Kind + " is not written in rc/2"
		if actor != nil {
			why = d.Kind + " takes no " + ActorField + " (a raw-key statement, or a key event that stays rc/1)"
		}
		return Draft{}, refusal.Malformed("%s", why)
	}
	if actor != nil && (!reID.MatchString(actor.Identity) || !reID.MatchString(actor.Grant)) {
		return Draft{}, refusal.Malformed("%s needs identity and grant statement ids", ActorField)
	}
	if d.Body == nil {
		return Draft{}, refusal.Malformed("the draft has no body")
	}
	if _, ok := d.Body.Get(IdentityCrit); ok {
		return Draft{}, refusal.Malformed("the body already carries %s; the writer adds the marker", IdentityCrit)
	}
	if marker == nil {
		marker = &canon.Object{Members: map[string]canon.Value{}}
	}
	b := &canon.Object{Members: map[string]canon.Value{}}
	for _, k := range d.Body.Keys {
		b.Keys = append(b.Keys, k)
		b.Members[k] = d.Body.Members[k]
	}
	b.Keys = append(b.Keys, IdentityCrit)
	b.Members[IdentityCrit] = marker
	d.RC, d.Crit, d.Body, d.Actor = "rc/"+strconv.Itoa(CandidateMajor), []string{IdentityCrit}, b, nil
	if actor != nil {
		a := *actor
		d.Actor = &a
	}
	return d, nil
}
