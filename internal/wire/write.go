package wire

import (
	"encoding/hex"
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
	kind := d.Kind
	ss := PAE(PayloadType(kind, Major), canon.Encode(env))
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
		return nil, &refusal.Refusal{Class: refusal.Intrinsic, Reason: "future timestamp",
			Detail: "ts " + d.TS + " is more than 300 s ahead of the writer's clock; scope this statement"}
	}
	line, _ := Sign(d, k)
	return Read(line)
}
