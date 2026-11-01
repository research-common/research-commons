// Package wire reads and writes statements in the wire format of DESIGN-notes-wire-format.md: the envelope
// (§2), the DSSE PAE signed string (§2), statement identity (§3), the two signature algorithms (§4) and the
// extension rules (§6).
//
// Read (or an explicitly configured Reader.Read) is the entry point for received bytes. It refuses with a
// typed refusal (package refusal) or returns a Statement whose Status says whether it can be evaluated
// (Valid) or is retained without interpretation (Unsupported). The checks run in a fixed order so that a
// negative test can show which boundary refused it: parse (size, depth, JSON subset) → envelope fields →
// body schema → body time values → signature → registered critical-extension validators. An unsupported
// crit skips all body validation.
package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/rctime"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/sig"
)

// Major is the one format major this reader implements.
const Major = 1

// MaxSignedString is the statement size bound of §1: the signed string is at most 65 536 bytes.
const MaxSignedString = 65536

// Algorithms of §4.
const (
	AlgEd25519 = "ed25519"
	AlgEIP191  = "eip191-secp256k1"
)

// Status says what a reader may do with a statement it holds.
type Status string

const (
	// Valid: the signature verified and every rule this reader implements passed.
	Valid Status = "valid"
	// Unsupported: retained and chained, never evaluated (unknown rc major, unknown alg, unimplemented crit).
	Unsupported Status = "unsupported"
	// UnknownKind: a validly signed statement of a kind §5 does not list. Stored and displayed as an unknown
	// kind; it grants nothing (C-core-13).
	UnknownKind Status = "unknown kind"
)

// Statement is a statement as the reader holds it.
type Statement struct {
	Status Status
	// Why names the reason for Unsupported ("rc/2", "alg ml-dsa-65", "crit x_escrow").
	Why string

	RC     string
	Kind   string
	Signer string
	Alg    string
	Seq    int64
	Prev   string // "" when null
	// Merges lists the other tips of the signer's own log this line absorbs (§7), sorted; nil when absent.
	Merges []string
	TS     rctime.Time
	Crit   []string
	Body   *canon.Object

	// Sig is the canonical encoding of the signature (§4): what the reader stores.
	Sig string
	// SignedString is the exact byte string the signature covers.
	SignedString []byte
	// ID is the statement id: lowercase hex sha256 of SignedString.
	ID string
	// Verified is true when the signature was checked. Unsupported statements under an unknown rc major or
	// unknown alg are retained unverified; both carry an id and links (another major's by the linkage
	// contract, wire §6), so a log can place them once a verified line of the key names them.
	Verified bool
	// Unpinned names the referent fields an observed statement's class requires and the statement lacks. Such
	// a statement is valid and admitted; its referent status reads unpinned (§5, claims-model note §5.3.1).
	Unpinned []string
	// Actor is the candidate rc/2 signed identity context (identity.go), set only by IdentityReader on a
	// verified rc/2 line that carries one. It is a claim to be evaluated, never authority. Read never sets it.
	Actor *Actor

	env  *canon.Object // the envelope without sig
	refs []string      // the body's typed references, set when the body schema ran and passed
}

// References returns the blobs the statement's body references: every value the body schema (§5) types as a
// digest, at any depth (content.digest, provenance.workflow and inputs, anchors.proof, refutes.evidence,
// comparator, report, members[].content, a source referent's response_digest or requests.digest, …), sorted
// and without repeats. It is computed by the schema check itself, so it lists exactly the fields the schema
// tables type with digest(). It returns nil for a statement this reader did not interpret (not verified, not
// Valid: an unknown kind, an unsupported major, alg or crit): such a body is opaque, and a caller that needs
// its references falls back to ScanDigests over the stored line.
func (s *Statement) References() []string {
	if s == nil || !s.Verified || s.Status != Valid {
		return nil
	}
	return slices.Clone(s.refs)
}

// Line returns the canonical stored form: the envelope with the canonical sig, JCS-encoded, no newline.
func (s *Statement) Line() []byte {
	o := &canon.Object{Keys: append(append([]string{}, s.env.Keys...), "sig"), Members: map[string]canon.Value{}}
	for k, v := range s.env.Members {
		o.Members[k] = v
	}
	o.Members["sig"] = canon.String(s.Sig)
	return canon.Encode(o)
}

// PayloadType is the DSSE payload type of a statement: application/vnd.research-commons.<kind>.v<major>+json.
func PayloadType(kind string, major int) string {
	return "application/vnd.research-commons." + kind + ".v" + strconv.Itoa(major) + "+json"
}

// PAE is the DSSE v1 pre-authentication encoding.
func PAE(payloadType string, body []byte) []byte {
	b := make([]byte, 0, len(payloadType)+len(body)+32)
	b = append(b, "DSSEv1 "...)
	b = strconv.AppendInt(b, int64(len(payloadType)), 10)
	b = append(b, ' ')
	b = append(b, payloadType...)
	b = append(b, ' ')
	b = strconv.AppendInt(b, int64(len(body)), 10)
	b = append(b, ' ')
	return append(b, body...)
}

// ID is lowercase hex sha256 of a signed string.
func ID(signedString []byte) string {
	h := sha256.Sum256(signedString)
	return hex.EncodeToString(h[:])
}

var (
	reAddr  = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
	reEdKey = regexp.MustCompile(`^ed25519:[0-9a-f]{64}$`)
	// reOtherKey is the shape a key may take in another major (a scheme prefix and hex), for the linkage
	// contract only: such a signer is never verified here.
	reOtherKey = regexp.MustCompile(`^[a-z][a-z0-9-]*:[0-9a-f]+$`)
	reID       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reRC       = regexp.MustCompile(`^rc/([1-9][0-9]*)$`)
	reKind     = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	reSigEIP   = regexp.MustCompile(`^0x[0-9a-f]{130}$`)
	reSigEd    = regexp.MustCompile(`^[0-9a-f]{128}$`)
	envFields  = []string{"rc", "kind", "signer", "alg", "seq", "prev", "ts", "body"}
)

// MaxLine bounds a received line before it is parsed (I15: a hostile line is refused before the parser walks
// it). The canonical envelope can exceed its input only through the escapes JCS writes for control characters
// (one byte becomes six), plus the PAE prefix, so any line that could yield a signed string within
// MaxSignedString is at most this long: a longer one is refused as the same operational size limit without
// being parsed. Lines between the two bounds are parsed and then held to MaxSignedString exactly.
const MaxLine = 6*MaxSignedString + 1024

// Read parses, validates and verifies one received statement, with no registered extensions.
func Read(line []byte) (*Statement, error) {
	return (&Reader{}).Read(line)
}

// Read parses, validates and verifies one received statement using this reader's fixed extension registry.
// Unsupported critical extensions skip both base-body validation and every extension validator.
func (r *Reader) Read(line []byte) (*Statement, error) {
	if len(line) > MaxLine {
		return nil, &refusal.Refusal{Class: refusal.Operational, Reason: refusal.SizeLimit,
			Detail: "size limit " + strconv.Itoa(MaxSignedString) + " (line of " + strconv.Itoa(len(line)) + " bytes refused before parsing)"}
	}
	v, err := canon.Parse(line)
	if err != nil {
		return nil, err
	}
	env, ok := v.(*canon.Object)
	if !ok {
		return nil, refusal.Malformed("top level is not an object")
	}
	return r.fromEnvelope(env)
}

func (r *Reader) fromEnvelope(full *canon.Object) (*Statement, error) {
	sigV, ok := full.Get("sig")
	if !ok {
		return nil, refusal.Malformed("missing sig")
	}
	sigS, ok := sigV.(canon.String)
	if !ok {
		return nil, refusal.Malformed("sig is not a string")
	}
	env := &canon.Object{Members: map[string]canon.Value{}}
	for _, k := range full.Keys {
		if k != "sig" {
			env.Keys = append(env.Keys, k)
			env.Members[k] = full.Members[k]
		}
	}
	s := &Statement{env: env, Status: Valid}

	// rc first: an unknown major is retained unverified, whatever else its envelope holds.
	rc, err := str(env, "rc")
	if err != nil {
		return nil, err
	}
	m := reRC.FindStringSubmatch(rc)
	if m == nil {
		return nil, refusal.Malformed("rc %q is not rc/<positive integer>", rc)
	}
	s.RC = rc
	major, err := strconv.Atoi(m[1])
	if err != nil || major < 1 {
		return nil, refusal.Malformed("rc %q is not rc/<positive integer>", rc)
	}
	if major != Major {
		return otherMajor(s, env, major, string(sigS))
	}

	for _, f := range envFields {
		if _, ok := env.Get(f); !ok {
			return nil, refusal.Malformed("missing envelope field %q", f)
		}
	}
	if s.Kind, err = str(env, "kind"); err != nil {
		return nil, err
	}
	if !reKind.MatchString(s.Kind) {
		return nil, refusal.Malformed("kind %q", s.Kind)
	}
	if s.Signer, err = str(env, "signer"); err != nil {
		return nil, err
	}
	if s.Alg, err = str(env, "alg"); err != nil {
		return nil, err
	}
	isAddr, isEd := reAddr.MatchString(s.Signer), reEdKey.MatchString(s.Signer)
	if !isAddr && !isEd {
		return nil, refusal.Malformed("signer %q is neither 0x + 40 lowercase hex nor ed25519: + 64 lowercase hex", s.Signer)
	}
	switch {
	case s.Alg == AlgEIP191 && !isAddr, s.Alg == AlgEd25519 && !isEd:
		return nil, refusal.Malformed("alg %s with signer %s", s.Alg, s.Signer)
	}
	seq, ok := env.Members["seq"].(canon.Int)
	if !ok || seq < 0 {
		return nil, refusal.Malformed("seq is not a non-negative integer")
	}
	s.Seq = int64(seq)
	switch p := env.Members["prev"].(type) {
	case canon.Null:
		if s.Seq != 0 {
			return nil, refusal.Malformed("prev null at seq %d", s.Seq)
		}
	case canon.String:
		if !reID.MatchString(string(p)) {
			return nil, refusal.Malformed("prev %q is not a statement id", string(p))
		}
		if s.Seq == 0 {
			return nil, refusal.Malformed("prev set at seq 0")
		}
		s.Prev = string(p)
	default:
		return nil, refusal.Malformed("prev is neither null nor a string")
	}
	if m, present := env.Get("merges"); present {
		if s.Merges, err = mergesList(m, s.Seq, s.Prev); err != nil {
			return nil, err
		}
	}
	tsS, err := str(env, "ts")
	if err != nil {
		return nil, err
	}
	if s.TS, err = rctime.ParseUTC(tsS); err != nil {
		return nil, err
	}
	body, ok := env.Members["body"].(*canon.Object)
	if !ok {
		return nil, refusal.Malformed("body is not an object")
	}
	s.Body = body
	if c, present := env.Get("crit"); present {
		if s.Crit, err = critList(c, body); err != nil {
			return nil, err
		}
	}

	// The signed string, the id and the size bound.
	s.SignedString = PAE(PayloadType(s.Kind, Major), canon.Encode(env))
	if len(s.SignedString) > MaxSignedString {
		return nil, &refusal.Refusal{Class: refusal.Operational, Reason: refusal.SizeLimit,
			Detail: "size limit " + strconv.Itoa(MaxSignedString)}
	}
	s.ID = ID(s.SignedString)

	switch s.Alg {
	case AlgEIP191, AlgEd25519:
	default:
		s.Status, s.Why, s.Sig = Unsupported, "alg "+s.Alg, string(sigS)
		return s, nil
	}

	// The body schema (§5) and then the body time values (§1.1, on fields the schema has typed as strings) are
	// checked on every statement this reader can evaluate.
	// A statement whose crit names an extension this reader lacks is evaluated under no interpretation (§6),
	// so its body is not read.
	supported := r.supports(s.Crit)
	if supported {
		known, ctx, err := bodySchema(s.Kind, body)
		if err != nil {
			return nil, err
		}
		if err := checkBodyTimes(s.Kind, body); err != nil {
			return nil, err
		}
		s.Unpinned, s.refs = ctx.unpinned, sortedRefs(ctx.refs)
		if !known {
			s.Status, s.Why = UnknownKind, s.Kind
		}
	}

	if err := s.verify(string(sigS)); err != nil {
		return nil, err
	}
	s.Verified = true
	if !supported {
		s.Status, s.Why = Unsupported, "crit "+strings.Join(s.Crit, ",")
	} else if err := r.validateExtensions(s.Crit, env); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Statement) verify(sigS string) error {
	switch s.Alg {
	case AlgEIP191:
		if !reSigEIP.MatchString(sigS) {
			return refusal.Malformed("sig is not 0x + 130 lowercase hex")
		}
		raw, _ := hex.DecodeString(sigS[2:])
		addr, _ := hex.DecodeString(s.Signer[2:])
		c, ok := sig.VerifyEIP191(s.SignedString, raw, addr)
		if !ok {
			return refusal.BadSig("does not recover %s", s.Signer)
		}
		s.Sig = "0x" + hex.EncodeToString(c)
	case AlgEd25519:
		if !reSigEd.MatchString(sigS) {
			return refusal.Malformed("sig is not 128 lowercase hex")
		}
		raw, _ := hex.DecodeString(sigS)
		pub, _ := hex.DecodeString(strings.TrimPrefix(s.Signer, "ed25519:"))
		if step := sig.VerifyEd25519(pub, s.SignedString, raw); step != "" {
			return refusal.BadSig("ed25519 %s", step)
		}
		s.Sig = sigS
	}
	return nil
}

// mergesList checks the line-local rules §7 gives merges: a non-empty, sorted, duplicate-free list of statement
// ids that never contains prev. The rules that need the rest of the log (each entry a line by the same key with
// a lower seq) are the log's (package keylog).
func mergesList(v canon.Value, seq int64, prev string) ([]string, error) {
	a, ok := v.(canon.Array)
	if !ok || len(a) == 0 {
		return nil, refusal.Malformed("merges is not a non-empty list")
	}
	if seq == 0 {
		return nil, refusal.Malformed("merges at seq 0: no earlier line to absorb")
	}
	out := make([]string, 0, len(a))
	for i, e := range a {
		id, ok := e.(canon.String)
		if !ok || !reID.MatchString(string(id)) {
			return nil, refusal.Malformed("merges entry is not a statement id")
		}
		if string(id) == prev {
			return nil, refusal.Malformed("merges contains prev %s", prev)
		}
		if i > 0 && canon.CompareKeys(out[i-1], string(id)) >= 0 {
			return nil, refusal.Malformed("merges is not sorted and duplicate-free")
		}
		out = append(out, string(id))
	}
	return out, nil
}

// critList checks the structure §6 gives crit: a non-empty, sorted, duplicate-free list of body member
// names, each present in the body and each an extension name (x_ prefix).
func critList(v canon.Value, body *canon.Object) ([]string, error) {
	a, ok := v.(canon.Array)
	if !ok || len(a) == 0 {
		return nil, refusal.Malformed("crit is not a non-empty list")
	}
	out := make([]string, 0, len(a))
	for i, e := range a {
		n, ok := e.(canon.String)
		if !ok {
			return nil, refusal.Malformed("crit member is not a string")
		}
		if i > 0 && canon.CompareKeys(out[i-1], string(n)) >= 0 {
			return nil, refusal.Malformed("crit is not sorted and duplicate-free")
		}
		if !strings.HasPrefix(string(n), "x_") {
			return nil, refusal.Malformed("crit names %q, which is not an extension name", string(n))
		}
		if _, ok := body.Get(string(n)); !ok {
			return nil, refusal.Malformed("crit names %q, which is not in the body", string(n))
		}
		out = append(out, string(n))
	}
	return out, nil
}

func str(o *canon.Object, k string) (string, error) {
	v, ok := o.Get(k)
	if !ok {
		return "", refusal.Malformed("missing envelope field %q", k)
	}
	s, ok := v.(canon.String)
	if !ok {
		return "", refusal.Malformed("%s is not a string", k)
	}
	return string(s), nil
}

// otherMajor reads a statement in a major this reader does not implement, under the linkage contract (wire §6):
// the id formula, the canonical signed body and the fields signer, seq, prev and merges are the same in every
// major. Nothing else is read and the signature is not checked (another major's alg set may differ), so the
// statement is Unsupported and unverified; it carries an id and links, so a log can place it once a verified
// line of the same key names it, exactly as an unknown-alg line (wire §4). A statement whose linkage fields
// break the contract is malformed: they are the contract's, not the other major's.
func otherMajor(s *Statement, env *canon.Object, major int, sig string) (*Statement, error) {
	s.Status, s.Why, s.Sig = Unsupported, s.RC, sig
	var err error
	if s.Kind, err = str(env, "kind"); err != nil {
		return nil, err
	}
	if !reKind.MatchString(s.Kind) {
		return nil, refusal.Malformed("kind %q", s.Kind)
	}
	if s.Signer, err = str(env, "signer"); err != nil {
		return nil, err
	}
	if !reAddr.MatchString(s.Signer) && !reEdKey.MatchString(s.Signer) && !reOtherKey.MatchString(s.Signer) {
		return nil, refusal.Malformed("signer %q is not a key", s.Signer)
	}
	seq, ok := env.Members["seq"].(canon.Int)
	if !ok || seq < 0 {
		return nil, refusal.Malformed("seq is not a non-negative integer")
	}
	s.Seq = int64(seq)
	switch p := env.Members["prev"].(type) {
	case canon.Null:
		if s.Seq != 0 {
			return nil, refusal.Malformed("prev null at seq %d", s.Seq)
		}
	case canon.String:
		if !reID.MatchString(string(p)) {
			return nil, refusal.Malformed("prev %q is not a statement id", string(p))
		}
		if s.Seq == 0 {
			return nil, refusal.Malformed("prev set at seq 0")
		}
		s.Prev = string(p)
	default:
		return nil, refusal.Malformed("prev is neither null nor a string")
	}
	if m, present := env.Get("merges"); present {
		if s.Merges, err = mergesList(m, s.Seq, s.Prev); err != nil {
			return nil, err
		}
	}
	s.SignedString = PAE(PayloadType(s.Kind, major), canon.Encode(env))
	if len(s.SignedString) > MaxSignedString {
		return nil, &refusal.Refusal{Class: refusal.Operational, Reason: refusal.SizeLimit,
			Detail: "size limit " + strconv.Itoa(MaxSignedString)}
	}
	s.ID = ID(s.SignedString)
	return s, nil
}
