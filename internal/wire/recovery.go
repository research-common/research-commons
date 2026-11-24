package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"

	"github.com/research-common/research-commons/internal/canon"
)

// The recoverable-root identity profile (docs/DESIGN-notes-recoverable-root-identity.md §4), read and not written:
// an identity_inception with profile recoverable-root-v1 commits to a recovery key; identity_succession is a
// successor root's seq-0 line; identity_recovery is the recovery key's one statement; identity_handover is the
// root's half of a recovery and carries the whole signed recovery statement, which this reader parses and verifies
// as a statement of its own (Statement.Carried). All three kinds are raw-key statements under the x_identity_v1
// marker ({}), like the fixed-root administrative kinds.

const (
	// RecoverableRootProfile is the recoverable-root identity profile token.
	RecoverableRootProfile = "recoverable-root-v1"
	// RecoveryCommitmentType is the payload type a recovery commitment is computed under (recoverable-root note §4):
	// the commitment is lowercase hex SHA-256 of PAE(RecoveryCommitmentType, <signer string>).
	RecoveryCommitmentType = "application/vnd.research-commons.recovery-commitment.v1"
)

// reCommitment is a recovery commitment: 64 lowercase hex digits.
var reCommitment = regexp.MustCompile(`^[0-9a-f]{64}$`)

// RecoveryCommitment is the commitment to a recovery key, from its signer string in the wire format's canonical
// form (`ed25519:` plus 64 lowercase hex, or `0x` plus 40 lowercase hex). The caller lowercases an address read
// from a device before computing it; a checksummed address is not a signer string.
func RecoveryCommitment(signer string) string {
	h := sha256.Sum256(PAE(RecoveryCommitmentType, []byte(signer)))
	return hex.EncodeToString(h[:])
}

// commitments reads {commitments:[c], rule:{any_one:true}} at p. This version reads exactly one commitment under
// any_one; any other count or rule is Unsupported for the whole statement, never "any one of them" (recoverable-root
// note §4, "One recovery key").
func commitments(v canon.Value, p string) (string, Status, string) {
	o, ok := v.(*canon.Object)
	if !ok {
		return "", Invalid, p + " is not an object"
	}
	if why := closed(o, p, "commitments", "rule"); why != "" {
		return "", Invalid, why
	}
	cv, ok := o.Get("commitments")
	arr, isArr := cv.(canon.Array)
	if !ok || !isArr || len(arr) == 0 {
		return "", Invalid, p + ".commitments is not a non-empty list"
	}
	for i, c := range arr {
		if s, ok := c.(canon.String); !ok || !reCommitment.MatchString(string(s)) {
			return "", Invalid, p + ".commitments[" + strconv.Itoa(i) + "] is not a commitment (64 lowercase hex)"
		}
	}
	rv, ok := o.Get("rule")
	ro, isObj := rv.(*canon.Object)
	if !ok || !isObj || len(ro.Keys) != 1 || !reToken.MatchString(ro.Keys[0]) {
		return "", Invalid, p + ".rule is not an object with one rule"
	}
	if ro.Keys[0] != "any_one" || len(arr) != 1 {
		return "", Unsupported, "recovery rule " + ro.Keys[0] + " over " + strconv.Itoa(len(arr)) + " commitments"
	}
	if b, ok := ro.Members["any_one"].(canon.Bool); !ok || !bool(b) {
		return "", Invalid, p + ".rule.any_one is not true"
	}
	return string(arr[0].(canon.String)), Valid, ""
}

// recoverableInception is inceptionBody for profile recoverable-root-v1: body.recovery carries the commitment.
func recoverableInception(s *Statement) (Status, string) {
	rv, ok := s.Body.Get("recovery")
	if !ok {
		return Invalid, "body.recovery is required for profile " + RecoverableRootProfile
	}
	_, st, why := commitments(rv, "body.recovery")
	return st, why
}

// InceptionCommitment is the recovery commitment a recoverable-root inception makes ("" for any other statement).
func InceptionCommitment(s *Statement) string {
	if s == nil || s.Kind != "identity_inception" || s.Body == nil {
		return ""
	}
	rv, ok := s.Body.Get("recovery")
	if !ok {
		return ""
	}
	c, st, _ := commitments(rv, "body.recovery")
	if st != Valid {
		return ""
	}
	return c
}

func successionBody(s *Statement) (Status, string) {
	if s.Seq != 0 {
		return Invalid, "identity_succession must be seq 0: the successor root is a fresh key"
	}
	if _, ok := idValue(s.Body, "identity"); !ok {
		return Invalid, "body.identity is not a statement id"
	}
	return Valid, ""
}

// recoveryBody reads the recovery key's statement: identity, last_good (a line of the root or null), successor
// ({key, inception} or null, which closes the identity), next (the next commitment, present exactly when there is
// a successor) and an optional note.
func recoveryBody(s *Statement) (Status, string) {
	if s.Seq != 0 {
		return Invalid, "identity_recovery must be seq 0: a recovery key signs once"
	}
	if _, ok := idValue(s.Body, "identity"); !ok {
		return Invalid, "body.identity is not a statement id"
	}
	lv, ok := s.Body.Get("last_good")
	if !ok {
		return Invalid, "body.last_good is required (null keeps only the root's first line)"
	}
	if _, isNull := lv.(canon.Null); !isNull {
		if _, ok := idValue(s.Body, "last_good"); !ok {
			return Invalid, "body.last_good is neither null nor a statement id"
		}
	}
	sv, ok := s.Body.Get("successor")
	if !ok {
		return Invalid, "body.successor is required (null closes the identity)"
	}
	nv, hasNext := s.Body.Get("next")
	future := ""
	if _, isNull := sv.(canon.Null); isNull {
		if hasNext {
			return Invalid, "body.next is not allowed when body.successor is null"
		}
	} else {
		so, isObj := sv.(*canon.Object)
		if !isObj {
			return Invalid, "body.successor is neither null nor an object"
		}
		if why := closed(so, "body.successor", "key", "inception"); why != "" {
			return Invalid, why
		}
		kv, ok := so.Get("key")
		if ks, isStr := kv.(canon.String); isStr && futureKey(string(ks)) {
			future = "key form " + keyScheme(string(ks))
		} else if !ok || key()(kv, "body.successor.key", &schemaCtx{}) != nil {
			return Invalid, "body.successor.key is not a key"
		}
		if _, ok := idValue(so, "inception"); !ok {
			return Invalid, "body.successor.inception is not a statement id"
		}
		if !hasNext {
			return Invalid, "body.next is required when body.successor is named"
		}
		if _, st, why := commitments(nv, "body.next"); st != Valid {
			return st, why
		}
	}
	if note, ok := s.Body.Get("note"); ok {
		if err := text()(note, "body.note", &schemaCtx{}); err != nil {
			return Invalid, err.Error()
		}
	}
	if future != "" {
		return Unsupported, future
	}
	return Valid, ""
}

// handoverBody reads the root's half of a recovery: identity, and recovery, a whole signed statement. The carried
// statement is parsed as a statement of its own and kept as Statement.Carried, so the evaluator can judge the
// handover from the carried bytes (recoverable-root note §4). A carried member that is not a statement at all makes
// the handover Invalid. A carried statement whose signature does not verify, or whose algorithm this reader lacks,
// leaves the handover Valid and is recorded on the carried statement (Verified false; Status Invalid naming the
// signature, or Unsupported naming the algorithm), because the profile reads those two cases differently (void, and
// unknown) and in a fixed order after the commitment, never as a refusal of the handover.
func (r *IdentityReader) handoverBody(s *Statement) (Status, string) {
	if s.Seq < 1 {
		return Invalid, "identity_handover must follow the root's first line"
	}
	if _, ok := idValue(s.Body, "identity"); !ok {
		return Invalid, "body.identity is not a statement id"
	}
	rv, ok := s.Body.Get("recovery")
	full, isObj := rv.(*canon.Object)
	if !ok || !isObj {
		return Invalid, "body.recovery is not an object (the signed identity_recovery)"
	}
	sigV, ok := full.Get("sig")
	sigS, isStr := sigV.(canon.String)
	if !ok || !isStr {
		return Invalid, "body.recovery.sig is not a string"
	}
	env := &canon.Object{Members: map[string]canon.Value{}}
	for _, k := range full.Keys {
		if k != "sig" {
			env.Keys = append(env.Keys, k)
			env.Members[k] = full.Members[k]
		}
	}
	c, err := r.read(env, string(sigS), false)
	if err != nil {
		return Invalid, "body.recovery is not a statement: " + err.Error()
	}
	if c.Status != Unsupported || c.Alg == AlgEIP191 || c.Alg == AlgEd25519 {
		if err := c.verify(string(sigS)); err != nil {
			c.Status, c.Why = Invalid, "signature does not verify: "+err.Error()
		} else {
			c.Verified, c.Sig = true, string(sigS)
		}
	}
	s.Carried = c
	return Valid, ""
}
