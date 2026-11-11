package resolve

import "github.com/research-common/research-commons/internal/keylog"

// SubjectKind is what owns a claim: a bare key, or an identity (identity profile §5.1). It mirrors the wire's
// tagged subjects (`{key: K}`, `{identity: I}`).
type SubjectKind string

const (
	// SubjectKey: the claim is the key's own word (claims §5.1). Every claim of every production reader.
	SubjectKey SubjectKind = "key"
	// SubjectIdentity: the claim is an identity's, made by delegate keys an actor evaluator finds eligible for it.
	// Only a reader with an evaluator has one (identity profile not active).
	SubjectIdentity SubjectKind = "identity"
)

// Subject is the owner of a claim, a unit member or a statement not counted: exactly one of a key or an identity.
type Subject struct {
	Kind SubjectKind
	ID   string // the full key (algorithm-prefixed) or the identity's inception id
}

// KeySubject is the subject of key k.
func KeySubject(k string) Subject { return Subject{Kind: SubjectKey, ID: k} }

// IdentitySubject is the subject of identity i.
func IdentitySubject(i string) Subject { return Subject{Kind: SubjectIdentity, ID: i} }

// IsKey reports whether the subject is a bare key.
func (s Subject) IsKey() bool { return s.Kind == SubjectKey }

// String is the display alias: a key subject shows as the key alone (exactly as before subjects were typed), an
// identity subject as "identity" and its short id.
func (s Subject) String() string {
	if s.Kind == SubjectIdentity {
		return "identity " + keylog.Short(s.ID)
	}
	return shortKey(s.ID)
}

// sortKey orders subjects: keys first (by key), then identities (by id), so a corpus with no identity subject
// keeps its key order.
func (s Subject) sortKey() string {
	if s.Kind == SubjectIdentity {
		return "1" + s.ID
	}
	return "0" + s.ID
}
