// Package identitymodel is an isolated, pure reference model of fixed-root grant
// eligibility. It is NOT a wire reader, signature verifier, or admission API.
// Authentication and validity values are attestations supplied by a trusted
// evidence adapter, not checks performed here. See README.md for that boundary.
package identitymodel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// IDs are abstract exact statement/content/resource/task identifiers. This model
// deliberately does not parse or create wire IDs, profiles, or critical markers.
type ID string
type Key string

type Authentication uint8

const (
	Unproven      Authentication = iota // An arbitrary affiliation/signer assertion.
	Authenticated                       // Adapter attests exact signed fields AND signer.
	RejectedSignature
)

type Validity uint8

const (
	Unchecked Validity = iota
	Understood
	Unsupported
	Invalid
)

type Event uint8

const (
	Unclassified Event = iota // Unknown root vocabulary is authority-unknown.
	Data
	IdentityInception
	GrantEvent
	CutEvent
	RotateKey
	RevokeKey
	Inert // Explicitly recognized inert root metadata/anchors, NOT a default.
	// The recoverable-root profile's kinds (recoverable-root note §4). A succession is a successor root's seq-0 line
	// on the identity; a recovery is the recovery key's one statement; a handover is the root's half of a recovery
	// and carries the signed recovery statement whole, so it is judged from its own bytes (Handover.Carried).
	SuccessionEvent
	RecoveryEvent
	HandoverEvent
)

type Profile uint8

const (
	UnknownProfile Profile = iota
	FixedRoot
	RecoverableRoot
)

type ActorBinding uint8

const (
	NoIdentityContext    ActorBinding = iota
	BoundIdentityContext              // Adapter attests the signed actor and understood critical context.
	UnsupportedIdentityContext
	InvalidIdentityContext
)

type SubjectKind uint8

const (
	NoSubject SubjectKind = iota
	KeySubject
	IdentitySubject
)

// Subject is a tagged authority reference; the unused field must be empty.
// These are model tags, not a proposed wire encoding.
type Subject struct {
	Kind     SubjectKind
	Key      Key
	Identity ID
}

type Actor struct {
	Identity ID
	Grant    ID
}

type Inception struct {
	Profile Profile
	// Commitment is the recovery commitment a recoverable-root inception makes (recoverable-root note §4): the
	// adapter's digest of the recovery key's signer string. The model compares commitments for equality only.
	Commitment string
}

// Succession is a successor root's first line, pinned by the recovery that names it (recoverable-root note §4).
type Succession struct{ Identity ID }

// Successor names the next root: its key, its seq-0 succession on the identity, and the adapter's commitment of
// its signer string, so the reader can refuse a root the identity has committed to as a recovery key (RR-31).
type Successor struct {
	Key        Key
	Inception  ID
	Commitment string
}

// Recovery is the recovery key's statement: the last good line of the current root's log ("" is null: only the
// root's seq-0 line is kept), the successor (nil closes the identity) and the next commitment ("" when closing).
type Recovery struct {
	Identity  ID
	LastGood  ID
	Successor *Successor
	Next      string
}

// Carried is the adapter's reading of the signed recovery statement a handover carries. It is judged from these
// fields alone (recoverable-root note §4, "a handover is judged by signature"): Commitment is the digest of its
// signer string; Authentication is Authenticated when its signature verifies, RejectedSignature when it does not,
// and Unproven when the reader lacks its algorithm; Validity is Understood for a well-formed identity_recovery.
type Carried struct {
	ID             ID
	Signer         Key
	Commitment     string
	Authentication Authentication
	Validity       Validity
	Seq            uint64
	Prev           ID
	Merges         []ID
	Event          Event
	Recovery       *Recovery
}

// Handover is the root's half of a recovery (recoverable-root note §4).
type Handover struct {
	Identity ID
	Carried  Carried
}

type Grant struct {
	Identity    ID
	Delegate    Key
	Inception   ID // Exact delegate seq:0; never a movable head.
	Permissions []Permission
}

type LastGoodMode uint8

const (
	UnspecifiedLastGood LastGoodMode = iota // Omission is NOT null.
	PreserveNone
	PreserveThrough
)

type LastGood struct {
	Mode LastGoodMode
	ID   ID
}

type Cut struct {
	Identity ID
	Grant    ID
	LastGood LastGood
}

// Fact is an adapter-supplied interpretation of immutable signed evidence. Each
// ID must identify precisely these fields. A Fact marked Authenticated is a
// trusted assertion by the caller; changing the enum does not verify a signature.
// Invalid includes intrinsic/relative invalidity established by the adapter
// (including time/link rules not represented here). Unsupported can still carry
// authenticated linkage, but cannot itself earn authority.
type Fact struct {
	ID             ID
	Signer         Key
	Authentication Authentication
	Validity       Validity
	Seq            uint64
	Prev           ID
	Merges         []ID
	Event          Event
	Inception      *Inception
	Grant          *Grant
	Cut            *Cut
	Actor          *Actor
	Binding        ActorBinding
	Operation      *Operation
	Succession     *Succession
	Recovery       *Recovery
	Handover       *Handover
}

type Status string

const (
	Eligible Status = "eligible"
	Denied   Status = "denied"
	Unknown  Status = "unknown"
)

const (
	EvaluatorVersion = "identity-model-4" // reads fixed-root-v1 and recoverable-root-v1
	NotEstablished   = "not_established"
	// MaxDelegateSelfEvents bounds how many of a delegate's own raw key events one
	// evaluation examines for warnings. Warnings carry no authority, so the limit
	// emits a warning and never changes a status.
	MaxDelegateSelfEvents = 64
)

type Reason struct {
	Code      string
	Status    Status
	Statement ID
	Related   ID
	Detail    string
}

type Dependency struct {
	ID       ID
	NeededBy ID
	Purpose  string
}

type Warning struct {
	Code      string
	Statement ID
	Detail    string
}

type Result struct {
	Status            Status
	Statement         ID
	Signer            Key
	Actor             Subject // Declared actor, not proof that authority succeeded.
	Grant             ID
	RootLineage       ID
	DelegateInception ID
	Basis             []ID
	RelevantCuts      []ID
	Dependencies      []Dependency
	Reasons           []Reason
	Warnings          []Warning
	EvidenceDigest    string // Digest of normalized MODEL FACTS, not wire bytes.
	EvaluatorVersion  string
	Freshness         string // Always not_established; no completeness/freshness theorem.
	// Recoverable-root identities (recoverable-root note §5): Generation is the one the identity is read at (0
	// for a fixed-root identity, or one that was never recovered), Recoveries the complete handovers followed to
	// reach it, in order, and Closed whether the last recovery named no successor.
	Generation uint64
	Recoveries []ID
	Closed     bool
}

// Snapshot owns its facts, exposes no mutable internals, and stores no
// request-specific results or caches. It is safe for concurrent evaluations.
// Construct a new snapshot to add evidence; there is no destructive cut removal API.
type Snapshot struct {
	facts    map[ID]Fact
	order    []ID
	bySigner map[Key][]ID // Authenticated facts only, each list in sorted id order.
	digest   string
}

// NewSnapshot deep-copies and normalizes model sets. Identical duplicate facts
// collapse; conflicting contents at one exact ID are a caller-contract error.
// It does not authenticate evidence. Invalid/unsupported/unproven facts can be
// retained so Evaluate can report non-passing reasons instead of hiding them.
func NewSnapshot(facts []Fact) (*Snapshot, error) {
	s := &Snapshot{facts: make(map[ID]Fact)}
	for _, f := range facts {
		if f.ID == "" {
			return nil, fmt.Errorf("identitymodel: empty evidence ID")
		}
		f = copyFact(f)
		if old, ok := s.facts[f.ID]; ok {
			if !reflect.DeepEqual(old, f) {
				return nil, fmt.Errorf("identitymodel: conflicting facts at %q", f.ID)
			}
			continue
		}
		s.facts[f.ID] = f
		s.order = append(s.order, f.ID)
	}
	slices.Sort(s.order)
	s.index()
	ordered := make([]Fact, 0, len(s.order))
	for _, id := range s.order {
		ordered = append(ordered, s.facts[id])
	}
	b := modelKey(struct {
		Version string
		Facts   []Fact
	}{EvaluatorVersion, ordered})
	h := sha256.Sum256([]byte(b))
	s.digest = hex.EncodeToString(h[:])
	return s, nil
}

func copyFact(f Fact) Fact {
	f.Merges = append([]ID(nil), f.Merges...)
	slices.Sort(f.Merges)
	if f.Inception != nil {
		v := *f.Inception
		f.Inception = &v
	}
	if f.Grant != nil {
		v := *f.Grant
		v.Permissions = append([]Permission(nil), v.Permissions...)
		for i := range v.Permissions {
			p := &v.Permissions[i]
			p.Targets = append([]ID(nil), p.Targets...)
			slices.Sort(p.Targets)
		}
		slices.SortFunc(v.Permissions, func(a, b Permission) int {
			return strings.Compare(modelKey(a), modelKey(b))
		})
		f.Grant = &v
	}
	if f.Cut != nil {
		v := *f.Cut
		f.Cut = &v
	}
	if f.Actor != nil {
		v := *f.Actor
		f.Actor = &v
	}
	if f.Operation != nil {
		v := *f.Operation
		v.Amends = append([]ID(nil), v.Amends...)
		slices.Sort(v.Amends)
		f.Operation = &v
	}
	if f.Succession != nil {
		v := *f.Succession
		f.Succession = &v
	}
	if f.Recovery != nil {
		f.Recovery = copyRecovery(f.Recovery)
	}
	if f.Handover != nil {
		v := *f.Handover
		v.Carried.Merges = append([]ID(nil), v.Carried.Merges...)
		slices.Sort(v.Carried.Merges)
		v.Carried.Recovery = copyRecovery(v.Carried.Recovery)
		f.Handover = &v
	}
	return f
}

func copyRecovery(r *Recovery) *Recovery {
	if r == nil {
		return nil
	}
	v := *r
	if v.Successor != nil {
		s := *v.Successor
		v.Successor = &s
	}
	return &v
}

// index builds the per-signer scan lists. Only authenticated facts are indexed:
// an unproven signer claim never enters another identity's scan or budget.
func (s *Snapshot) index() {
	s.bySigner = map[Key][]ID{}
	for _, id := range s.order {
		if f := s.facts[id]; f.Authentication == Authenticated {
			s.bySigner[f.Signer] = append(s.bySigner[f.Signer], id)
		}
	}
}

func (s *Snapshot) EvidenceDigest() string { return s.digest }

// Clone is request-independent and shares no mutable state with its source.
func (s *Snapshot) Clone() *Snapshot {
	out := &Snapshot{facts: make(map[ID]Fact), order: slices.Clone(s.order), digest: s.digest}
	for id, f := range s.facts {
		out.facts[id] = copyFact(f)
	}
	out.index()
	return out
}
