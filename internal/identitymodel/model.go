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
)

type Profile uint8

const (
	UnknownProfile Profile = iota
	FixedRoot
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

type Inception struct{ Profile Profile }

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
}

type Status string

const (
	Eligible Status = "eligible"
	Denied   Status = "denied"
	Unknown  Status = "unknown"
)

const (
	EvaluatorVersion = "fixed-root-model-1"
	NotEstablished   = "not_established"
	// MaxTraversalFacts bounds each ancestry walk and the relevant authenticated
	// root-event scan, not the total snapshot or wire protocol. Hitting a limit
	// yields unknown, never a partial pass. Unrelated/unproven noise does not
	// consume another identity's semantic budget. Transport/memory admission
	// limits belong to the trusted caller, not this model.
	MaxTraversalFacts = 2048
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
}

// Snapshot owns its facts, exposes no mutable internals, and stores no
// request-specific results or caches. It is safe for concurrent evaluations.
// Construct a new snapshot to add evidence; there is no destructive cut removal API.
type Snapshot struct {
	facts  map[ID]Fact
	order  []ID
	digest string
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
		f.Operation = &v
	}
	return f
}

func (s *Snapshot) EvidenceDigest() string { return s.digest }

// Clone is request-independent and shares no mutable state with its source.
func (s *Snapshot) Clone() *Snapshot {
	out := &Snapshot{facts: make(map[ID]Fact), order: slices.Clone(s.order), digest: s.digest}
	for id, f := range s.facts {
		out.facts[id] = copyFact(f)
	}
	return out
}
