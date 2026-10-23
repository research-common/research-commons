// Package identity is the CANDIDATE fixed-root identity admission adapter. It is the only production code that
// turns signed wire evidence into identitymodel facts: it reads exact received bytes with wire.IdentityReader,
// sets Authentication only for a signature this reader verified, and translates retained evidence without a
// bare-key Counts() filter. It enables no writer, no global major and no resolver consumer.
//
// Contract: research note "Reconciled admission contract" (local), summarized in README.md of this package.
package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/identitymodel"
	"github.com/research-common/research-commons/internal/wire"
)

// MaxAdmitLines bounds the distinct authenticated statements (verified, or vouched by a verified same-key line) of
// one snapshot. Over the bound Admit fails as a whole: there is no partial snapshot, so no partial pass. Selecting
// relevant keys before admission is the transport's job: anyone can sign many lines with keys of their own.
const MaxAdmitLines = 100000

// MaxUnprovenLines bounds the retained unverified, unvouched lines. They are linkage claims that anyone could have
// fabricated and affect nothing, so over the bound the ones with the largest ids are dropped (a dropped link reads
// missing, which is no more permissive than unproven) instead of failing the snapshot.
const MaxUnprovenLines = 100000

// Refused is a received line no reader can attribute (parse, envelope linkage or signature failure). It is not
// evidence: a bad-signature copy of a real line must not stand for that line, so it is never a fact.
type Refused struct {
	Index int
	Err   error
}

// Snapshot is an immutable admitted evidence set.
type Snapshot struct {
	model   *identitymodel.Snapshot
	held    map[string]*wire.Statement
	receipt string
	refused []Refused

	droppedUnproven int
}

// Admit reads every line with the candidate identity reader and builds the model snapshot. Delivery order and
// duplicates do not change the result.
func Admit(lines [][]byte) (*Snapshot, error) {
	r := wire.NewIdentityReader()
	s := &Snapshot{held: map[string]*wire.Statement{}}
	stored := map[string][]byte{}
	for i, line := range lines {
		st, err := r.Read(line)
		if err != nil {
			s.refused = append(s.refused, Refused{i, err})
			continue
		}
		canonical := st.Line()
		if old, ok := stored[st.ID]; ok && bytes.Compare(old, canonical) <= 0 {
			continue
		}
		if !bytes.Equal(line, canonical) {
			// Translate from canonical bytes only, so no fact depends on the member order a copy arrived in.
			if st, err = r.Read(canonical); err != nil {
				return nil, fmt.Errorf("identity: line %d (%s): canonical form does not read back: %w", i, st.ID, err)
			}
		}
		s.held[st.ID], stored[st.ID] = st, canonical
	}
	vouched := vouch(s.held)
	var authenticated int
	var unproven []string
	for id, st := range s.held {
		if st.Verified || vouched[id] {
			authenticated++
		} else {
			unproven = append(unproven, id)
		}
	}
	if authenticated > MaxAdmitLines {
		return nil, fmt.Errorf("identity: more than %d distinct authenticated statements; no partial snapshot", MaxAdmitLines)
	}
	if len(unproven) > MaxUnprovenLines {
		slices.Sort(unproven)
		for _, id := range unproven[MaxUnprovenLines:] {
			delete(s.held, id)
			delete(stored, id)
		}
		s.droppedUnproven = len(unproven) - MaxUnprovenLines
	}
	ids := make([]string, 0, len(s.held))
	for id := range s.held {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	facts := make([]identitymodel.Fact, 0, len(ids))
	h := sha256.New()
	for _, id := range ids {
		st := s.held[id]
		facts = append(facts, translate(st, vouched[id]))
		line := stored[id]
		if !st.Verified {
			// An unverified line's sig is not authenticated: anyone could resend it with other sig bytes.
			// The receipt commits to its signed content (the id) only.
			c := *st
			c.Sig = ""
			line = c.Line()
		}
		fmt.Fprintf(h, "%s %d\n", id, len(line))
		h.Write(line)
		h.Write([]byte{'\n'})
	}
	m, err := identitymodel.NewSnapshot(facts)
	if err != nil {
		return nil, fmt.Errorf("identity: adapter produced inconsistent facts: %w", err)
	}
	s.model = m
	s.receipt = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return s, nil
}

// DroppedUnproven counts unverified, unvouched lines dropped over MaxUnprovenLines.
func (s *Snapshot) DroppedUnproven() int { return s.droppedUnproven }

// Evaluate answers whether the statement id may act for the identity and grant its signature names. It is
// identity eligibility only: bare statements are reported as no_identity_actor and belong to the unchanged
// legacy evaluator; operation roles, policy and time are consumers' questions.
func (s *Snapshot) Evaluate(id string) identitymodel.Result {
	return s.model.Evaluate(identitymodel.ID(id))
}

// Receipt digests the exact admitted canonical lines (one per id; for an unverified line, its signed content with
// the unauthenticated sig emptied). It is the evidence receipt, distinct from the model's EvidenceDigest over
// normalized facts. Blob availability is NOT covered.
func (s *Snapshot) Receipt() string { return s.receipt }

// EvidenceDigest is the model digest over normalized facts.
func (s *Snapshot) EvidenceDigest() string { return s.model.EvidenceDigest() }

// Refused lists the received lines that are not evidence.
func (s *Snapshot) Refused() []Refused { return slices.Clone(s.refused) }

// Status reports how the reader holds a statement id ("" when not held).
func (s *Snapshot) Status(id string) (wire.Status, bool) {
	st, ok := s.held[id]
	if !ok {
		return "", false
	}
	return st.Status, st.Verified
}

// vouch returns the unverified lines (another major, an unknown alg) whose exact bytes a verified line of the
// same key committed to through prev/merges, directly or through other vouched lines. Such a line's id is under
// that key's verified signature and the id covers every signed byte, so its content is authenticated even though
// its meaning is not: it is admitted as authenticated, unsupported evidence. An unvouched unverified line could
// have been fabricated by anyone and stays unproven.
func vouch(held map[string]*wire.Statement) map[string]bool {
	out := map[string]bool{}
	var queue []*wire.Statement
	for _, st := range held {
		if st.Verified {
			queue = append(queue, st)
		}
	}
	for len(queue) > 0 {
		st := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for _, l := range append([]string{st.Prev}, st.Merges...) {
			x, ok := held[l]
			if l == "" || !ok || x.Verified || out[l] || x.Signer != st.Signer {
				continue
			}
			out[l] = true
			queue = append(queue, x)
		}
	}
	return out
}

// translate is the single Fact constructor. Authentication is a fact about THIS read (a verified signature, or a
// verified same-key commitment to the exact bytes), never about keylog placement; validity follows the admission
// contract §3–§4.
func translate(st *wire.Statement, vouched bool) identitymodel.Fact {
	f := identitymodel.Fact{ID: identitymodel.ID(st.ID), Signer: identitymodel.Key(st.Signer), Seq: uint64(st.Seq),
		Prev: identitymodel.ID(st.Prev), Validity: identitymodel.Unchecked, Event: identitymodel.Unclassified}
	for _, m := range st.Merges {
		f.Merges = append(f.Merges, identitymodel.ID(m))
	}
	if vouched {
		f.Authentication, f.Validity = identitymodel.Authenticated, identitymodel.Unsupported
		return f // authenticated bytes, uninterpreted meaning: linkage, and unknown if it is a root control
	}
	if !st.Verified {
		return f // Unproven: retained linkage claim only.
	}
	f.Authentication = identitymodel.Authenticated
	switch st.Status {
	case wire.Valid:
		f.Validity = identitymodel.Understood
	case wire.Invalid:
		f.Validity = identitymodel.Invalid
	default:
		f.Validity = identitymodel.Unsupported
	}
	candidate := st.RC == "rc/2"
	admin := candidate && (st.Kind == "identity_inception" || st.Kind == "identity_grant" || st.Kind == "identity_cut")
	switch {
	case admin:
		administrative(&f, st)
		return f
	case st.Status != wire.Valid:
		// Authenticated but not understood. Never Invalid outside the administrative kinds: a malformed line in
		// a root lineage (a revoke_key, say) could have been terminal, so it must read unknown, not ineffective.
		f.Validity = identitymodel.Unsupported
		if st.Actor != nil {
			f.Event, f.Operation = identitymodel.Data, &identitymodel.Operation{Kind: "unevaluated"}
			f.Actor = &identitymodel.Actor{Identity: identitymodel.ID(st.Actor.Identity), Grant: identitymodel.ID(st.Actor.Grant)}
			f.Binding = identitymodel.UnsupportedIdentityContext
			if st.Status == wire.Invalid {
				f.Binding = identitymodel.InvalidIdentityContext
			}
		}
		return f
	case !candidate && st.Kind == "rotate_key":
		f.Event = identitymodel.RotateKey
	case !candidate && st.Kind == "revoke_key":
		f.Event = identitymodel.RevokeKey
	case st.Actor == nil && (st.Kind == "describes" || st.Kind == "anchors"):
		f.Event = identitymodel.Inert
	case wire.PermissionDomain(st.Kind) != "":
		f.Event, f.Operation = identitymodel.Data, operation(st)
		if st.Actor != nil {
			f.Actor = &identitymodel.Actor{Identity: identitymodel.ID(st.Actor.Identity), Grant: identitymodel.ID(st.Actor.Grant)}
			f.Binding = identitymodel.BoundIdentityContext
		}
	}
	return f
}

func operation(st *wire.Statement) *identitymodel.Operation {
	op := &identitymodel.Operation{Kind: identitymodel.Kind(st.Kind)}
	switch wire.PermissionDomain(st.Kind) {
	case "contents":
		op.Target = identitymodel.Target{Type: identitymodel.ContentTarget, ID: identitymodel.ID(text(object(st.Body, "content"), "digest"))}
	case "statements":
		op.Target = identitymodel.Target{Type: identitymodel.StatementTarget, ID: identitymodel.ID(text(st.Body, "of"))}
	case "resources":
		op.Target = identitymodel.Target{Type: identitymodel.ResourceTarget, ID: identitymodel.ID(text(st.Body, "resource"))}
	case "tasks":
		op.Target = identitymodel.Target{Type: identitymodel.TaskTarget, ID: identitymodel.ID(text(st.Body, "task"))}
	case "log":
		op.Target = identitymodel.Target{Type: identitymodel.LogTarget, Key: identitymodel.Key(st.Signer)}
	}
	if st.RC == "rc/2" {
		if _, ok := object(st.Body, wire.IdentityCrit).Get("amends"); ok {
			op.Amend = true
		}
	}
	return op
}

// administrative fills the typed payload best-effort, so an authenticated Invalid or Unsupported control keeps
// whatever exact binding it does carry (a cut naming I/G stays addressed to G and therefore blocks G).
func administrative(f *identitymodel.Fact, st *wire.Statement) {
	b := st.Body
	switch st.Kind {
	case "identity_inception":
		f.Event, f.Inception = identitymodel.IdentityInception, &identitymodel.Inception{}
		if st.Status == wire.Valid && text(b, "profile") == wire.FixedRootProfile {
			f.Inception.Profile = identitymodel.FixedRoot
		}
	case "identity_grant":
		d := object(b, "delegate")
		g := &identitymodel.Grant{Identity: identitymodel.ID(idText(b, "identity")), Delegate: identitymodel.Key(text(d, "key")),
			Inception: identitymodel.ID(idText(d, "inception"))}
		if a, ok := field(b, "permissions").(canon.Array); ok {
			for _, pv := range a {
				if p, ok := permission(pv); ok {
					g.Permissions = append(g.Permissions, p)
				}
			}
		}
		f.Event, f.Grant = identitymodel.GrantEvent, g
	case "identity_cut":
		c := &identitymodel.Cut{Identity: identitymodel.ID(idText(b, "identity")), Grant: identitymodel.ID(idText(b, "grant"))}
		switch v := field(b, "last_good").(type) {
		case canon.Null:
			c.LastGood.Mode = identitymodel.PreserveNone
		case canon.String:
			if id := idText(b, "last_good"); id != "" {
				c.LastGood = identitymodel.LastGood{Mode: identitymodel.PreserveThrough, ID: identitymodel.ID(id)}
			}
			_ = v
		}
		f.Event, f.Cut = identitymodel.CutEvent, c
		if f.Validity == identitymodel.Invalid && c.Grant == "" {
			// A cut is addressed by its grant. Without a readable grant no grant can be definitely denied by it:
			// unknown for all of I's grants (model: unsupported root event), never a definite denial and never
			// ineffective. An unreadable identity with a readable grant is an invalid cut addressed to that grant.
			f.Validity = identitymodel.Unsupported
		}
	}
}

func permission(v canon.Value) (identitymodel.Permission, bool) {
	o, ok := v.(*canon.Object)
	if !ok {
		return identitymodel.Permission{}, false
	}
	kind := text(o, "kind")
	domain := wire.PermissionDomain(kind)
	if domain == "" {
		return identitymodel.Permission{}, false // an unknown kind already made the grant Unsupported
	}
	p := identitymodel.Permission{Kind: identitymodel.Kind(kind)}
	if b, ok := field(o, "amend").(canon.Bool); ok {
		p.Amend = bool(b)
	}
	if domain == "log" {
		p.Mode = identitymodel.OwnLog
		return p, true
	}
	t := object(o, "targets")
	if t == nil {
		return p, true // UnspecifiedTargets: the model denies it as invalid scope
	}
	if len(t.Members) != 1 {
		return p, true // no single target mode: UnspecifiedTargets, denied as invalid scope (never member-order-picked)
	}
	for mode, v := range t.Members {
		switch mode {
		case "any_content", "any_statement":
			p.Mode = identitymodel.AnyTarget
		default:
			p.Mode = identitymodel.ExactTargets
			if a, ok := v.(canon.Array); ok {
				for _, e := range a {
					if s, ok := e.(canon.String); ok {
						p.Targets = append(p.Targets, identitymodel.ID(s))
					}
				}
			}
		}
	}
	return p, true
}

func field(o *canon.Object, k string) canon.Value {
	if o == nil {
		return nil
	}
	v, _ := o.Get(k)
	return v
}

func object(o *canon.Object, k string) *canon.Object {
	x, _ := field(o, k).(*canon.Object)
	return x
}

func text(o *canon.Object, k string) string {
	s, _ := field(o, k).(canon.String)
	return string(s)
}

// idText returns a field only when it is a full statement id, so a malformed reference never matches anything.
func idText(o *canon.Object, k string) string {
	s := text(o, k)
	if len(s) != 64 {
		return ""
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return s
}
