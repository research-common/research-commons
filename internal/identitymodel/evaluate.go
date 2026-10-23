package identitymodel

import (
	"slices"
	"strings"
)

type evaluation struct {
	result Result
	basis  map[ID]bool
	cuts   map[ID]bool
}

// Evaluate answers only: may this explicitly opted-in signature act for its
// named fixed-root identity/grant under this evidence? It does not evaluate bare
// key eligibility or operation-specific roles, state, amendments, time or policy.
// Bare statements are denied IDENTITY eligibility, not denied legacy eligibility.
func (s *Snapshot) Evaluate(statement ID) Result {
	e := evaluation{
		result: Result{Status: Eligible, Statement: statement, EvidenceDigest: s.digest,
			EvaluatorVersion: EvaluatorVersion, Freshness: NotEstablished},
		basis: map[ID]bool{}, cuts: map[ID]bool{},
	}
	st, ok := s.facts[statement]
	if !ok {
		e.missing(statement, statement, "statement")
		return e.finish()
	}
	e.basis[statement] = true
	e.result.Signer = st.Signer
	e.reasons(authenticationReasons(st))
	e.reasons(validityReasons(st))
	e.reasons(shapeReasons(st))
	if st.Actor == nil {
		e.result.Actor = Subject{Kind: KeySubject, Key: st.Signer}
		e.add("no_identity_actor", Denied, statement, "", "bare-key eligibility belongs to the unchanged legacy evaluator")
		return e.finish()
	}
	a := *st.Actor
	e.result.Actor = Subject{Kind: IdentitySubject, Identity: a.Identity}
	e.result.Grant, e.result.RootLineage = a.Grant, a.Identity
	if a.Identity == "" || a.Grant == "" {
		e.add("invalid_actor", Denied, statement, "", "identity and grant must both be explicit")
		return e.finish()
	}
	switch st.Binding {
	case BoundIdentityContext:
	case UnsupportedIdentityContext:
		e.add("unsupported_actor_binding", Unknown, statement, "", "no key fallback")
	default:
		e.add("invalid_actor_binding", Denied, statement, "", "actor requires authenticated understood critical context")
	}
	if st.Event != Data || st.Operation == nil {
		e.add("not_delegable_operation", Denied, statement, "", "administrative and raw key events do not act as identity operations")
	}
	root, rootHeld := s.facts[a.Identity]
	if !rootHeld {
		e.missing(a.Identity, statement, "identity inception")
	} else {
		e.basis[root.ID] = true
		e.reasons(authenticationReasons(root))
		e.reasons(validityReasons(root))
		e.reasons(shapeReasons(root))
		if root.Event != IdentityInception || root.Inception == nil || root.Seq != 0 {
			e.add("invalid_identity_inception", Denied, root.ID, "", "identity must pin the root's own inception")
		} else if root.Inception.Profile != FixedRoot {
			e.add("unsupported_identity_profile", Unknown, root.ID, "", "no profile or root migration")
		}
		e.proof(s.chain(root.ID, root.Signer, root.ID, "root inception"))
	}
	g, grantHeld := s.facts[a.Grant]
	var grant *Grant
	if !grantHeld {
		e.missing(a.Grant, statement, "grant")
	} else {
		e.basis[g.ID] = true
		e.reasons(authenticationReasons(g))
		e.reasons(validityReasons(g))
		e.reasons(shapeReasons(g))
		if g.Event != GrantEvent || g.Grant == nil {
			e.add("invalid_grant", Denied, g.ID, "", "actor must name an exact grant event")
		} else {
			grant = g.Grant
			e.result.DelegateInception = grant.Inception
			if grant.Identity != a.Identity {
				e.add("wrong_grant_identity", Denied, g.ID, a.Identity, "")
			}
			if grant.Delegate == "" || grant.Inception == "" || grant.Delegate != st.Signer {
				e.add("wrong_delegate", Denied, statement, g.ID, "grant pins a key and its exact inception")
			}
			if rootHeld && grant.Delegate == root.Signer {
				e.add("root_is_delegate", Denied, g.ID, root.ID, "dedicated administrative root cannot be its worker")
			}
			// Scope is read only from an understood grant: an unsupported grant is unknown (its validity
			// reason), never a definite scope denial built from the entries this reader happened to parse.
			if g.Validity == Understood {
				e.reasons(checkPermissions(grant.Permissions, g.ID))
			}
			if st.Operation != nil && g.Validity == Understood {
				_, reasons := scopeAllows(grant.Permissions, *st.Operation, st.Signer)
				for i := range reasons {
					reasons[i].Statement, reasons[i].Related = statement, g.ID
				}
				e.reasons(reasons)
			}
			if grant.Inception != "" {
				if d, ok := s.facts[grant.Inception]; ok && d.Seq != 0 {
					e.add("delegate_pin_not_inception", Denied, g.ID, d.ID, "a head is not an inception")
				}
				e.proof(s.chain(grant.Inception, grant.Delegate, grant.Inception, "delegate inception"))
				e.proof(s.chain(statement, grant.Delegate, grant.Inception, "statement ancestry"))
			}
		}
		if rootHeld {
			e.proof(s.chain(g.ID, root.Signer, a.Identity, "grant root ancestry"))
		}
	}
	// Only authenticated issuer evidence can create uncertainty for an identity.
	// Arbitrary caller affiliation strings and forged root signer claims are ignored.
	if rootHeld && root.Authentication == Authenticated && root.Event == IdentityInception {
		s.rootState(&e, root, a, grant)
	}
	if grant != nil {
		s.delegateWarnings(&e, grant)
	}
	return e.finish()
}

func (s *Snapshot) rootState(e *evaluation, root Fact, actor Actor, grant *Grant) {
	relevant := 0
	for _, id := range s.order {
		f := s.facts[id]
		if f.ID == root.ID || f.Signer != root.Signer || f.Authentication != Authenticated {
			continue
		}
		rel := s.rootRelation(id, root.Signer, root.ID)
		if rel == outside {
			continue // A rival inception never retires or administers this identity.
		}
		relevant++
		if relevant > MaxTraversalFacts {
			e.add("model_limit", Unknown, root.ID, "", "relevant authenticated root-event limit; no partial pass")
			break
		}
		p := s.chain(id, root.Signer, root.ID, "root event ancestry")
		if rel == inside && (f.Event == RotateKey || f.Event == RevokeKey) && f.Validity == Understood && len(shapeReasons(f)) == 0 {
			// Terminal irrespective of reason, last_good, successor or branch (profile §3), and therefore also
			// irrespective of defects in its merges or earlier lines: its prev lineage alone places it on I.
			// Otherwise a compromised root could plant one bad tip and void the owner's fork-clearing revoke.
			e.basis[id] = true
			e.proof(p) // moot for the status, kept so the explanation shows any ancestry defect
			e.add("root_retired", Denied, id, root.ID, "terminal in-lineage root event; never follow a successor")
			continue
		}
		// A cut is addressed by its grant; a grant belongs to exactly one identity. A cut on I's lineage that
		// names this grant under another identity is an invalid cut addressed to G, never "for another grant".
		targetCut := f.Event == CutEvent && f.Cut != nil && f.Cut.Grant == actor.Grant
		if rel == unresolved || p.status() == Unknown {
			e.add("unresolved_root_ancestry", Unknown, id, root.ID, "authenticated root evidence; relationship or complete ancestry unresolved")
			e.proof(p)
			if targetCut {
				e.cuts[id] = true
			}
			continue
		}
		if targetCut {
			e.cuts[id] = true
			e.proof(p)
			e.reasons(validityReasons(f))
			e.reasons(shapeReasons(f))
			if f.Cut.Identity != actor.Identity {
				e.add("wrong_cut_identity", Denied, id, actor.Identity, "cut names this grant under another or unreadable identity")
				continue
			}
			if p.status() != Eligible || f.Validity != Understood || len(shapeReasons(f)) != 0 {
				continue // Invalid attributable cuts are non-passing, not omitted.
			}
			s.applyCut(e, f, grant)
			continue
		}
		if f.Event == GrantEvent && f.Grant != nil && (f.Validity == Unsupported || f.Validity == Unchecked) {
			// Grants only accumulate and never restrict each other, and fixed-root-v1 permission kinds are leaf
			// operations only (anything administrative needs a new inception profile, which reads unknown). So an
			// identifiable grant this reader cannot understand affects that grant alone; the actor's own grant
			// is judged above by its validity reasons.
			if id != actor.Grant {
				e.basis[id] = true
				e.result.Warnings = append(e.result.Warnings, Warning{"unsupported_sibling_grant", id, "another grant of this identity is not understood; it does not affect this grant"})
			}
			continue
		}
		if f.Validity == Unsupported || f.Validity == Unchecked || f.Validity > Invalid {
			e.proof(p)
			e.add("unsupported_root_event", Unknown, id, root.ID, "authenticated in-lineage event is not understood")
			continue
		}
		if f.Event == CutEvent && (f.Cut == nil || f.Cut.Grant == "") {
			e.proof(p)
			e.add("unaddressable_root_cut", Unknown, id, root.ID, "cannot establish affected grant")
			continue
		}
		switch f.Event {
		case GrantEvent, Inert, CutEvent, RotateKey, RevokeKey:
		default:
			// Vocabulary before ancestry: an event outside the closed root vocabulary is uncertainty whatever its
			// ancestry; a defect in that ancestry must never turn unknown into a silent warning.
			e.proof(p)
			e.add("unsupported_root_event", Unknown, id, root.ID, "not in the closed root vocabulary")
			continue
		}
		if p.status() != Eligible || f.Validity == Invalid || len(shapeReasons(f)) != 0 {
			// A conclusively invalid non-cut cannot retire a valid root (a valid terminal event was handled
			// above, whatever its ancestry). Report it without turning an invalid sibling grant into a
			// replacement state.
			e.basis[id] = true
			e.result.Warnings = append(e.result.Warnings, Warning{"invalid_root_event", id, "not an effective root operation"})
			continue
		}
		e.proof(p)
		switch f.Event {
		case RotateKey, RevokeKey:
			e.add("root_retired", Denied, id, root.ID, "terminal in-lineage root event; never follow a successor")
		case GrantEvent, Inert:
			// Independent grants coexist; recognized inert events change no authority.
		case CutEvent:
			// A fully addressed cut for another grant does not affect this one.
		default:
			e.add("unsupported_root_event", Unknown, id, root.ID, "not in the closed root vocabulary")
		}
	}
}

func (s *Snapshot) applyCut(e *evaluation, f Fact, grant *Grant) {
	last := f.Cut.LastGood
	switch last.Mode {
	case PreserveNone:
		if last.ID != "" {
			e.add("invalid_last_good", Denied, f.ID, last.ID, "null must not carry an ID")
			return
		}
		e.add("cut_excluded", Denied, e.result.Statement, f.ID, "explicit null preserves nothing")
	case PreserveThrough:
		if last.ID == "" {
			e.add("invalid_last_good", Denied, f.ID, "", "last-good ID is required")
			return
		}
		if grant == nil || grant.Inception == "" || grant.Delegate == "" {
			e.add("cut_grant_unresolved", Unknown, f.ID, e.result.Grant, "cannot validate the pinned delegate closure")
			return
		}
		p := s.chain(last.ID, grant.Delegate, grant.Inception, "cut last-good ancestry")
		for i := range p.deps {
			if p.deps[i].ID == last.ID && p.deps[i].NeededBy == last.ID {
				p.deps[i].NeededBy = f.ID
			}
		}
		e.proof(p)
		if p.status() == Eligible && !p.ids[e.result.Statement] {
			e.add("cut_excluded", Denied, e.result.Statement, f.ID, "not in this exact inclusive prev+merges closure")
		}
	default:
		e.add("invalid_last_good", Denied, f.ID, last.ID, "omitted/unknown last-good is not null or unlimited")
	}
}

func (s *Snapshot) delegateWarnings(e *evaluation, grant *Grant) {
	checked := 0
	for _, id := range s.order {
		f := s.facts[id]
		if f.Signer != grant.Delegate || f.Authentication != Authenticated || f.Validity != Understood ||
			(f.Event != RotateKey && f.Event != RevokeKey) {
			continue
		}
		// Warnings only, never authority: bound the per-query walk cost a delegate's own log can impose. Every
		// examined event costs walks, so the count includes events that turn out to be outside the inception.
		if checked++; checked > MaxDelegateSelfEvents {
			e.result.Warnings = append(e.result.Warnings, Warning{"delegate_self_event_limit", grant.Inception, "further delegate self-events not examined"})
			break
		}
		if s.rootRelation(id, grant.Delegate, grant.Inception) != inside {
			continue
		}
		if s.chain(id, grant.Delegate, grant.Inception, "delegate self-event").status() == Eligible {
			e.basis[id] = true
			e.result.Warnings = append(e.result.Warnings, Warning{"delegate_self_event", id, "does not close opted-in grants; bare-key effects belong to the legacy evaluator"})
		}
	}
}

func shapeReasons(f Fact) []Reason {
	valid := (f.Inception != nil) == (f.Event == IdentityInception) &&
		(f.Grant != nil) == (f.Event == GrantEvent) && (f.Cut != nil) == (f.Event == CutEvent) &&
		(f.Operation != nil) == (f.Event == Data)
	if f.Event != Data && (f.Actor != nil || f.Binding != NoIdentityContext) {
		valid = false
	}
	if !valid {
		return []Reason{{Code: "invalid_event_shape", Status: Denied, Statement: f.ID}}
	}
	return nil
}

func combine(a, b Status) Status {
	if a == Denied || b == Denied {
		return Denied
	}
	if a == Unknown || b == Unknown {
		return Unknown
	}
	return Eligible
}

func (e *evaluation) add(code string, status Status, statement, related ID, detail string) {
	e.reasons([]Reason{{code, status, statement, related, detail}})
}

func (e *evaluation) reasons(rs []Reason) {
	for _, r := range rs {
		e.result.Status = combine(e.result.Status, r.Status)
		e.result.Reasons = append(e.result.Reasons, r)
	}
}

func (e *evaluation) missing(id, from ID, purpose string) {
	e.add("missing_evidence", Unknown, from, id, purpose)
	e.result.Dependencies = append(e.result.Dependencies, Dependency{id, from, purpose})
}

func (e *evaluation) proof(p proof) {
	for id := range p.ids {
		e.basis[id] = true
	}
	e.reasons(p.reasons)
	e.result.Dependencies = append(e.result.Dependencies, p.deps...)
}

func (e *evaluation) finish() Result {
	for id := range e.basis {
		e.result.Basis = append(e.result.Basis, id)
	}
	for id := range e.cuts {
		e.result.RelevantCuts = append(e.result.RelevantCuts, id)
	}
	slices.Sort(e.result.Basis)
	slices.Sort(e.result.RelevantCuts)
	e.result.Reasons = sortedUnique(e.result.Reasons)
	e.result.Dependencies = sortedUnique(e.result.Dependencies)
	e.result.Warnings = sortedUnique(e.result.Warnings)
	return e.result
}

func sortedUnique[T comparable](items []T) []T {
	slices.SortFunc(items, func(a, b T) int {
		return strings.Compare(modelKey(a), modelKey(b))
	})
	return slices.Compact(items)
}
