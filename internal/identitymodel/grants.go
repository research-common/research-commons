package identitymodel

import "slices"

// Grant-level status (profile §4.1, "requirements on consumers"): every view of a delegate key shows, beside the
// key's bare-key status, each grant naming it with its state: open, cut at L, cut null or unknown. This is that
// second axis. It is computed by the same root scan as an act's evaluation (rootState), so a grant reads `open`
// exactly when an act under it would meet no root-side denial or uncertainty, and a cut is classified by the
// same rules (attributable, effective, addressed to this grant on this identity's lineage).
//
// It answers about the grant, never about an act: whether one act counts still depends on its own ancestry, its
// scope, its binding and (for a cut at L) whether it is in L's closure. That is Evaluate's question.

// GrantStatus is the grant-level state.
type GrantStatus string

const (
	// GrantOpen: the grant is valid on the identity's lineage and no cut addressed to it is held.
	GrantOpen GrantStatus = "open"
	// GrantCutAt: an effective cut keeps the delegate's acts through last_good (LastGood lists each such L).
	GrantCutAt GrantStatus = "cut at last_good"
	// GrantCutNull: an effective cut with last_good null: no act under the grant counts.
	GrantCutNull GrantStatus = "cut null"
	// GrantUnknown: the held evidence cannot establish the grant's state (missing or unsupported evidence,
	// unresolved root ancestry, a cap).
	GrantUnknown GrantStatus = "unknown"
	// GrantDenied: the held evidence shows no act under the grant can count (the root retired, the grant or a cut
	// addressed to it is invalid); the reasons name why.
	GrantDenied GrantStatus = "denied"
)

// GrantState is the grant-level answer.
type GrantState struct {
	Grant    ID
	Identity ID  // the identity the grant names ("" when not readable)
	Delegate Key // the key the grant names
	Status   GrantStatus
	LastGood []ID // for GrantCutAt: the last_good of each effective cut at a line, sorted
	Cuts     []ID // every cut addressed to the grant on the identity's lineage (effective or not), sorted
	Basis    []ID
	Reasons  []Reason
	Warnings []Warning
	// Freshness is always NotEstablished: an omitted cut is indistinguishable from no cut (profile §1).
	Freshness        string
	EvidenceDigest   string
	EvaluatorVersion string
}

// GrantsTo lists every authenticated grant event naming delegate as its delegate key, in id order. A grant is the
// root's statement, so a delegate's grants are found by content, not by signer.
func (s *Snapshot) GrantsTo(delegate Key) []ID {
	var out []ID
	for _, id := range s.order {
		f := s.facts[id]
		if f.Authentication == Authenticated && f.Event == GrantEvent && f.Grant != nil && f.Grant.Delegate == delegate {
			out = append(out, id)
		}
	}
	return out
}

// GrantState is GrantStateWith under the profile's caps.
func (s *Snapshot) GrantState(grant ID) GrantState { return s.GrantStateWith(grant, DefaultLimits()) }

// GrantStateWith answers the grant-level state of grant under explicit caps (see Limits). Reaching a cap is
// GrantUnknown with a model_limit reason, never a partial `open`.
func (s *Snapshot) GrantStateWith(grant ID, lim Limits) (gs GrantState) {
	lim = lim.normalized()
	b := &budget{lim: lim, deps: map[ID]bool{}}
	var cuts []Fact
	e := evaluation{
		result: Result{Status: Eligible, Statement: grant, Grant: grant, EvidenceDigest: s.digest,
			EvaluatorVersion: EvaluatorVersion, Freshness: NotEstablished},
		basis: map[ID]bool{}, cuts: map[ID]bool{}, grantCuts: &cuts,
		w: &walker{s: s, b: b, lineages: map[lineageKey]*lineageMemo{}},
	}
	gs = GrantState{Grant: grant, Freshness: NotEstablished, EvidenceDigest: s.digest, EvaluatorVersion: EvaluatorVersion}
	finish := func(capped bool) GrantState {
		r := e.finish()
		gs.Basis, gs.Cuts, gs.Reasons, gs.Warnings = r.Basis, r.RelevantCuts, r.Reasons, r.Warnings
		slices.Sort(gs.LastGood)
		gs.LastGood = slices.Compact(gs.LastGood)
		gs.Status = grantStatus(r, capped, gs.LastGood)
		if gs.Status != GrantCutAt {
			gs.LastGood = nil
		}
		return gs
	}
	defer func() {
		if v := recover(); v != nil {
			hit, ok := v.(limitHit)
			if !ok {
				panic(v)
			}
			e.add("model_limit", Unknown, grant, "", hit.detail())
			gs = finish(true)
		}
	}()
	s.grantWithin(&e, &gs, &cuts)
	return finish(false)
}

// grantWithin is the grant part of evaluateWithin (the grant, its identity's inception, the delegate inception it
// pins, its permissions, the root scan) with the cuts collected and classified here.
func (s *Snapshot) grantWithin(e *evaluation, gs *GrantState, cuts *[]Fact) {
	g, ok := e.w.b.read(s, gs.Grant)
	if !ok {
		e.missing(gs.Grant, gs.Grant, "grant")
		return
	}
	e.basis[g.ID] = true
	e.reasons(authenticationReasons(g))
	e.reasons(validityReasons(g))
	e.reasons(shapeReasons(g))
	if g.Event != GrantEvent || g.Grant == nil {
		e.add("invalid_grant", Denied, g.ID, "", "not a grant event")
		return
	}
	grant := g.Grant
	gs.Identity, gs.Delegate = grant.Identity, grant.Delegate
	if grant.Identity == "" {
		e.add("wrong_grant_identity", Denied, g.ID, "", "the grant names no readable identity")
		return
	}
	if grant.Delegate == "" || grant.Inception == "" {
		e.add("wrong_delegate", Denied, g.ID, "", "grant pins a key and its exact inception")
	}
	if g.Validity == Understood {
		e.reasons(checkPermissions(grant.Permissions, g.ID))
	}
	if grant.Inception != "" && grant.Delegate != "" {
		if d, ok := e.w.b.read(s, grant.Inception); ok && d.Seq != 0 {
			e.add("delegate_pin_not_inception", Denied, g.ID, d.ID, "a head is not an inception")
		}
		e.proof(e.w.chain(grant.Inception, grant.Delegate, grant.Inception, "delegate inception"))
	}
	root, rootHeld := e.w.b.read(s, grant.Identity)
	if !rootHeld {
		e.missing(grant.Identity, g.ID, "identity inception")
		return
	}
	e.basis[root.ID] = true
	e.reasons(authenticationReasons(root))
	e.reasons(validityReasons(root))
	e.reasons(shapeReasons(root))
	if root.Event != IdentityInception || root.Inception == nil || root.Seq != 0 {
		e.add("invalid_identity_inception", Denied, root.ID, "", "identity must pin the root's own inception")
	} else if root.Inception.Profile != FixedRoot {
		e.add("unsupported_identity_profile", Unknown, root.ID, "", "no profile or root migration")
	}
	if grant.Delegate == root.Signer {
		e.add("root_is_delegate", Denied, g.ID, root.ID, "dedicated administrative root cannot be its worker")
	}
	e.proof(e.w.chain(root.ID, root.Signer, root.ID, "root inception"))
	e.proof(e.w.chain(g.ID, root.Signer, grant.Identity, "grant root ancestry"))
	if root.Authentication == Authenticated && root.Event == IdentityInception {
		s.rootState(e, root, Actor{Identity: grant.Identity, Grant: gs.Grant}, grant)
	}
	for _, f := range *cuts {
		s.classifyCut(e, gs, f, grant)
	}
	s.delegateWarnings(e, grant)
}

// classifyCut is applyCut at grant level: a null cut closes the grant; a cut at L is recorded with L once L's
// ancestry on the pinned delegate lineage is established; a malformed last_good denies as it does for every act.
func (s *Snapshot) classifyCut(e *evaluation, gs *GrantState, f Fact, grant *Grant) {
	last := f.Cut.LastGood
	switch last.Mode {
	case PreserveNone:
		if last.ID != "" {
			e.add("invalid_last_good", Denied, f.ID, last.ID, "null must not carry an ID")
			return
		}
		e.add("cut_null", Denied, gs.Grant, f.ID, "explicit null preserves nothing")
	case PreserveThrough:
		if last.ID == "" {
			e.add("invalid_last_good", Denied, f.ID, "", "last-good ID is required")
			return
		}
		if grant.Inception == "" || grant.Delegate == "" {
			e.add("cut_grant_unresolved", Unknown, f.ID, gs.Grant, "cannot validate the pinned delegate closure")
			return
		}
		p := e.w.chain(last.ID, grant.Delegate, grant.Inception, "cut last-good ancestry")
		for i := range p.deps {
			if p.deps[i].ID == last.ID && p.deps[i].NeededBy == last.ID {
				p.deps[i].NeededBy = f.ID
			}
		}
		e.proof(p)
		if p.closure == Eligible {
			gs.LastGood = append(gs.LastGood, last.ID)
		}
	default:
		e.add("invalid_last_good", Denied, f.ID, last.ID, "omitted/unknown last-good is not null or unlimited")
	}
}

// grantStatus folds the reasons into one state. A null cut closes the grant whatever else is uncertain (no act
// under it can count); otherwise any definite denial wins, then any uncertainty (a cap included); then a cut at a
// line; otherwise the grant is open.
func grantStatus(r Result, capped bool, lastGood []ID) GrantStatus {
	for _, x := range r.Reasons {
		if x.Code == "cut_null" {
			return GrantCutNull
		}
	}
	switch {
	case capped:
		return GrantUnknown
	case r.Status == Denied:
		return GrantDenied
	case r.Status == Unknown:
		return GrantUnknown
	case len(lastGood) > 0:
		return GrantCutAt
	}
	return GrantOpen
}
