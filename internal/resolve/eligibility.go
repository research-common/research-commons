package resolve

// EvidenceReady reports whether this snapshot has verified, chained and understood
// the statement. It is the explicit accessor for Evaluable, not an authorization
// decision: the signer's key events do not erase authenticated evidence. A valid
// detached proposal can still be displayed, but is not ready evidence here.
func (p *Placed) EvidenceReady() bool { return p.Evaluable }

// BareKeyEligible reports whether ready evidence survives every in-force key event
// of its actual signer (the legacy intersection rule). It does not establish a
// controller role, an approval threshold, identity authority or trust. This is only
// the existing bare-key counting gate, not a fallback for unsupported evidence.
//
// An identity-context statement (IdentityContext) is never bare-key eligible, whatever its signer's key events:
// its signature acts for the identity its actor names, so only an actor evaluator can make it count (through the
// counting gate), and without one it is never a key's evidence (identity profile §2.3: "never a key fallback").
func (p *Placed) BareKeyEligible() bool {
	return p.keyEventsClear() && !p.IdentityContext()
}

// keyEventsClear is the legacy intersection rule alone: ready evidence that survives every in-force key event of
// its signer. For a bare-key statement it is BareKeyEligible; for an identity-context statement it is the bare-key
// status shown beside an identity answer, never applied as a filter.
func (p *Placed) keyEventsClear() bool {
	return p.EvidenceReady() && len(p.After) == 0 && len(p.Doubted) == 0
}

// IdentityContext reports whether the statement carries a signed identity actor that its reader read: an rc/2
// line read by the candidate dual-major reader with an `x_actor_v1`. The default reader never reads one (it
// retains rc/2 unverified, and an rc/1 envelope actor is not read), so with it this is always false. An rc/2
// line with the marker and no actor is not identity context: it is a `key(K)` statement on an identity-aware
// body and keeps the bare-key gate.
func (p *Placed) IdentityContext() bool { return p.St != nil && p.St.Actor != nil }
