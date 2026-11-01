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
func (p *Placed) BareKeyEligible() bool {
	return p.EvidenceReady() && len(p.After) == 0 && len(p.Doubted) == 0
}
