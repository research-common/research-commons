package resolve

import (
	"slices"
)

// Structural coverage, for the writer's own preconditions (the anchor before transport, bitcoin-time note §2; the
// withheld bytes of claims-model note §7). These answer what the log says, never what was verified: an anchor
// covers a statement when it is in the log in the right place, whatever its proof's state, and a statement on an
// incoherent line is still covered (incoherence discards a bound, it does not un-cover the statement). Readers'
// answers never use them: priority and every time answer rest on bounds (time.go).

// CoveringAnchors lists, sorted, the anchors lines that cover the statement with this id: lines by the statement's
// own signer whose `covered` precedes the anchors line in the signer's log (bitcoin-time note §1 rule 3) and has the
// statement in its history through signed prev and merges (rule 2). A pending proof covers; a proof's state, its
// blob being held, and key events are not consulted. nil when the statement is not held or nothing covers it.
func (r *Resolver) CoveringAnchors(id string) []string {
	p, ok := r.byID[id]
	if !ok {
		return nil
	}
	signer := p.St.Signer
	var out []string
	for _, a := range r.byKind["anchors"] {
		if a.St.Signer != signer {
			continue
		}
		cov := str(a.St.Body, "covered")
		if cov == "" || !r.precedes(signer, cov, a.St.ID) || !closure(cov, r.chained[signer])[id] {
			continue
		}
		out = append(out, a.St.ID)
	}
	slices.Sort(out)
	return out
}

// WithheldBy lists, sorted, the authored and observed statements held for the blob with this digest whose
// availability declares redistribution withheld (claims-model note §7), counted or not: a declaration is the
// signer's commitment, and a sender who carries the bytes breaks it whatever a reader would count.
func (r *Resolver) WithheldBy(digest string) []string {
	var out []string
	for _, k := range []string{"authored", "observed"} {
		for _, p := range r.byKind[k] {
			if contentDigest(p.St.Body) != digest {
				continue
			}
			if str(object(p.St.Body, "availability"), "redistribution") == "withheld" {
				out = append(out, p.St.ID)
			}
		}
	}
	slices.Sort(out)
	return out
}

// Holders lists the keys whose current `holds` for the blob serves it (the reveal of a withheld artifact,
// claims-model note §7), sorted.
func (r *Resolver) Holders(digest string) []string { return r.holders(digest) }
