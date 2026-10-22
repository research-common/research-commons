package identitymodel

// proof is local to one request; its set is the exact inclusive prev+merges
// closure. No global key eligibility or self-revocation filter participates.
type proof struct {
	ids     map[ID]bool
	reasons []Reason
	deps    []Dependency
}

func (p *proof) add(code string, status Status, id, related ID, detail string) {
	p.reasons = append(p.reasons, Reason{code, status, id, related, detail})
}

func (p proof) status() Status {
	status := Eligible
	for _, r := range p.reasons {
		status = combine(status, r.Status)
	}
	return status
}

func authenticationReasons(f Fact) []Reason {
	switch f.Authentication {
	case Authenticated:
		return nil
	case RejectedSignature:
		return []Reason{{Code: "signature_rejected", Status: Denied, Statement: f.ID}}
	default:
		return []Reason{{Code: "authentication_unproven", Status: Unknown, Statement: f.ID}}
	}
}

func validityReasons(f Fact) []Reason {
	switch f.Validity {
	case Understood:
		return nil
	case Invalid:
		return []Reason{{Code: "invalid_evidence", Status: Denied, Statement: f.ID}}
	default:
		return []Reason{{Code: "unsupported_evidence", Status: Unknown, Statement: f.ID}}
	}
}

// chain verifies the model's local link rules rather than trusting an opaque
// "chained" boolean. The adapter still owns cryptography, time coherence, format
// constraints and authenticated extraction of every field.
func (s *Snapshot) chain(head ID, key Key, pin ID, purpose string) proof {
	p := proof{ids: map[ID]bool{}}
	type edge struct{ id, from ID }
	todo := []edge{{head, head}}
	seen := map[ID]bool{}
	for len(todo) > 0 {
		next := todo[len(todo)-1]
		id := next.id
		todo = todo[:len(todo)-1]
		if seen[id] {
			continue
		}
		if len(seen) >= MaxTraversalFacts {
			p.add("model_limit", Unknown, head, id, purpose+": ancestry walk limit; no partial pass")
			break
		}
		seen[id] = true
		f, ok := s.facts[id]
		if !ok {
			p.add("missing_evidence", Unknown, next.from, id, purpose)
			p.deps = append(p.deps, Dependency{id, next.from, purpose})
			continue
		}
		p.ids[id] = true
		p.reasons = append(p.reasons, authenticationReasons(f)...)
		if f.Authentication != Authenticated {
			continue // Unauthenticated links are not lineage facts.
		}
		if f.Signer != key || key == "" {
			p.add("wrong_signer", Denied, id, head, purpose)
			continue
		}
		if f.Validity == Invalid {
			p.add("invalid_ancestry", Denied, id, head, purpose)
		} else if f.Validity == Unchecked || f.Validity > Invalid {
			p.add("unchecked_ancestry", Unknown, id, head, purpose)
		}
		if f.Seq == 0 {
			if f.Prev != "" || len(f.Merges) != 0 {
				p.add("invalid_inception_links", Denied, id, pin, purpose)
			}
			if id != pin {
				p.add("wrong_lineage", Denied, id, pin, purpose)
			}
			continue
		}
		if f.Prev == "" {
			p.add("missing_prev_field", Denied, id, "", purpose)
		} else {
			if prev, ok := s.facts[f.Prev]; ok && (prev.Seq >= f.Seq || prev.Seq != f.Seq-1) {
				p.add("invalid_prev_sequence", Denied, id, f.Prev, purpose)
			}
			todo = append(todo, edge{f.Prev, id})
		}
		seen := map[ID]bool{f.Prev: true}
		for _, m := range f.Merges {
			if m == "" || seen[m] {
				p.add("invalid_merge", Denied, id, m, purpose)
			}
			seen[m] = true
			if merged, ok := s.facts[m]; ok && merged.Seq >= f.Seq {
				p.add("invalid_merge_sequence", Denied, id, m, purpose)
			}
			todo = append(todo, edge{m, id})
		}
	}
	return p
}

type relation uint8

const (
	unresolved relation = iota
	inside
	outside
)

// rootRelation follows authenticated prev edges only. A conclusive rival
// inception excludes an event; a claimed Identity field never overrides this.
// Merges must still be validated by chain and cannot adopt another inception.
func (s *Snapshot) rootRelation(head ID, key Key, pin ID) relation {
	seen := map[ID]bool{}
	for !seen[head] {
		if len(seen) >= MaxTraversalFacts {
			return unresolved
		}
		seen[head] = true
		f, ok := s.facts[head]
		if !ok || f.Authentication != Authenticated || f.Signer != key {
			return unresolved
		}
		if f.Seq == 0 {
			if f.Prev != "" || len(f.Merges) != 0 {
				return unresolved
			}
			if f.ID == pin {
				return inside
			}
			return outside
		}
		prev, ok := s.facts[f.Prev]
		if !ok || prev.Seq >= f.Seq || prev.Seq != f.Seq-1 {
			return unresolved
		}
		head = f.Prev
	}
	return unresolved
}
