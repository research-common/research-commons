package identitymodel

// The recoverable-root profile (recoverable-root note §5). An identity's inception commits to a recovery key; a
// recovery takes that key and the current root, names the root's last good line and a successor root, and the
// identity id does not change. The reader evaluates generation by generation: at generation g with root R, pin D
// (R's seq-0 line on the identity) and commitment K, it judges every handover R signed for the identity, in the
// order §5 step 1 fixes (the commitment first, so a holder of R alone can only make void handovers), takes the
// distinct effects of the complete ones, and either stops (none: g is current), retires the identity for good
// (more than one: rivals), or follows the one effect to generation g+1 with the kept prefix of R's log.
//
// A fixed-root identity has one generation and no handovers, so the same code reads both profiles.

// generation is one root's turn as the identity's root.
type generation struct {
	root       Key
	pin        ID     // the root's seq-0 line on this identity: the inception, or the successor's succession
	commitment string // the recovery commitment in force
	handover   ID     // the complete handover that ended this generation; "" for the current one
	lastGood   ID     // with handover: the kept prefix's head; "" keeps only pin
	keep       map[ID]bool
}

// effect is what a complete recovery does. Two complete handovers of one root whose effects differ are rivals
// (rule 5); the same effect twice is one recovery (RR-07).
type effect struct {
	successor ID
	lastGood  ID
	next      string
}

// generations is the chain read for one identity.
type generations struct {
	profile Profile
	gens    []generation
	closed  bool // the last generation ended with a recovery naming no successor
	settled bool // the chain was read to its end: no unresolved handover, no rivals, no cap
	roots   map[Key]bool
}

// isRoot reports whether key is or was a root of the identity, as far as the chain was read.
func (g generations) isRoot(key Key) bool { return g.roots[key] }

// current is the generation whose root administers the identity now: nil when the identity is closed, or when
// the chain could not be read to its end.
func (g generations) current() *generation {
	if g.closed || !g.settled || len(g.gens) == 0 {
		return nil
	}
	return &g.gens[len(g.gens)-1]
}

// identityGenerations reads the inception's profile and, for a recoverable root, walks the generations, adding
// to the evaluation what it finds. rootHeld false gives an empty chain: the reasons were added by the caller.
func (s *Snapshot) identityGenerations(e *evaluation, root Fact, rootHeld bool) generations {
	gens := generations{roots: map[Key]bool{}}
	if !rootHeld {
		return gens
	}
	if root.Event != IdentityInception || root.Inception == nil || root.Seq != 0 {
		e.add("invalid_identity_inception", Denied, root.ID, "", "identity must pin the root's own inception")
		return gens
	}
	gens.profile = root.Inception.Profile
	gens.roots[root.Signer] = true
	first := generation{root: root.Signer, pin: root.ID, commitment: root.Inception.Commitment}
	switch root.Inception.Profile {
	case FixedRoot:
		gens.gens, gens.settled = []generation{first}, true
		return gens
	case RecoverableRoot:
		if root.Inception.Commitment == "" {
			e.add("invalid_identity_inception", Denied, root.ID, "", "a recoverable-root inception commits to a recovery key")
			return gens
		}
	default:
		e.add("unsupported_identity_profile", Unknown, root.ID, "", "no profile or root migration")
		return gens
	}
	if root.Authentication != Authenticated {
		gens.gens = []generation{first}
		return gens // the caller's authentication reason stands; no root scan follows an unproven root
	}
	used := map[string]bool{first.commitment: true}
	cur := first
	for {
		if len(gens.gens) > e.w.b.lim.Generations {
			panic(limitHit{LimitGenerations, e.w.b.lim.Generations})
		}
		effects := map[effect]ID{}
		var order []effect
		unresolved := false
		for _, id := range s.bySigner[cur.root] {
			f, _ := e.w.b.read(s, id)
			if f.Event != HandoverEvent || f.Handover == nil || f.Handover.Identity != root.ID {
				continue
			}
			e.basis[id] = true
			v := s.judgeHandover(e, &cur, f, root.ID, used, gens.roots)
			switch v.status {
			case Denied: // void: reported, changes nothing
				e.result.Warnings = append(e.result.Warnings, Warning{"void_handover", id, v.why})
			case Unknown:
				unresolved = true
				e.add("recovery_unresolved", Unknown, id, v.related, v.why)
			default:
				if _, seen := effects[v.eff]; !seen {
					effects[v.eff] = id
					order = append(order, v.eff)
				}
			}
		}
		if len(effects) > 1 {
			for _, eff := range order {
				e.add("retired_for_good", Denied, effects[eff], root.ID, "two complete recoveries of this root differ: the identity is retired for good (rule 5)")
			}
			gens.gens = append(gens.gens, cur)
			return gens
		}
		if unresolved {
			gens.gens = append(gens.gens, cur)
			return gens
		}
		if len(effects) == 0 {
			gens.gens = append(gens.gens, cur)
			gens.settled = true
			return gens
		}
		eff := order[0]
		cur.handover, cur.lastGood = effects[eff], eff.lastGood
		cur.keep = s.keptPrefix(e, cur)
		e.result.Recoveries = append(e.result.Recoveries, cur.handover)
		gens.gens = append(gens.gens, cur)
		if eff.successor == "" {
			gens.closed, gens.settled = true, true
			return gens
		}
		used[eff.next] = true
		succ, _ := e.w.b.read(s, eff.successor) // held: judgeHandover read it
		gens.roots[succ.Signer] = true
		cur = generation{root: succ.Signer, pin: succ.ID, commitment: eff.next}
	}
}

// verdict is one handover's judgement: Denied is void, Unknown is unresolved, Eligible is complete with eff.
type verdict struct {
	status  Status
	eff     effect
	why     string
	related ID
}

func void(why string) verdict { return verdict{status: Denied, why: why} }

// judgeHandover applies §5 step 1 to one handover of the generation's root, in its order: (a) the carried
// statement's commitment against the one in force, (b) its algorithm, (c) its validity as this identity's
// identity_recovery at seq 0, (d) its signer against the identity's roots and its own successor; then the "also
// void" list: the successor (a fresh key, not a root, not a committed recovery key, with its succession held), the
// next commitment (unused), and the kept prefix (a line of this root's lineage holding no key event and no line
// outside the vocabulary).
func (s *Snapshot) judgeHandover(e *evaluation, cur *generation, f Fact, identity ID, used map[string]bool, roots map[Key]bool) verdict {
	if f.Validity != Understood || len(shapeReasons(f)) != 0 {
		return void("handover not understood")
	}
	c := f.Handover.Carried
	if c.Commitment == "" || c.Commitment != cur.commitment {
		return void("carried statement is not by the committed recovery key")
	}
	if c.Authentication == Unproven {
		return verdict{status: Unknown, related: c.ID, why: "carried statement's algorithm is not supported by this reader"}
	}
	if c.Authentication != Authenticated || c.Validity != Understood || c.Event != RecoveryEvent || c.Recovery == nil ||
		c.Seq != 0 || c.Prev != "" || len(c.Merges) != 0 || c.Recovery.Identity != identity {
		return void("carried statement is not a valid identity_recovery for this identity at seq 0")
	}
	r := c.Recovery
	if c.Signer == "" || roots[c.Signer] || (r.Successor != nil && r.Successor.Key == c.Signer) {
		return void("the recovery key is no root of the identity (RR-30)")
	}
	if (r.Successor == nil) != (r.Next == "") {
		return void("a successor and a next commitment go together")
	}
	var succID ID
	if sc := r.Successor; sc != nil {
		if sc.Key == "" || sc.Inception == "" || sc.Commitment == "" {
			return void("successor is not fully named")
		}
		if used[r.Next] {
			return void("the next commitment repeats one the identity has used (RR-15)")
		}
		if roots[sc.Key] {
			return void("a key is an identity's root at most once (RR-26)")
		}
		if used[sc.Commitment] || sc.Commitment == r.Next {
			return void("a key the identity has committed to as a recovery key never becomes its root (RR-31)")
		}
		sf, ok := e.w.b.read(s, sc.Inception)
		if !ok {
			e.result.Dependencies = append(e.result.Dependencies, Dependency{sc.Inception, f.ID, "successor's first line"})
			return verdict{status: Unknown, related: sc.Inception, why: "the successor's first line is not held"}
		}
		e.basis[sf.ID] = true
		if sf.Authentication != Authenticated || sf.Validity != Understood || sf.Event != SuccessionEvent || sf.Succession == nil ||
			sf.Seq != 0 || sf.Prev != "" || len(sf.Merges) != 0 || sf.Signer != sc.Key || sf.Succession.Identity != identity {
			return void("the successor's first line is not its identity_succession for this identity")
		}
		succID = sf.ID
	}
	if r.LastGood != "" {
		if e.w.rootRelation(r.LastGood, cur.root, cur.pin) == outside {
			return void("last_good is a line of another key or another lineage")
		}
		switch e.w.closure(r.LastGood, cur.root, cur.pin).status {
		case Denied:
			return void("last_good's ancestry on this root's lineage is invalid")
		case Unknown:
			p := e.w.chain(r.LastGood, cur.root, cur.pin, "kept prefix")
			e.proof(p)
			return verdict{status: Unknown, related: r.LastGood, why: "the last good line or an ancestor of it is not held"}
		}
		e.proof(e.w.chain(r.LastGood, cur.root, cur.pin, "kept prefix"))
		probe := generation{root: cur.root, pin: cur.pin, lastGood: r.LastGood}
		for id := range s.keptPrefix(e, probe) {
			if id == cur.pin {
				continue
			}
			pf := s.facts[id]
			switch {
			case pf.Event == RotateKey || pf.Event == RevokeKey:
				return void("the kept prefix holds a raw key event of the root (RR-19)")
			case pf.Validity == Understood && !InProfileRootVocabulary(RecoverableRoot, pf.Event):
				return void("the kept prefix holds a root line outside the closed vocabulary (RR-25)")
			}
		}
	}
	return verdict{status: Eligible, eff: effect{successor: succID, lastGood: r.LastGood, next: r.Next}}
}

// keptPrefix is the set of ids a replaced root's recovery keeps: its last good line and that line's exact
// inclusive prev+merges closure, plus the pin (recoverable-root note §5 step 3). With no last good line only the
// pin is kept (RR-18). It walks the memoized closure, so it costs the prefix's size once per generation.
func (s *Snapshot) keptPrefix(e *evaluation, g generation) map[ID]bool {
	keep := map[ID]bool{g.pin: true}
	if g.lastGood == "" {
		return keep
	}
	w := e.w
	w.closure(g.lastGood, g.root, g.pin)
	m := w.memo(g.root, g.pin)
	todo := []ID{g.lastGood}
	for len(todo) > 0 {
		id := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if keep[id] {
			continue
		}
		w.b.inspect()
		n := m.nodes[id]
		if n == nil || !n.held {
			continue
		}
		keep[id] = true
		todo = append(todo, n.children...)
	}
	return keep
}

// placeGrant checks a grant's place on the identity: it is a line of one of the identity's roots, chained to that
// root's seq-0 line on the identity; and if that root was replaced, it lies in the kept prefix of its recovery,
// else it is void (recovery_voided, RR-02, RR-17b, RR-29). A grant by a key that was never a root fails the
// lineage check against the first root, as a fixed-root grant does.
func (s *Snapshot) placeGrant(e *evaluation, gens generations, g Fact) {
	if len(gens.gens) == 0 {
		return
	}
	e.result.Generation = uint64(len(gens.gens) - 1)
	e.result.Closed = gens.closed
	for _, gen := range gens.gens {
		if gen.root != g.Signer {
			continue
		}
		e.proof(e.w.chain(g.ID, gen.root, gen.pin, "grant root ancestry"))
		if gen.handover != "" && !gen.keep[g.ID] {
			e.add("recovery_voided", Denied, g.ID, gen.handover, "the grant is outside the kept prefix of a root a recovery replaced")
		}
		return
	}
	first := gens.gens[0]
	e.proof(e.w.chain(g.ID, first.root, first.pin, "grant root ancestry"))
}

// rootScans runs the root scan for every generation read: replaced roots over their kept prefixes (cuts only),
// the current root over its whole lineage. A chain that could not be settled scans what was read, so a definite
// denial found there still reports; the unresolved or rival reasons already make the result non-passing.
func (s *Snapshot) rootScans(e *evaluation, gens generations, actor Actor, grant *Grant) {
	for i, gen := range gens.gens {
		pin, ok := e.w.b.read(s, gen.pin)
		if !ok || pin.Authentication != Authenticated {
			continue
		}
		if gen.handover != "" {
			s.rootState(e, pin, actor, grant, gens.profile, gen.keep)
			continue
		}
		if i == len(gens.gens)-1 {
			s.rootState(e, pin, actor, grant, gens.profile, nil)
		}
	}
}
