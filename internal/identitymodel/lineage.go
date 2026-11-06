package identitymodel

// proof is local to one request: the reasons, dependencies and held ids a walk
// contributes to the explanation, and the status of the head's exact inclusive
// prev+merges closure. No global key eligibility or self-revocation filter
// participates.
type proof struct {
	ids     map[ID]bool
	reasons []Reason
	deps    []Dependency
	closure Status
}

func (p *proof) add(code string, status Status, id, related ID, detail string) {
	p.reasons = append(p.reasons, Reason{code, status, id, related, detail})
}

func (p proof) status() Status { return p.closure }

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

func statusOf(rs []Reason) Status {
	status := Eligible
	for _, r := range rs {
		status = combine(status, r.Status)
	}
	return status
}

// lineageKey names one key's history pinned at one inception. Every closure fact
// depends only on (fact, key, pin), so per-query memos are keyed by it.
type lineageKey struct {
	key Key
	pin ID
}

// node is the memoized local view of one fact in one lineage. Its reasons are
// head-independent: a defect is reported against the fact and the lineage pin,
// never against whichever head happened to reach it first.
type node struct {
	held     bool
	reasons  []Reason // Local link-rule reasons; purpose is filled in on emission.
	children []ID     // prev, then sorted merges (duplicates kept: they are reported).
	status   Status   // Closure status: local reasons combined with every child's.
	height   int      // Longest prev/merge path below this fact, in edges.
	done     bool
}

type lineageMemo struct {
	nodes   map[ID]*node
	emitted map[string]map[ID]bool // purpose -> facts whose local reasons were emitted.
	reaches map[ID]map[ID]bool     // target -> fact -> target is in the fact's closure.
	place   map[ID]placement
}

type placement struct {
	rel  relation
	dist int // prev edges to the lineage's inception (or to the point placement failed).
}

// walker holds one query's budget and memos. It is never shared between queries.
type walker struct {
	s        *Snapshot
	b        *budget
	lineages map[lineageKey]*lineageMemo
}

func (w *walker) memo(key Key, pin ID) *lineageMemo {
	k := lineageKey{key, pin}
	m := w.lineages[k]
	if m == nil {
		m = &lineageMemo{nodes: map[ID]*node{}, emitted: map[string]map[ID]bool{},
			reaches: map[ID]map[ID]bool{}, place: map[ID]placement{}}
		w.lineages[k] = m
	}
	return m
}

// local verifies the model's link rules for one fact rather than trusting an
// opaque "chained" boolean. The adapter still owns cryptography, time coherence,
// format constraints and authenticated extraction of every field.
func (w *walker) local(id ID, key Key, pin ID) *node {
	f, ok := w.b.read(w.s, id)
	if !ok {
		return &node{status: Unknown}
	}
	n := &node{held: true}
	var p proof
	p.reasons = authenticationReasons(f)
	switch {
	case f.Authentication != Authenticated:
		// Unauthenticated links are not lineage facts.
	case f.Signer != key || key == "":
		p.add("wrong_signer", Denied, id, pin, "")
	default:
		if f.Validity == Invalid {
			p.add("invalid_ancestry", Denied, id, pin, "")
		} else if f.Validity == Unchecked || f.Validity > Invalid {
			p.add("unchecked_ancestry", Unknown, id, pin, "")
		}
		if f.Seq == 0 {
			if f.Prev != "" || len(f.Merges) != 0 {
				p.add("invalid_inception_links", Denied, id, pin, "")
			}
			if id != pin {
				p.add("wrong_lineage", Denied, id, pin, "")
			}
			break
		}
		if f.Prev == "" {
			p.add("missing_prev_field", Denied, id, "", "")
		} else {
			if prev, ok := w.b.read(w.s, f.Prev); ok && (prev.Seq >= f.Seq || prev.Seq != f.Seq-1) {
				p.add("invalid_prev_sequence", Denied, id, f.Prev, "")
			}
			n.children = append(n.children, f.Prev)
		}
		seen := map[ID]bool{f.Prev: true}
		for _, m := range f.Merges {
			if m == "" || seen[m] {
				p.add("invalid_merge", Denied, id, m, "")
			}
			seen[m] = true
			if merged, ok := w.b.read(w.s, m); ok && merged.Seq >= f.Seq {
				p.add("invalid_merge_sequence", Denied, id, m, "")
			}
			n.children = append(n.children, m)
		}
	}
	n.reasons = p.reasons
	n.status = statusOf(p.reasons)
	return n
}

// closure computes (once per lineage per query) the status and height of every
// fact in head's inclusive prev+merges closure. Iterative post-order, so a 100k
// linear history needs no deep recursion.
//
// A child still on the stack closes a cycle. Every link followed leaves an
// authenticated, in-key, seq>0 fact whose prev must be exactly seq-1 and whose
// merges must be lower, so a cycle always contains a locally denied link. The
// closing fact therefore takes Denied, which keeps every memoized status exact.
func (w *walker) closure(head ID, key Key, pin ID) *node {
	m := w.memo(key, pin)
	if n := m.nodes[head]; n != nil && n.done {
		w.b.inspect()
		return n
	}
	type frame struct {
		id   ID
		n    *node
		next int
	}
	onStack := map[ID]bool{}
	start := func(id ID) frame {
		n := w.local(id, key, pin)
		m.nodes[id] = n
		onStack[id] = true
		return frame{id: id, n: n}
	}
	stack := []frame{start(head)}
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		if top.next < len(top.n.children) {
			c := top.n.children[top.next]
			top.next++
			w.b.inspect()
			if onStack[c] {
				top.n.status = Denied
				continue
			}
			if cn := m.nodes[c]; cn != nil && cn.done {
				top.n.status = combine(top.n.status, cn.status)
				top.n.height = max(top.n.height, cn.height+1)
				w.b.path(top.n.height)
				continue
			}
			stack = append(stack, start(c))
			continue
		}
		n := top.n
		n.done = true
		delete(onStack, top.id)
		stack = stack[:len(stack)-1]
		if len(stack) > 0 {
			parent := stack[len(stack)-1].n
			parent.status = combine(parent.status, n.status)
			parent.height = max(parent.height, n.height+1)
			w.b.path(parent.height)
		}
	}
	return m.nodes[head]
}

// chain returns head's closure status plus the explanation not yet emitted for
// this lineage and purpose. Facts already emitted under the same purpose are not
// walked again, so the explanation for a long history is linear, not one copy of
// the whole ancestry per head. A missing head is always reported against itself.
func (w *walker) chain(head ID, key Key, pin ID, purpose string) proof {
	root := w.closure(head, key, pin)
	p := proof{ids: map[ID]bool{}, closure: root.status}
	m := w.memo(key, pin)
	emitted := m.emitted[purpose]
	if emitted == nil {
		emitted = map[ID]bool{}
		m.emitted[purpose] = emitted
	}
	missing := func(id, from ID) {
		p.add("missing_evidence", Unknown, from, id, purpose)
		p.deps = append(p.deps, Dependency{id, from, purpose})
	}
	if !root.held {
		missing(head, head)
		return p
	}
	todo := []ID{head}
	for len(todo) > 0 {
		id := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		w.b.inspect()
		if emitted[id] {
			continue
		}
		emitted[id] = true
		n := m.nodes[id]
		p.ids[id] = true
		for _, r := range n.reasons {
			if r.Detail == "" && r.Code != "authentication_unproven" && r.Code != "signature_rejected" {
				r.Detail = purpose
			}
			p.reasons = append(p.reasons, r)
		}
		for i := len(n.children) - 1; i >= 0; i-- {
			c := n.children[i]
			if cn := m.nodes[c]; cn != nil && !cn.held {
				missing(c, id)
				continue
			}
			todo = append(todo, c)
		}
	}
	return p
}

// contains reports whether target is in head's exact inclusive closure, memoized
// per lineage and target. Only called on an eligible closure, which is acyclic.
func (w *walker) contains(head, target ID, key Key, pin ID) bool {
	w.closure(head, key, pin)
	m := w.memo(key, pin)
	memo := m.reaches[target]
	if memo == nil {
		memo = map[ID]bool{}
		m.reaches[target] = memo
	}
	type frame struct {
		id   ID
		next int
	}
	visiting := map[ID]bool{}
	stack := []frame{{id: head}}
	visiting[head] = true
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		w.b.inspect()
		if _, ok := memo[top.id]; !ok && top.id == target {
			memo[top.id] = true
		}
		if v, ok := memo[top.id]; ok {
			stack = stack[:len(stack)-1]
			if len(stack) > 0 && v {
				memo[stack[len(stack)-1].id] = true
			}
			continue
		}
		n := m.nodes[top.id]
		if n == nil || !n.held || top.next >= len(n.children) {
			memo[top.id] = false
			continue
		}
		c := n.children[top.next]
		top.next++
		if v, ok := memo[c]; ok {
			if v {
				memo[top.id] = true
			}
			continue
		}
		if !visiting[c] {
			visiting[c] = true
			stack = append(stack, frame{id: c})
		}
	}
	return memo[head]
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
// Placements are memoized per lineage, so placing every event of a long history
// costs one walk, not one walk per event.
func (w *walker) rootRelation(head ID, key Key, pin ID) relation {
	m := w.memo(key, pin)
	var path []ID
	onPath := map[ID]bool{}
	result, hit := placement{rel: unresolved}, false
	for {
		if pl, ok := m.place[head]; ok {
			w.b.inspect()
			result, hit = pl, true
			break
		}
		if onPath[head] {
			break // A prev cycle never reaches an inception.
		}
		onPath[head] = true
		path = append(path, head)
		f, ok := w.b.read(w.s, head)
		if !ok || f.Authentication != Authenticated || f.Signer != key {
			break
		}
		if f.Seq == 0 {
			if f.Prev == "" && len(f.Merges) == 0 {
				result.rel = outside
				if f.ID == pin {
					result.rel = inside
				}
			}
			break
		}
		prev, ok := w.b.read(w.s, f.Prev)
		if !ok || prev.Seq >= f.Seq || prev.Seq != f.Seq-1 {
			break
		}
		head = f.Prev
	}
	// Every fact on the walked path inherits the result; its distance is the prev
	// edges between it and the point the result was established.
	offset := 0
	if hit {
		offset = 1
	}
	for i := len(path) - 1; i >= 0; i-- {
		pl := placement{rel: result.rel, dist: result.dist + offset + (len(path) - 1 - i)}
		w.b.path(pl.dist)
		m.place[path[i]] = pl
	}
	if len(path) == 0 {
		return result.rel
	}
	return m.place[path[0]].rel
}
