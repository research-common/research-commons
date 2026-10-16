// Package dag computes forks and their clearing over a graph of signed predecessor links. It is the one
// definition of "fork" and "cleared" (claims-model note I12): a key's log uses it with each line's `prev` as
// its branching link and `merges` as joining links (wire-format note §7); a resource uses it with each
// edition's `predecessors`, all branching (claims-model note §8). Neither caller re-implements it.
//
// A fork point is a node with two or more successors by branching links, or the empty id "" when two or
// more nodes have no held predecessor at all (two first lines). Joining links never create a fork point:
// naming a line in `merges` absorbs it, it does not continue from it (wire-format note §7).
//
// A fork at F clears at a node D when every node below F is an ancestor of D or a descendant of D: every
// branch has been brought into D and nothing below F escapes it. That is the note's "every tip at it is an
// ancestor of one line", read at the moment the clearing line is written, so a later, separate fork below D
// is reported as its own fork point and does not reopen F. Following one branch never clears: the clearing
// node has to name the others. Everything is a pure function of the node set, so delivery order cannot
// change an answer (I14).
package dag

import (
	"slices"
	"strings"
)

// Node is one node's links. Branch links can create a fork at the target; Join links only absorb it.
type Node struct {
	Branch []string
	Join   []string
}

// Fork is one fork point and what became of it.
type Fork struct {
	// At is the node the branches share as predecessor; "" for two or more roots.
	At string
	// Branches are At's successors by branching links, sorted.
	Branches []string
	// Tips are the nodes below At with no successor, sorted.
	Tips []string
	// ClearedBy is the earliest node at which the fork clears; "" while it has not.
	ClearedBy string
}

// Cleared reports whether the fork has cleared.
func (f Fork) Cleared() bool { return f.ClearedBy != "" }

// Forks returns every fork point of the graph, sorted by At. A link to a node that is not a key of g is
// ignored (the caller passes only nodes it holds).
func Forks(g map[string]Node) []Fork {
	g = reduce(g)
	branchSucc := map[string][]string{} // fork structure
	succ := map[string][]string{}       // reachability, every link
	for n, nd := range g {
		root := true
		for _, p := range nd.Branch {
			branchSucc[p] = append(branchSucc[p], n)
			succ[p] = append(succ[p], n)
			root = false
		}
		for _, p := range nd.Join {
			succ[p] = append(succ[p], n)
			root = false
		}
		if root {
			branchSucc[""] = append(branchSucc[""], n)
		}
	}
	var out []Fork
	for at, bs := range branchSucc {
		bs = dedupe(bs)
		if len(bs) < 2 {
			continue
		}
		f := Fork{At: at, Branches: bs}
		below := map[string]bool{}
		for _, b := range bs {
			for n := range descendants(b, succ) {
				below[n] = true
			}
		}
		for n := range below {
			if len(succ[n]) == 0 {
				f.Tips = append(f.Tips, n)
			}
		}
		slices.Sort(f.Tips)
		f.ClearedBy = convergence(below, g, succ)
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b Fork) int { return strings.Compare(a.At, b.At) })
	return out
}

// convergence returns the earliest node D in below such that every node in below is D, an ancestor of D or
// a descendant of D; "" if there is none. Two such nodes are always ancestor and descendant of each other,
// so the earliest is unique.
func convergence(below map[string]bool, g map[string]Node, succ map[string][]string) string {
	best := ""
	bestAnc := 0
	for d := range below {
		anc := ancestors(d, g)
		desc := descendants(d, succ)
		ok := true
		for n := range below {
			if !anc[n] && !desc[n] {
				ok = false
				break
			}
		}
		// the earliest candidate has the fewest ancestors; ties cannot happen between distinct candidates
		if ok && (best == "" || len(anc) < bestAnc) {
			best, bestAnc = d, len(anc)
		}
	}
	return best
}

// Tips returns every node with no successor by any link, sorted: the heads of the graph.
func Tips(g map[string]Node) []string {
	hasSucc := map[string]bool{}
	for _, nd := range g {
		for _, p := range nd.Branch {
			hasSucc[p] = true
		}
		for _, p := range nd.Join {
			hasSucc[p] = true
		}
	}
	var out []string
	for n := range g {
		if !hasSucc[n] {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// reduce keeps only held links, and drops from each node any link (branch or join) to a node that is an
// ancestor of another of its link targets: such a link adds no history (a line whose `merges` names an
// ancestor of its own `prev`, an edition naming a predecessor and that predecessor's ancestor), and as a
// branching link it would report a fork point that clears the moment it appears.
func reduce(g map[string]Node) map[string]Node {
	held := func(ps []string) []string {
		var out []string
		for _, p := range ps {
			if _, ok := g[p]; ok {
				out = append(out, p)
			}
		}
		return out
	}
	h := make(map[string]Node, len(g))
	for n, nd := range g {
		h[n] = Node{Branch: held(nd.Branch), Join: held(nd.Join)}
	}
	out := make(map[string]Node, len(h))
	for n, nd := range h {
		targets := append(slices.Clone(nd.Branch), nd.Join...)
		if len(targets) < 2 {
			out[n] = nd
			continue
		}
		implied := func(p string) bool {
			for _, q := range targets {
				if q != p && ancestors(q, h)[p] {
					return true
				}
			}
			return false
		}
		var r Node
		for _, p := range nd.Branch {
			if !implied(p) {
				r.Branch = append(r.Branch, p)
			}
		}
		for _, p := range nd.Join {
			if !implied(p) {
				r.Join = append(r.Join, p)
			}
		}
		out[n] = r
	}
	return out
}

// ancestors returns every held node reachable from n through any link, n excluded.
func ancestors(n string, g map[string]Node) map[string]bool {
	seen := map[string]bool{}
	stack := append(slices.Clone(g[n].Branch), g[n].Join...)
	for len(stack) > 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[x] {
			continue
		}
		if _, held := g[x]; !held {
			continue
		}
		seen[x] = true
		stack = append(stack, g[x].Branch...)
		stack = append(stack, g[x].Join...)
	}
	return seen
}

// descendants returns n and every node reachable from it through successor links.
func descendants(n string, succ map[string][]string) map[string]bool {
	seen := map[string]bool{n: true}
	stack := []string{n}
	for len(stack) > 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, s := range succ[x] {
			if !seen[s] {
				seen[s] = true
				stack = append(stack, s)
			}
		}
	}
	return seen
}

func dedupe(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}
