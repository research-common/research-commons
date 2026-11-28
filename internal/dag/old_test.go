package dag

// The implementation this package had before reachability was batched (#291), kept verbatim (names prefixed
// with old) as the reference the differential test holds the new one to.

import (
	"slices"
	"strings"
)

// Forks returns every fork point of the graph, sorted by At. A link to a node that is not a key of g is
// ignored (the caller passes only nodes it holds).
func oldForks(g map[string]Node) []Fork {
	g = oldReduce(g)
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
		bs = oldDedupe(bs)
		if len(bs) < 2 {
			continue
		}
		f := Fork{At: at, Branches: bs}
		below := oldBelowOf(bs, succ)
		for n := range below {
			if len(succ[n]) == 0 {
				f.Tips = append(f.Tips, n)
			}
		}
		slices.Sort(f.Tips)
		f.ClearedBy = oldConvergence(below, g, succ)
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b Fork) int { return strings.Compare(a.At, b.At) })
	return out
}

// belowOf is every node a fork's branches reach through any link, the branches included: the set its tips and
// its clearing are computed over.
func oldBelowOf(branches []string, succ map[string][]string) map[string]bool {
	below := map[string]bool{}
	for _, b := range branches {
		for n := range oldDescendants(b, succ) {
			below[n] = true
		}
	}
	return below
}

// Span returns the nodes of g that are on fork f, sorted: every node its branches reach (the branches, the lines
// between them and the tips), up to and including its clearing node when it has cleared; a node after the
// clearing node is past the fork. f is one of oldForks(g): Span reads the same reduced graph and the same "below" set,
// so a surface that marks a node as on a fork agrees with the fork itself (claims-model note I12).
func oldSpan(g map[string]Node, f Fork) []string {
	g = oldReduce(g)
	succ := map[string][]string{}
	for n, nd := range g {
		for _, p := range nd.Branch {
			succ[p] = append(succ[p], n)
		}
		for _, p := range nd.Join {
			succ[p] = append(succ[p], n)
		}
	}
	below := oldBelowOf(f.Branches, succ)
	var past map[string]bool
	if f.ClearedBy != "" {
		past = oldDescendants(f.ClearedBy, succ)
		delete(past, f.ClearedBy)
	}
	var out []string
	for n := range below {
		if _, held := g[n]; held && !past[n] {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// convergence returns the earliest node D in below such that every node in below is D, an ancestor of D or
// a descendant of D; "" if there is none. Two such nodes are always ancestor and descendant of each other,
// so the earliest is unique.
func oldConvergence(below map[string]bool, g map[string]Node, succ map[string][]string) string {
	best := ""
	bestAnc := 0
	for d := range below {
		anc := oldAncestors(d, g)
		desc := oldDescendants(d, succ)
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
func oldTips(g map[string]Node) []string {
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
func oldReduce(g map[string]Node) map[string]Node {
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
				if q != p && oldAncestors(q, h)[p] {
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
func oldAncestors(n string, g map[string]Node) map[string]bool {
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
func oldDescendants(n string, succ map[string][]string) map[string]bool {
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

func oldDedupe(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}
