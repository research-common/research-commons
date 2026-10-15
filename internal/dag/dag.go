// Package dag computes forks and their clearing over a graph of signed predecessor links. It is the one
// definition of "fork" and "cleared" (claims-model note I12): a key's log uses it with each line's `prev` and
// `merges` as predecessors (wire-format note §7), and a resource uses it with each edition's `predecessors`
// (claims-model note §8). Neither caller re-implements it.
//
// A fork point is a node with two or more successors, or the empty id "" when two or more nodes have no
// predecessor at all (two first lines). A fork clears when every branch is an ancestor of one node, so
// following one branch never clears it: the clearing node has to name the others. Everything is a pure
// function of the node set, so delivery order cannot change an answer (I14).
package dag

import (
	"slices"
)

// Fork is one fork point and what became of it.
type Fork struct {
	// At is the node the branches share as predecessor; "" for two or more roots.
	At string
	// Branches are At's successors, sorted.
	Branches []string
	// Tips are the nodes descending from At (branches included) with no successor, sorted.
	Tips []string
	// Cleared is true when some node descends from (or is) every branch.
	Cleared bool
	// ClearedBy are the earliest such nodes: common descendants none of whose predecessors is one, sorted.
	ClearedBy []string
}

// Forks returns every fork point of the graph, sorted by At. preds maps each node to its predecessors;
// a predecessor that is not itself a key of preds is ignored (the caller passes only nodes it holds).
func Forks(preds map[string][]string) []Fork {
	succ := map[string][]string{}
	for n, ps := range preds {
		root := true
		for _, p := range ps {
			if _, held := preds[p]; held {
				succ[p] = append(succ[p], n)
				root = false
			}
		}
		if root {
			succ[""] = append(succ[""], n)
		}
	}
	var out []Fork
	for at, ss := range succ {
		ss = dedupe(ss)
		if len(ss) < 2 {
			continue
		}
		f := Fork{At: at, Branches: ss}
		var common map[string]bool
		all := map[string]bool{}
		for _, b := range ss {
			d := descendants(b, succ)
			for n := range d {
				all[n] = true
			}
			if common == nil {
				common = d
				continue
			}
			for n := range common {
				if !d[n] {
					delete(common, n)
				}
			}
		}
		for n := range all {
			if len(succ[n]) == 0 {
				f.Tips = append(f.Tips, n)
			}
		}
		for n := range common {
			minimal := true
			for _, p := range preds[n] {
				if common[p] {
					minimal = false
				}
			}
			if minimal {
				f.ClearedBy = append(f.ClearedBy, n)
			}
		}
		f.Cleared = len(common) > 0
		slices.Sort(f.Tips)
		slices.Sort(f.ClearedBy)
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b Fork) int {
		switch {
		case a.At < b.At:
			return -1
		case a.At > b.At:
			return 1
		}
		return 0
	})
	return out
}

// Tips returns every node with no successor, sorted: the heads of the graph.
func Tips(preds map[string][]string) []string {
	hasSucc := map[string]bool{}
	for _, ps := range preds {
		for _, p := range ps {
			hasSucc[p] = true
		}
	}
	var out []string
	for n := range preds {
		if !hasSucc[n] {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
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
