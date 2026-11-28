package dag

import (
	"container/heap"
	"math/bits"
	"slices"
)

// index keeps node numbers in topological order. Links point backwards. The
// reachability passes use one word per node, not a quadratic closure table.
type index struct {
	ids      []string
	byID     map[string]int
	links    [][]int
	branches [][]int
	succ     [][]int
}

func prepare(g map[string]Node) *index {
	// The empty string doubles as the synthetic root; preserve the old behavior
	// for direct callers using it as a real node. Signed IDs are never empty.
	if _, ok := g[""]; ok {
		return nil
	}
	ids := make([]string, 0, len(g))
	for id := range g {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	pos := make(map[string]int, len(ids))
	for i, id := range ids {
		pos[id] = i
	}
	links := make([][]int, len(ids))
	succ := make([][]int, len(ids))
	degree := make([]int, len(ids))
	for i, id := range ids {
		nd := g[id]
		for _, ps := range [][]string{nd.Branch, nd.Join} {
			for _, p := range ps {
				if j, ok := pos[p]; ok {
					links[i] = append(links[i], j)
					succ[j] = append(succ[j], i)
					degree[i]++
				}
			}
		}
	}
	var order []int
	for i, d := range degree {
		if d == 0 {
			order = append(order, i)
		}
	}
	for h := 0; h < len(order); h++ {
		for _, s := range succ[order[h]] {
			degree[s]--
			if degree[s] == 0 {
				order = append(order, s)
			}
		}
	}
	if len(order) != len(ids) {
		return nil
	}
	x := &index{ids: make([]string, len(ids)), byID: make(map[string]int, len(ids)), links: make([][]int, len(ids)), branches: make([][]int, len(ids))}
	for i, old := range order {
		x.ids[i] = ids[old]
		x.byID[ids[old]] = i
	}
	generation := make([]int, len(ids))
	queries := make([]bool, len(ids))
	for i, id := range x.ids {
		nd := g[id]
		for _, ps := range [][]string{nd.Branch, nd.Join} {
			for _, p := range ps {
				if j, ok := x.byID[p]; ok {
					x.links[i] = append(x.links[i], j)
					generation[i] = max(generation[i], generation[j]+1)
				}
			}
		}
		for _, p := range nd.Branch {
			if j, ok := x.byID[p]; ok {
				x.branches[i] = append(x.branches[i], j)
			}
		}
		// A highest-generation target cannot be implied by another target.
		for _, p := range x.links[i] {
			if generation[p]+1 < generation[i] {
				queries[p] = true
			}
		}
	}
	var targets []int
	for i, q := range queries {
		if q {
			targets = append(targets, i)
		}
	}
	dropped := make([][]bool, len(ids))
	for i := range dropped {
		dropped[i] = make([]bool, len(x.links[i]))
	}
	seed, reach := make([]uint64, len(ids)), make([]uint64, len(ids))
	for start := 0; start < len(targets); start += 64 {
		clear(seed)
		clear(reach)
		for j, p := range targets[start:min(start+64, len(targets))] {
			seed[p] = uint64(1) << j
		}
		for i, ps := range x.links {
			var implied uint64
			for _, p := range ps {
				implied |= reach[p] // strict ancestors: duplicate targets do not imply each other
				reach[i] |= reach[p] | seed[p]
			}
			for j, p := range ps {
				if implied&seed[p] != 0 {
					dropped[i][j] = true
				}
			}
		}
	}
	x.succ = make([][]int, len(ids))
	for i, ps := range x.links {
		nb := len(x.branches[i])
		var kept, branch []int
		for j, p := range ps {
			if !dropped[i][j] {
				kept = append(kept, p)
				if j < nb {
					branch = append(branch, p)
				}
				x.succ[p] = append(x.succ[p], i)
			}
		}
		x.links[i], x.branches[i] = kept, branch
	}
	return x
}

func reduce(g map[string]Node) map[string]Node {
	x := prepare(g)
	if x == nil {
		return legacyReduce(g)
	}
	out := make(map[string]Node, len(g))
	for i, id := range x.ids {
		var nd Node
		for j, p := range x.links[i] {
			if j < len(x.branches[i]) {
				nd.Branch = append(nd.Branch, x.ids[p])
			} else {
				nd.Join = append(nd.Join, x.ids[p])
			}
		}
		out[id] = nd
	}
	return out
}

// Forks returns every fork point, sorted by At. Missing links are ignored.
func Forks(g map[string]Node) []Fork {
	fs, _ := analyze(g, false)
	return fs
}

// ForksAndSpans returns Forks(g) and the corresponding Span(g, f) for each fork,
// sharing the graph preparation instead of repeating it for every span.
func ForksAndSpans(g map[string]Node) ([]Fork, [][]string) {
	return analyze(g, true)
}

func analyze(g map[string]Node, withSpans bool) ([]Fork, [][]string) {
	x := prepare(g)
	if x == nil {
		fs := legacyForks(g)
		var spans [][]string
		if withSpans {
			for _, f := range fs {
				spans = append(spans, Span(g, f))
			}
		}
		return fs, spans
	}
	branchSucc := make(map[string][]string)
	for i, id := range x.ids {
		if len(x.links[i]) == 0 {
			branchSucc[""] = append(branchSucc[""], id)
		}
		for _, p := range x.branches[i] {
			branchSucc[x.ids[p]] = append(branchSucc[x.ids[p]], id)
		}
	}
	var fs []Fork
	for at, bs := range branchSucc {
		bs = dedupe(bs)
		if len(bs) >= 2 {
			fs = append(fs, Fork{At: at, Branches: bs})
		}
	}
	slices.SortFunc(fs, func(a, b Fork) int {
		if a.At < b.At {
			return -1
		}
		if a.At > b.At {
			return 1
		}
		return 0
	})
	var spans [][]string
	seen := make([]int, len(x.ids))
	cleared := make([]int, len(fs))
	for fi := range fs {
		cleared[fi] = -1
		q := &frontier{}
		for _, b := range fs[fi].Branches {
			p := x.byID[b]
			seen[p] = fi + 1
			heap.Push(q, p)
		}
		var span []string
		dead := false
		for q.Len() > 0 {
			p := heap.Pop(q).(int)
			if withSpans {
				span = append(span, x.ids[p])
			}
			// In the transitive reduction, no edge can bypass a node comparable
			// with the entire below-set. A singleton frontier, before any sink,
			// is therefore exactly the first such node.
			if q.Len() == 0 && !dead {
				fs[fi].ClearedBy = x.ids[p]
				cleared[fi] = p
				break
			}
			if len(x.succ[p]) == 0 {
				dead = true
				fs[fi].Tips = append(fs[fi].Tips, x.ids[p])
			}
			for _, s := range x.succ[p] {
				if seen[s] != fi+1 {
					seen[s] = fi + 1
					heap.Push(q, s)
				}
			}
		}
		slices.Sort(span)
		slices.Sort(fs[fi].Tips)
		if withSpans {
			spans = append(spans, span)
		}
	}
	if !slices.ContainsFunc(cleared, func(p int) bool { return p >= 0 }) {
		return fs, spans
	}
	// A cleared fork's tips are the sinks reachable from its clearing node.
	// Batch 64 sinks at a time; this bounds workspace even with many tips.
	var sinks []int
	for i, ss := range x.succ {
		if len(ss) == 0 {
			sinks = append(sinks, i)
		}
	}
	reach := make([]uint64, len(x.ids))
	for start := 0; start < len(sinks); start += 64 {
		clear(reach)
		chunk := sinks[start:min(start+64, len(sinks))]
		for j, p := range chunk {
			reach[p] = uint64(1) << j
		}
		for i := len(x.ids) - 1; i >= 0; i-- {
			for _, s := range x.succ[i] {
				reach[i] |= reach[s]
			}
		}
		for fi, p := range cleared {
			if p < 0 {
				continue
			}
			for word := reach[p]; word != 0; word &= word - 1 {
				fs[fi].Tips = append(fs[fi].Tips, x.ids[chunk[bits.TrailingZeros64(word)]])
			}
		}
	}
	for i := range fs {
		slices.Sort(fs[i].Tips)
	}
	return fs, spans
}

type frontier []int

func (f frontier) Len() int           { return len(f) }
func (f frontier) Less(i, j int) bool { return f[i] < f[j] }
func (f frontier) Swap(i, j int)      { f[i], f[j] = f[j], f[i] }
func (f *frontier) Push(x any)        { *f = append(*f, x.(int)) }
func (f *frontier) Pop() any          { a := *f; x := a[len(a)-1]; *f = a[:len(a)-1]; return x }
