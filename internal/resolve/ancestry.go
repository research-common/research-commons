package resolve

import "github.com/research-common/research-commons/internal/wire"

// ancestry answers "is line x in the history of line from" for one key's chained lines without walking the log.
//
// The question is asked for every claim, amendment, anchor and submission, and walking the log for each (closure)
// made every such question cost the length of the log. The chained lines form a forest under prev (a line's prev
// is one line, a root has none held), and in a forest "x is an ancestor of from" is an interval test on a
// depth-first numbering. Merges add edges outside the forest; they are rare (a fork being cleared), so the
// history of each line that carries merges is kept whole, and a line reaches x either along prev, or through
// one of the merge lines on its own prev path. A log with more merge lines than maxMergeLines keeps the walk.
type ancestry struct {
	chained map[string]*wire.Statement
	in, out map[string]int // depth-first entry and exit numbers in the prev forest
	// merges is each line carrying merges, with its whole history (closure); nil with walk set
	merges map[string]map[string]bool
	walk   bool
}

const maxMergeLines = 64

func newAncestry(chained map[string]*wire.Statement) *ancestry {
	a := &ancestry{chained: chained, in: make(map[string]int, len(chained)), out: make(map[string]int, len(chained))}
	children := map[string][]string{}
	var roots, merging []string
	for id, st := range chained {
		if _, ok := chained[st.Prev]; ok && st.Prev != "" {
			children[st.Prev] = append(children[st.Prev], id)
		} else {
			roots = append(roots, id)
		}
		if len(st.Merges) > 0 {
			merging = append(merging, id)
		}
	}
	// numbering: iterative, a log can be deeper than a call stack should go
	n := 0
	type frame struct {
		id   string
		next int
	}
	for _, root := range roots {
		stack := []frame{{id: root}}
		a.in[root] = n
		n++
		for len(stack) > 0 {
			f := &stack[len(stack)-1]
			kids := children[f.id]
			if f.next < len(kids) {
				c := kids[f.next]
				f.next++
				a.in[c] = n
				n++
				stack = append(stack, frame{id: c})
				continue
			}
			a.out[f.id] = n
			n++
			stack = stack[:len(stack)-1]
		}
	}
	if len(merging) > maxMergeLines {
		a.walk = true
		return a
	}
	if len(merging) > 0 {
		a.merges = make(map[string]map[string]bool, len(merging))
		for _, id := range merging {
			a.merges[id] = closure(id, chained)
		}
	}
	return a
}

// onPrevPath reports whether x is from itself or one of its ancestors along prev alone.
func (a *ancestry) onPrevPath(from, x string) bool {
	fi, ok := a.in[from]
	if !ok {
		return false
	}
	xi, ok := a.in[x]
	return ok && xi <= fi && a.out[from] <= a.out[x]
}

// reaches reports whether x is from or a chained line reachable from it through prev and merges: exactly
// closure(from, chained)[x].
func (a *ancestry) reaches(from, x string) bool {
	if a == nil {
		return false
	}
	if a.walk {
		return closure(from, a.chained)[x]
	}
	if a.onPrevPath(from, x) {
		return true
	}
	for m, history := range a.merges {
		if history[x] && a.onPrevPath(from, m) {
			return true
		}
	}
	return false
}
