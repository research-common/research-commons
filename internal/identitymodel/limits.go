package identitymodel

import "fmt"

// Evaluation caps (profile §7). They bound the work ONE query may do; they are not
// transport or admission limits (those belong to the trusted caller). Reaching any
// cap stops the query: the result is non-passing with a model_limit reason that
// names the cap and its value, never a partial pass. Reasons established before the
// cap stay in the result, so a definite denial found first remains denied.
//
// Accounting (deterministic for the same evidence and limits, whatever the delivery
// order, because facts are normalized and every walk follows a fixed order: the
// snapshot's sorted ids, then prev before the sorted merges):
//
//   - Dependencies: distinct statement ids the query reads, held or missing. The
//     statement, its identity inception, its grant, every node of every ancestry
//     closure walked, each prev/merge link read for a sequence check, and every
//     authenticated root-signer event examined by the root scan each count once
//     per query, however often they are read.
//   - Path edges: the longest prev/merge path from a walked head to the end of its
//     closure (a missing link counts as one edge), and the prev-only path a
//     placement walk follows to an inception. A closure's length is a property of
//     the evidence, computed once per lineage, not the depth a traversal happened
//     to reach.
//   - Inspections: every fact read, every link followed and every memoized result
//     reused counts one. This is the total-work bound: memoization keeps a long
//     linear history linear, and the cap keeps any adversarial shape bounded.
//
// Facts by other keys and unproven facts are never read by a query (scans use
// per-signer indexes of authenticated facts), so they cannot spend this identity's
// budget. The root's and the delegate's own authenticated facts are: the root scan
// reads every R fact as a dependency before deciding it is outside I's lineage, and
// the delegate scan inspects every fact of K's log. Only R or K can author that
// load, and it fails closed. On linear histories the dependency cap binds first;
// on merge-dense logs the inspection cap can.
type Limits struct {
	Dependencies int
	PathEdges    int
	Inspections  int
}

const (
	DefaultMaxDependencies = 100_000
	DefaultMaxPathEdges    = 100_000
	DefaultMaxInspections  = 1_000_000

	// Cap names carried by model_limit reasons.
	LimitDependencies = "dependencies"
	LimitPathEdges    = "path_edges"
	LimitInspections  = "inspections"
)

// DefaultLimits returns the profile's evaluation caps.
func DefaultLimits() Limits {
	return Limits{DefaultMaxDependencies, DefaultMaxPathEdges, DefaultMaxInspections}
}

func (l Limits) normalized() Limits {
	d := DefaultLimits()
	if l.Dependencies <= 0 {
		l.Dependencies = d.Dependencies
	}
	if l.PathEdges <= 0 {
		l.PathEdges = d.PathEdges
	}
	if l.Inspections <= 0 {
		l.Inspections = d.Inspections
	}
	return l
}

// limitHit unwinds a query that reached a cap. It never escapes the package:
// EvaluateWith recovers it, so no caller can act on a partially walked closure.
type limitHit struct {
	name  string
	value int
}

func (h limitHit) detail() string {
	return fmt.Sprintf("%s limit %d reached; no partial pass", h.name, h.value)
}

type budget struct {
	lim         Limits
	deps        map[ID]bool
	inspections int
}

func (b *budget) inspect() {
	if b.inspections++; b.inspections > b.lim.Inspections {
		panic(limitHit{LimitInspections, b.lim.Inspections})
	}
}

func (b *budget) read(s *Snapshot, id ID) (Fact, bool) {
	b.inspect()
	if !b.deps[id] {
		if len(b.deps) >= b.lim.Dependencies {
			panic(limitHit{LimitDependencies, b.lim.Dependencies})
		}
		b.deps[id] = true
	}
	f, ok := s.facts[id]
	return f, ok
}

func (b *budget) path(edges int) {
	if edges > b.lim.PathEdges {
		panic(limitHit{LimitPathEdges, b.lim.PathEdges})
	}
}

// Stats reports the work one evaluation did; it exists for measurement and tests.
type Stats struct {
	Dependencies int
	Inspections  int
}
