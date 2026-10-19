// Package resolve is the one resolver (claims-model note I12, §4 "Views"): it turns the statements a reader
// holds into the answers every surface shows. It reads per-key logs (package keylog) and never a statement on
// its own: a statement counts toward anything only once its line has chained (wire-format note §7, "Gaps"),
// and only while the key events of its signer let it count (claims-model note §4.1).
//
// This file holds the shared index and the key-event rules. Each kind of answer lives in its own file:
// resources (collections, tasks, series; claims-model note §8) in resource.go; authorship, priority and
// single-party defaults (§5.1, §5.2) in artifact.go; derivation groups and grades (§5.2, §7) in group.go; time
// bounds (§10) in time.go; edition rules (§8) in edition_rules.go; membership and the pre-pin check in
// membership.go; growing series in series.go; observations, referent status and capture evidence (§5.3.1,
// §5.3.3) in observation.go; corroboration status and reputation projections (§5.3.2, §5.4) in corroboration.go.
//
// Every answer is a pure function of the set of held lines, so delivery order cannot change it (I14, P-01).
package resolve

import (
	"slices"
	"sync"

	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// Placed is one statement as the resolver sees it.
type Placed struct {
	St *wire.Statement
	// Chained is true when the statement's line has chained in its signer's log. A detached statement is shown,
	// attributed, and evaluated toward nothing.
	Chained bool
	// Evaluable is true when the statement is chained, verified and fully understood (status valid).
	Evaluable bool
	// After names the in-force key events of the signer that come before this line in the log's order (they
	// are among its ancestors). The key had already rotated or revoked when it signed this line, so the line
	// counts toward nothing, and never makes anything contested (C-core-99, C-core-143).
	After []string
	// Doubted gives, one reason per in-force key event, why a line that is NOT after that event still counts
	// toward nothing (claims-model note §4.1): it sits on a branch the event's history leaves out (the sibling
	// rule), or the event is a hard revocation and the line is outside its `last_good`'s history (or it names
	// no usable `last_good`). Such a line may have been the key's legitimate word, so an edition that needed it
	// is contested, not silently dropped (C-core-143a, b, e).
	Doubted []string
}

// Counts reports whether the statement counts toward any answer: chained, valid, and let through by every
// in-force key event of its signer (the intersection rule, §4.1).
func (p *Placed) Counts() bool { return p.Evaluable && len(p.After) == 0 && len(p.Doubted) == 0 }

// Resolver is the reader's view over every log it holds. Build it with New after the logs change; it keeps
// no state of its own beyond that snapshot.
type Resolver struct {
	logs    *keylog.Store
	chained map[string]map[string]*wire.Statement // per key: its chained lines by id
	byID    map[string]*Placed
	byKind  map[string][]*Placed
	keys    map[string]keylog.KeyState
	// time and cmp are the reader's own verifiers (I9): time evidence (§10) and comparator runs (§5.2).
	time TimeVerifier
	cmp  Comparator
	// cmpMu guards cmpRuns: each comparator result this resolver obtained, keyed by comparator and the unordered
	// pair of outputs, so every pair runs at most once per snapshot whichever blobs are viewed (group.go, pair).
	cmpMu   sync.Mutex
	cmpRuns map[[3]string]cmpResult
	// rules is the reader's edition-rule configuration: dialects, content, limits, segments (edition_rules.go).
	rules ruleConfig
	// obs is the reader's configuration for observations and corroboration (observation.go); origins is its
	// delivery-metadata index, shown in explain and an input to nothing (corroboration.go).
	obs     *obsConfig
	origins OriginIndex
}

// New indexes every placed line of every log in s. With no options the reader verifies no proof format and
// runs no comparator, so no bound orders anything and no comparison is made.
func New(s *keylog.Store, opts ...Option) *Resolver {
	r := &Resolver{logs: s, chained: map[string]map[string]*wire.Statement{}, byID: map[string]*Placed{}, byKind: map[string][]*Placed{}, keys: map[string]keylog.KeyState{},
		time: NoTimeVerifier{}, cmp: NoComparator{}, cmpRuns: map[[3]string]cmpResult{}, obs: defaultObsConfig()}
	for _, o := range opts {
		o(r)
	}
	for _, k := range s.Keys() {
		v := s.Log(k).View()
		ks := v.KeyState()
		r.keys[k] = ks
		chained := map[string]*wire.Statement{}
		for _, ln := range v.Lines {
			if ln.State == keylog.Chained {
				chained[ln.St.ID] = ln.St
			}
		}
		r.chained[k] = chained
		// Every in-force key event (rotations included: a rotation retires the old key like a `superseded`
		// revocation, §4.1) and its history: the event and every chained line it reaches through prev and merges.
		type event struct {
			ev       keylog.KeyEvent
			history  map[string]bool
			lastGood map[string]bool // for a hard revocation: last_good's history; nil when unusable
		}
		var events []event
		for _, ev := range ks.Events {
			if !ev.InForce {
				continue
			}
			e := event{ev: ev, history: closure(ev.St.ID, chained)}
			if ev.Hard() && ev.LastGood != "" && e.history[ev.LastGood] {
				e.lastGood = closure(ev.LastGood, chained)
			}
			events = append(events, e)
		}
		for _, ln := range v.Lines {
			p := &Placed{St: ln.St, Chained: ln.State == keylog.Chained}
			p.Evaluable = p.Chained && ln.St.Verified && ln.St.Status == wire.Valid
			if p.Chained {
				for _, e := range events {
					id, what := e.ev.St.ID, e.ev.Kind+" "+keylog.Short(e.ev.St.ID)
					switch {
					case slices.Contains(ks.After[ln.St.ID], id):
						p.After = append(p.After, "after "+what)
					case !e.history[ln.St.ID]:
						p.Doubted = append(p.Doubted, "on a branch "+what+" does not include (sibling rule)")
					case e.ev.Hard() && e.lastGood == nil:
						p.Doubted = append(p.Doubted, "hard "+what+" names no last_good in its history")
					case e.ev.Hard() && !e.lastGood[ln.St.ID]:
						p.Doubted = append(p.Doubted, "after last_good of hard "+what)
					}
				}
			}
			r.byID[ln.St.ID] = p
			r.byKind[ln.St.Kind] = append(r.byKind[ln.St.Kind], p)
		}
	}
	return r
}

// Statement returns a placed statement by id.
func (r *Resolver) Statement(id string) (*Placed, bool) {
	p, ok := r.byID[id]
	return p, ok
}

// retiredKey reports whether key has an in-force revoke_key or rotate_key anywhere in its log, and names the
// first by seq. This is a display question ("does this controller still have a usable key?", C-core-99):
// controller roles name keys and do not follow a rotation (§4.1, §8). Whether one statement counts is decided
// per line (Placed.Counts).
func (r *Resolver) retiredKey(key string) (string, bool) {
	for _, ev := range r.keys[key].Events {
		if ev.InForce {
			return ev.St.ID, true
		}
	}
	return "", false
}

// precedes reports whether line a is an ancestor of line b in key's log (through prev and merges).
func (r *Resolver) precedes(key, a, b string) bool {
	return a != b && closure(b, r.chained[key])[a]
}

// closure returns id and every chained line reachable from it through prev and merges.
func closure(id string, chained map[string]*wire.Statement) map[string]bool {
	seen := map[string]bool{}
	stack := []string{id}
	for len(stack) > 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		st, ok := chained[x]
		if !ok || seen[x] {
			continue
		}
		seen[x] = true
		if st.Prev != "" {
			stack = append(stack, st.Prev)
		}
		stack = append(stack, st.Merges...)
	}
	return seen
}
