// Package resolve is the one resolver (claims-model note I12, §4 "Views"): it turns the statements a reader
// holds into the answers every surface shows. It reads per-key logs (package keylog) and never a statement on
// its own: a statement counts toward anything only once its line has chained (wire-format note §7, "Gaps"),
// and key events apply to the lines after them as the log orders them (keylog.KeyState).
//
// This file holds the shared index. Each kind of answer lives in its own file: resources (collections, tasks,
// series; claims-model note §8) in resource.go.
//
// Every answer is a pure function of the set of held lines, so delivery order cannot change it (I14, P-01).
package resolve

import (
	"slices"

	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// Placed is one statement as the resolver sees it.
type Placed struct {
	St *wire.Statement
	// Chained is true when the statement's line has chained in its signer's log. A detached statement is shown,
	// attributed, and evaluated toward nothing.
	Chained bool
	// Evaluable is true when the statement is chained, verified and fully understood (status valid). Only an
	// evaluable statement counts toward an answer.
	Evaluable bool
	// Revoked lists the in-force revoke_key events of the signer that do not have this line in their history:
	// the line comes after the revocation in the log's order (keylog.KeyState.After), or sits on a branch the
	// revocation does not include. Empty for a detached line, which is not evaluated.
	//
	// The second half is finding R3 (fail closed for authority): a revocation is the owner's signed statement
	// of which history it stands behind, and "a branch the owner does not recognise is not merged: the answer
	// to it is revoke_key with key_compromise" (storage note §4.2). A line on a branch the revocation does not
	// include is therefore never counted toward authority. It is still shown, attributed and retained (I3).
	Revoked []string
	// RevokedAfter is the subset of Revoked that comes strictly before this line in the log's order.
	RevokedAfter []string
}

// Resolver is the reader's view over every log it holds. Build it with New after the logs change; it keeps
// no state of its own beyond that snapshot.
type Resolver struct {
	logs   *keylog.Store
	byID   map[string]*Placed
	byKind map[string][]*Placed
	keys   map[string]keylog.KeyState
}

// New indexes every placed line of every log in s.
func New(s *keylog.Store) *Resolver {
	r := &Resolver{logs: s, byID: map[string]*Placed{}, byKind: map[string][]*Placed{}, keys: map[string]keylog.KeyState{}}
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
		// history[R] = R and every chained line R has among its ancestors through prev and merges.
		history := map[string]map[string]bool{}
		var revokes []string
		for _, ev := range ks.Events {
			if ev.InForce && ev.Kind == "revoke_key" {
				revokes = append(revokes, ev.St.ID)
				history[ev.St.ID] = closure(ev.St.ID, chained)
			}
		}
		for _, ln := range v.Lines {
			p := &Placed{St: ln.St, Chained: ln.State == keylog.Chained}
			p.Evaluable = p.Chained && ln.St.Verified && ln.St.Status == wire.Valid
			if p.Chained {
				for _, rv := range revokes {
					if !history[rv][ln.St.ID] {
						p.Revoked = append(p.Revoked, rv)
					}
				}
				for _, ev := range ks.After[ln.St.ID] {
					if slices.Contains(revokes, ev) {
						p.RevokedAfter = append(p.RevokedAfter, ev)
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

// revokedKey reports whether key has an in-force revoke_key anywhere in its log, and names it. This is a
// display question ("does this controller still have a usable key?", C-core-99). Whether one statement counts
// is decided per line by Placed.Revoked, which follows the log's order: a statement before the revocation
// keeps counting, one after it does not (C-core-143), and a branch that does not include the revocation is
// the key's own fork, shown as one.
func (r *Resolver) revokedKey(key string) (string, bool) {
	for _, ev := range r.keys[key].Events {
		if ev.InForce && ev.Kind == "revoke_key" {
			return ev.St.ID, true
		}
	}
	return "", false
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
