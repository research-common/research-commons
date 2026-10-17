package keylog

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// Key events (wire-format note §5 `rotate_key` · `revoke_key`, §7 "Gaps"; claims-model note §4, §12).
//
// This file answers two log-level questions and nothing more:
//
//   - which of a key's rotations and revocations are in force: a key event is in force when it has chained
//     (§7: "a detached `rotate_key` or `revoke_key` is not yet in force");
//   - which lines come after an in-force event "as the log orders them" (C-core-127b): the lines that have
//     the event among their ancestors through `prev` and `merges`. On a forked log, an event on one branch
//     applies to that branch's descendants and to any line that merges it, never to the other branch.
//
// What an event means for those lines (the sibling rule, hard and soft, `last_good`, claims-model note §4.1) is
// the resolver's. Key succession stays a reader projection (claims-model §16 (1)). Nothing here grants or
// removes authority.
//
// Only verified, fully understood lines are key events: an unknown-alg line (even vouched) or a line whose
// `crit` names an extension this reader lacks has a body nobody here can rely on.

// KeyEvent is one rotate_key or revoke_key in a log.
type KeyEvent struct {
	St   *wire.Statement
	Kind string // "rotate_key" or "revoke_key"
	// Successor is the rotate_key successor key; "" for a revocation.
	Successor string
	// Reason is the revoke_key reason token; "" for a rotation.
	Reason string
	// LastGood is the revoke_key `last_good` statement id; "" when absent or for a rotation.
	LastGood string
	// InForce is true when the event's line has chained.
	InForce bool
}

// Hard reports whether a key event leaves only `last_good`'s history counting (claims-model note §4.1). A
// rotation and a revocation for `superseded` or `cessation_of_operation` are soft: the key retired, and its
// history counts. Every other reason is hard, including undocumented and future values (fail closed).
func (ev KeyEvent) Hard() bool {
	if ev.Kind == "rotate_key" {
		return false
	}
	return ev.Reason != "superseded" && ev.Reason != "cessation_of_operation"
}

// KeyState is the key-event view of one log.
type KeyState struct {
	Key string
	// Events are every key event placed in the log, in force or not, by seq then id.
	Events []KeyEvent
	// After maps a chained line's id to the ids of the in-force events strictly before it in the log's order,
	// sorted. A line with no such event is absent. Detached lines are never listed: they are not evaluated.
	After map[string][]string
}

// Succession is one in-force rotation: From's log names To as its successor in statement Event.
type Succession struct {
	From, To string
	Event    string
}

// KeyState computes the key-event view from the log's view.
func (v View) KeyState() KeyState {
	ks := KeyState{Key: v.Key, After: map[string][]string{}}
	chained := map[string]*wire.Statement{}
	for _, ln := range v.Lines {
		if ln.State == Chained {
			chained[ln.St.ID] = ln.St
		}
		if ev, ok := keyEvent(ln.St); ok {
			ev.InForce = ln.State == Chained
			ks.Events = append(ks.Events, ev)
		}
	}
	inForce := map[string]bool{}
	for _, ev := range ks.Events {
		if ev.InForce {
			inForce[ev.St.ID] = true
		}
	}
	if len(inForce) == 0 {
		return ks
	}
	for id := range chained {
		var after []string
		for a := range ancestorsOf(id, chained) {
			if inForce[a] {
				after = append(after, a)
			}
		}
		if len(after) > 0 {
			slices.Sort(after)
			ks.After[id] = after
		}
	}
	return ks
}

// Successions returns every in-force rotation across the store's logs, sorted by From then event id. Two
// rotations of one key (on two branches of a forked log, or one after the other) are both listed: choosing
// between them is the reader's projection.
//
// A listed succession is not yet authority. The resolver must not read Successions alone: an in-force hard
// revocation of the same key (any reason but superseded or cessation_of_operation, claims-model §4.1) whose
// last_good precedes a rotation outranks that rotation, because a successor named after a compromise is
// compromised with it, and a rotate_key is exactly what a key thief would sign. Combine this list with each
// key's KeyState (After, and the revocations in Events) before granting a successor anything.
func (s *Store) Successions() []Succession {
	var out []Succession
	for _, k := range s.Keys() {
		for _, ev := range s.logs[k].View().KeyState().Events {
			if ev.InForce && ev.Kind == "rotate_key" {
				out = append(out, Succession{From: k, To: ev.Successor, Event: ev.St.ID})
			}
		}
	}
	return out
}

func keyEvent(st *wire.Statement) (KeyEvent, bool) {
	if !st.Verified || st.Status != wire.Valid || (st.Kind != "rotate_key" && st.Kind != "revoke_key") {
		return KeyEvent{}, false
	}
	ev := KeyEvent{St: st, Kind: st.Kind}
	str := func(k string) string {
		if v, ok := st.Body.Get(k); ok {
			if s, ok := v.(canon.String); ok {
				return string(s)
			}
		}
		return ""
	}
	ev.Successor, ev.Reason, ev.LastGood = str("successor"), str("reason"), str("last_good")
	return ev, true
}

// ancestorsOf returns every chained line reachable from id through prev and merges, id excluded.
func ancestorsOf(id string, chained map[string]*wire.Statement) map[string]bool {
	seen := map[string]bool{}
	stack := links(chained[id])
	for len(stack) > 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		st, ok := chained[x]
		if !ok || seen[x] {
			continue
		}
		seen[x] = true
		stack = append(stack, links(st)...)
	}
	return seen
}

// renderEvents is the key-event part of the log display.
func (ks KeyState) render(b *strings.Builder) {
	for _, ev := range ks.Events {
		what := ev.Kind
		if ev.Successor != "" {
			what += " to " + ev.Successor
		}
		if ev.Reason != "" {
			hs := "soft"
			if ev.Hard() {
				hs = "hard"
			}
			what += " (" + ev.Reason + ", " + hs + ")"
		}
		if ev.LastGood != "" {
			what += " last_good " + Short(ev.LastGood)
		}
		state := "in force"
		if !ev.InForce {
			state = "not in force (detached)"
		}
		fmt.Fprintf(b, "  key event seq %d %s: %s, %s\n", ev.St.Seq, Short(ev.St.ID), what, state)
	}
}

func (ks KeyState) afterTag(id string) string {
	ev := ks.After[id]
	if len(ev) == 0 {
		return ""
	}
	s := make([]string, len(ev))
	for i, x := range ev {
		s[i] = Short(x)
	}
	return " after " + strings.Join(s, ",")
}
