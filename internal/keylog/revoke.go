package keylog

import (
	"slices"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// The writer's merge set for a revocation (storage note §4.2). A `revoke_key` cuts every line of the key outside
// its own history (claims-model note §4.1), so the tool builds that history by reason. For a soft reason the
// owner retires a key it still controls, and the tool merges every tip it holds so that nothing is cut by
// accident. One kind of tip is never merged that way: a tip whose branch carries a key event outside the history
// the owner chose to extend. Folding a rotate_key in puts the revocation after it, so the rotation counts and
// the revocation counts toward nothing; the owner's routine retirement would hand the other branch's event the
// last word. Such a tip is refused, named with its event, and the next step is a hard reason with last_good,
// which cuts every line outside last_good's history whatever is merged.
//
// "Outside the chosen history" stands in for "not written by this machine": the store keeps no record of which
// statements it signed (the operation history of storage §3.6 is optional, best-effort, and read by no answer),
// so the rule refuses every such key event, the owner's own from a second machine included. Extending that tip
// with --prev, or a hard reason, is the way through for an owner who did write it.

// SoftMergeKeyEvent is the reason a soft revocation's merge set is refused: a tip it would merge carries a key
// event outside the history being extended.
const SoftMergeKeyEvent = "key event on a tip a soft revocation would merge"

// TipAboveNext is the reason a merge set is refused when a tip sits at or above the new line's seq: `merges`
// may name only lower lines (wire-format note §7), so that tip has to be the one extended.
const TipAboveNext = "tip at or above the new line's seq"

// TipKeyEvents is one tip, other than the line being extended, whose branch carries key events outside that
// line's history.
type TipKeyEvents struct {
	Tip    string
	Events []KeyEvent // by seq then id
}

// ForeignKeyEvents lists every chained tip other than prev whose branch (its history minus prev's) carries a
// key event, by tip id. prev must be a chained line of the log; the answer is a function of the held lines.
// The hard-reason path uses it to mark tips; SoftRevokeMerges refuses on it.
func (v View) ForeignKeyEvents(prev string) []TipKeyEvents {
	chained := map[string]*wire.Statement{}
	for _, ln := range v.Lines {
		if ln.State == Chained {
			chained[ln.St.ID] = ln.St
		}
	}
	mine := ancestorsOf(prev, chained)
	mine[prev] = true
	var out []TipKeyEvents
	for _, tip := range v.Tips {
		if mine[tip] {
			continue
		}
		branch := ancestorsOf(tip, chained)
		branch[tip] = true
		var evs []KeyEvent
		for id := range branch {
			if mine[id] {
				continue
			}
			if ev, ok := keyEvent(chained[id]); ok {
				ev.InForce = true
				evs = append(evs, ev)
			}
		}
		if len(evs) > 0 {
			slices.SortFunc(evs, func(a, b KeyEvent) int { return cmpSeqID(a.St, b.St) })
			out = append(out, TipKeyEvents{Tip: tip, Events: evs})
		}
	}
	return out
}

// SoftRevokeMerges is the `merges` list for a soft-reason revocation extending prev: every other chained tip,
// sorted. It refuses (reader policy, the writer's own) when a tip it would merge carries a key event outside
// prev's history, naming the first such tip and event; and when a tip cannot be named because it is not below
// the new line's seq. prev must be a chained line of this log.
func (v View) SoftRevokeMerges(prev string) ([]string, *refusal.Refusal) {
	var at *wire.Statement
	for _, ln := range v.Lines {
		if ln.St.ID == prev && ln.State == Chained {
			at = ln.St
		}
	}
	if at == nil {
		return nil, &refusal.Refusal{Class: refusal.Policy, Reason: "prev not chained",
			Detail: "the line to extend, " + Short(prev) + ", is not a chained line of this log; nothing was signed"}
	}
	if foreign := v.ForeignKeyEvents(prev); len(foreign) > 0 {
		f := foreign[0]
		var what []string
		for _, ev := range f.Events {
			what = append(what, ev.Kind+" "+Short(ev.St.ID))
		}
		return nil, &refusal.Refusal{Class: refusal.Policy, Reason: SoftMergeKeyEvent,
			Detail: "tip " + f.Tip + " carries " + strings.Join(what, ", ") + " outside the history of " + Short(prev) +
				"; merging it under a soft reason would put the revocation after that event, so the event counts and the " +
				"revocation does not; nothing was signed; revoke with a hard reason and last_good on your own line instead, " +
				"which cuts the other branch"}
	}
	chained := map[string]*wire.Statement{}
	for _, ln := range v.Lines {
		if ln.State == Chained {
			chained[ln.St.ID] = ln.St
		}
	}
	var merges []string
	for _, tip := range v.Tips {
		if tip == prev {
			continue
		}
		if chained[tip].Seq > at.Seq {
			return nil, &refusal.Refusal{Class: refusal.Policy, Reason: TipAboveNext,
				Detail: "tip " + tip + " is at seq " + strconv.FormatInt(chained[tip].Seq, 10) + ", not below the new line's seq " + strconv.FormatInt(at.Seq+1, 10) +
					"; merges may name only lower lines; nothing was signed; extend that tip instead"}
		}
		merges = append(merges, tip)
	}
	slices.Sort(merges)
	return merges, nil
}
