// Package keylog holds per-key logs (wire-format note §7, storage note §4): the statements one key signed,
// ordered by the `prev` and `merges` each names inside its signature.
//
// A log keeps every line it was handed that passed wire.Read and the ownership rule. Everything else is
// computed by View, as a pure function of that set: whether a line chains to the first line or is detached
// and waiting for a gap, which fork points exist and whether each has cleared, the tips, which lines are
// incoherent, and which lines break a rule that needs the rest of the log (a `merges` entry with a seq not
// lower than the line's, a `prev` at the wrong seq, a link to another key's line). Because nothing is
// decided at arrival, the order lines arrive in cannot change any answer (I14, C-core-127a, P-01).
//
// What a line *means* (an authored counted, an edition applied, a rotation in force) is the resolver's job.
// This package only says whether the line has chained, which is the precondition for any of that (§7, "Gaps").
package keylog

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/dag"
	"github.com/research-common/research-commons/internal/rctime"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// Store holds the logs of every key a reader knows, so a log can tell a link to another key's line from a
// link to a line nobody holds.
type Store struct {
	logs  map[string]*Log
	owner map[string]string // statement id -> signer, over every log
}

func NewStore() *Store { return &Store{logs: map[string]*Log{}, owner: map[string]string{}} }

// Log returns the log named for key, creating it empty.
func (s *Store) Log(key string) *Log {
	l, ok := s.logs[key]
	if !ok {
		l = &Log{key: key, store: s, lines: map[string]*wire.Statement{}}
		s.logs[key] = l
	}
	return l
}

// Keys returns every key with a log, sorted.
func (s *Store) Keys() []string {
	ks := make([]string, 0, len(s.logs))
	for k := range s.logs {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// Log is one key's log.
type Log struct {
	key   string
	store *Store
	lines map[string]*wire.Statement // by id: every line kept, including ones View refuses
	// retained are lines this reader keeps without placing them: an rc major it does not implement (nothing
	// in the envelope is read) or an alg it cannot verify. They are shown, never chained: an unverified line
	// placed in the graph would let anyone draw a FORK on any key's log.
	retained map[string]*wire.Statement
}

// Add delivers one stored line to this log. It returns a refusal when the line is refused: by wire.Read
// (parse, envelope, schema, signature), by the ownership rule, or by a log-relative rule that the lines held
// right now already decide. A line refused by Read or by ownership is not kept. A line refused by a
// log-relative rule is kept, so that a later delivery order reaches the same view (View lists it under
// Refused). A duplicate by id is a no-op (§7, "Ordering"; C-core-10).
func (l *Log) Add(line []byte) (*wire.Statement, error) {
	st, err := wire.Read(line)
	if err != nil {
		return nil, err
	}
	if !st.Verified {
		if l.retained == nil {
			l.retained = map[string]*wire.Statement{}
		}
		key := st.ID
		if key == "" { // unknown rc major: no id computed; key the retained copy by its stored bytes
			key = "unparsed:" + wire.ID(line)
		}
		l.retained[key] = st
		return st, nil
	}
	if st.Signer != l.key {
		return nil, &refusal.Refusal{Class: refusal.Intrinsic, Reason: refusal.WrongLog,
			Detail: fmt.Sprintf("signer %s in the log of %s; scope this line", st.Signer, l.key)}
	}
	if _, dup := l.lines[st.ID]; dup {
		return l.lines[st.ID], nil
	}
	l.lines[st.ID] = st
	l.store.owner[st.ID] = st.Signer
	if r := l.View().refusalOf(st.ID); r != nil {
		return st, r
	}
	return st, nil
}

// State of a placed line.
type State string

const (
	// Chained: the line reaches the first line of the log through prev, and every merges entry is chained.
	Chained State = "chained"
	// Detached: a prev or merges entry is not held (or is itself detached). Kept, attributed, shown with the
	// gap named; evaluated once the gap fills (§7, "Gaps"; C-core-143).
	Detached State = "detached"
)

// Gap names what a detached line waits for.
type Gap struct {
	// FromSeq..ToSeq is the missing stretch below the line (FromSeq <= ToSeq), when the prev chain is broken.
	FromSeq, ToSeq int64
	HasSeq         bool
	// IDs are merges entries (or a prev) that are not held, named by id (C-core-127b).
	IDs []string
}

// Line is one placed line in the view.
type Line struct {
	St      *wire.Statement
	State   State
	Waiting Gap
	// Incoherent: the line's ts is earlier than the ts of the line at its prev (C-core-106).
	Incoherent bool
}

// Refused is a kept line that breaks a rule needing the rest of the log.
type Refused struct {
	St     *wire.Statement
	Reason *refusal.Refusal
}

// View is everything derived from a log's lines.
type View struct {
	Key      string
	Lines    []Line // placed lines, by seq then id
	Refused  []Refused
	Retained []*wire.Statement // unverified lines, kept and not placed
	Forks    []dag.Fork        // over chained lines only
	Tips     []string          // chained lines with no chained successor
}

// View computes the log's state from its lines.
func (l *Log) View() View {
	v := View{Key: l.key}
	refused := map[string]*refusal.Refusal{}
	for _, st := range l.lines {
		if r := l.relativeRule(st); r != nil {
			refused[st.ID] = r
		}
	}
	held := func(id string) (*wire.Statement, bool) {
		st, ok := l.lines[id]
		if !ok || refused[id] != nil {
			return nil, false
		}
		return st, true
	}

	// Chained-ness is a fixed point: a line is chained when its prev is chained (or it is seq 0) and every
	// merges entry is chained. Iterate to the fixed point; the graph is acyclic because seq strictly drops.
	chained := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for id, st := range l.lines {
			if chained[id] || refused[id] != nil {
				continue
			}
			ok := st.Seq == 0 || chained[st.Prev]
			for _, m := range st.Merges {
				ok = ok && chained[m]
			}
			if ok {
				chained[id], changed = true, true
			}
		}
	}

	preds := map[string][]string{}
	for id, st := range l.lines {
		if refused[id] != nil {
			v.Refused = append(v.Refused, Refused{st, refused[id]})
			continue
		}
		ln := Line{St: st, State: Chained}
		if !chained[id] {
			ln.State = Detached
			ln.Waiting = l.gap(st, held, chained)
		}
		if p, ok := held(st.Prev); ok && rctime.Compare(st.TS, p.TS) < 0 {
			ln.Incoherent = true
		}
		v.Lines = append(v.Lines, ln)
		if chained[id] {
			var ps []string
			if st.Prev != "" {
				ps = append(ps, st.Prev)
			}
			preds[id] = append(ps, st.Merges...)
		}
	}
	slices.SortFunc(v.Lines, func(a, b Line) int { return cmpSeqID(a.St, b.St) })
	slices.SortFunc(v.Refused, func(a, b Refused) int { return cmpSeqID(a.St, b.St) })
	for _, st := range l.retained {
		v.Retained = append(v.Retained, st)
	}
	slices.SortFunc(v.Retained, func(a, b *wire.Statement) int { return strings.Compare(a.ID+a.Why, b.ID+b.Why) })
	v.Forks = dag.Forks(preds)
	v.Tips = dag.Tips(preds)
	return v
}

// relativeRule applies the §7 rules that need other lines. It looks only at lines held (in any log), so it
// is the same whatever order they arrived in.
func (l *Log) relativeRule(st *wire.Statement) *refusal.Refusal {
	mal := func(f string, a ...any) *refusal.Refusal {
		r := refusal.Malformed(f, a...)
		r.Detail += "; scope this line"
		return r
	}
	if st.Prev != "" {
		if p, ok := l.lines[st.Prev]; ok && p.Seq != st.Seq-1 {
			return mal("seq %d after prev at seq %d: seq is prev's plus 1", st.Seq, p.Seq)
		}
		if o, ok := l.store.owner[st.Prev]; ok && o != l.key {
			return mal("prev names a line of another key (%s)", o)
		}
	}
	for _, m := range st.Merges {
		if p, ok := l.lines[m]; ok && p.Seq >= st.Seq {
			return mal("merges names a line at seq %d, not lower than this line's seq %d", p.Seq, st.Seq)
		}
		if o, ok := l.store.owner[m]; ok && o != l.key {
			return mal("merges names a line of another key (%s)", o)
		}
	}
	return nil
}

func (v View) refusalOf(id string) *refusal.Refusal {
	for _, r := range v.Refused {
		if r.St.ID == id {
			return r.Reason
		}
	}
	return nil
}

// gap explains why st is detached: walk down prev while lines are held; where the walk stops, the stretch
// from the highest chained seq below it (+1) to the stop is missing. Unheld merges entries are named by id;
// a held but detached merges entry contributes its own gap.
func (l *Log) gap(st *wire.Statement, held func(string) (*wire.Statement, bool), chained map[string]bool) Gap {
	var g Gap
	addSeq := func(from, to int64) {
		if !g.HasSeq || from < g.FromSeq {
			g.FromSeq = from
		}
		if !g.HasSeq || to > g.ToSeq {
			g.ToSeq = to
		}
		g.HasSeq = true
	}
	var walk func(x *wire.Statement, seen map[string]bool)
	walk = func(x *wire.Statement, seen map[string]bool) {
		if seen[x.ID] || chained[x.ID] {
			return
		}
		seen[x.ID] = true
		if x.Seq > 0 && !chained[x.Prev] {
			if p, ok := held(x.Prev); ok {
				walk(p, seen)
			} else {
				addSeq(l.highestChainedBelow(x.Seq, chained)+1, x.Seq-1)
			}
		}
		for _, m := range x.Merges {
			if chained[m] {
				continue
			}
			if p, ok := held(m); ok {
				walk(p, seen)
			} else {
				g.IDs = append(g.IDs, m)
			}
		}
	}
	walk(st, map[string]bool{})
	slices.Sort(g.IDs)
	g.IDs = slices.Compact(g.IDs)
	return g
}

func (l *Log) highestChainedBelow(seq int64, chained map[string]bool) int64 {
	best := int64(-1)
	for id := range chained {
		if s := l.lines[id].Seq; s < seq && s > best {
			best = s
		}
	}
	return best
}

func cmpSeqID(a, b *wire.Statement) int {
	switch {
	case a.Seq < b.Seq:
		return -1
	case a.Seq > b.Seq:
		return 1
	}
	return strings.Compare(a.ID, b.ID)
}

// Short is the display alias of an id (wire-format note §3): its first 12 hex characters.
func Short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// Render is the log display: one line per placed statement, then forks and refusals. It is a function of the
// view only, so two views with the same content render identically. Tokens are FORK, cleared, detached,
// incoherent, refused, unsupported (claims-model note §13).
func (v View) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "log %s\n", v.Key)
	for _, ln := range v.Lines {
		fmt.Fprintf(&b, "  seq %d %s %s", ln.St.Seq, Short(ln.St.ID), ln.St.Kind)
		if len(ln.St.Merges) > 0 {
			ms := make([]string, len(ln.St.Merges))
			for i, m := range ln.St.Merges {
				ms[i] = Short(m)
			}
			fmt.Fprintf(&b, " merges %s", strings.Join(ms, ","))
		}
		if ln.St.Status != wire.Valid {
			fmt.Fprintf(&b, " [%s: %s]", ln.St.Status, ln.St.Why)
		}
		if ln.State == Detached {
			b.WriteString(" detached: waiting for " + ln.Waiting.describe(v.Key))
		}
		if ln.Incoherent {
			b.WriteString(" incoherent")
		}
		b.WriteString("\n")
	}
	for _, f := range v.Forks {
		at := "the first line"
		if f.At != "" {
			at = Short(f.At)
		}
		br := make([]string, len(f.Branches))
		for i, x := range f.Branches {
			br[i] = Short(x)
		}
		if f.Cleared {
			cb := make([]string, len(f.ClearedBy))
			for i, x := range f.ClearedBy {
				cb[i] = Short(x)
			}
			fmt.Fprintf(&b, "  FORK at %s: branches %s, cleared by %s (merged)\n", at, strings.Join(br, ","), strings.Join(cb, ","))
		} else {
			tp := make([]string, len(f.Tips))
			for i, x := range f.Tips {
				tp[i] = Short(x)
			}
			fmt.Fprintf(&b, "  FORK at %s: branches %s, tips %s\n", at, strings.Join(br, ","), strings.Join(tp, ","))
		}
	}
	for _, r := range v.Refused {
		fmt.Fprintf(&b, "  refused seq %d %s: %s\n", r.St.Seq, Short(r.St.ID), r.Reason)
	}
	for _, st := range v.Retained {
		fmt.Fprintf(&b, "  retained %s [unsupported: %s]\n", Short(st.ID), st.Why)
	}
	return b.String()
}

func (g Gap) describe(key string) string {
	var parts []string
	if g.HasSeq {
		r := strconv.FormatInt(g.FromSeq, 10)
		if g.ToSeq != g.FromSeq {
			r += "–" + strconv.FormatInt(g.ToSeq, 10)
		}
		parts = append(parts, "seq "+r+" of "+key)
	}
	for _, id := range g.IDs {
		parts = append(parts, id)
	}
	return strings.Join(parts, ", ")
}
