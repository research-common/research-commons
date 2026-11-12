package cli

import (
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/dag"
	"github.com/research-common/research-commons/internal/keylog"
)

// A key's log forks when two lines of the key name one predecessor (claims-model note §12, storage note §4.2):
// both lines are kept and both count, and the fork is shown on every read surface until the key's owner signs a
// line that merges every tip. Every surface here reads the fork from the log's own view (keylog.View.Forks and
// ForksOn, both over dag.Forks), the computation the log display and the gate use, so "FORK" and "merged" mean
// the same thing wherever they are printed (claims-model note I12). A fork is a disclosure: it never moves an exit
// (it is not a failed check, and lines on every branch count) and never refuses anything.

// logView is the log view of key, computed once per invocation.
func (v *view) logView(key string) keylog.View {
	if lv, ok := v.logViews[key]; ok {
		return lv
	}
	if v.logViews == nil {
		v.logViews = map[string]keylog.View{}
	}
	lv := v.logs.Log(key).View()
	v.logViews[key] = lv
	return lv
}

// logLine is the placed line of statement id in its signer's log.
func (v *view) logLine(signer, id string) (keylog.Line, bool) {
	for _, ln := range v.logView(signer).Lines {
		if ln.St.ID == id {
			return ln, true
		}
	}
	return keylog.Line{}, false
}

// forkSeq is the sequence point a fork's branches were signed from: the seq every branch line carries.
func forkSeq(lv keylog.View, f dag.Fork) int64 {
	for _, ln := range lv.Lines {
		if ln.St.ID == f.Branches[0] {
			return ln.St.Seq
		}
	}
	return 0
}

// logForkObj is one fork of a log as the statement surfaces print it beside a line on it: FORK with its tips while
// it is open, merged with the clearing line once every tip is an ancestor of one line.
func logForkObj(lv keylog.View, f dag.Fork) *Obj {
	o := newObj()
	if f.Cleared() {
		o.set("state", tokV(tok("merged")))
	} else {
		o.set("state", tokV(tok("FORK")))
	}
	o.set("seq", intV(forkSeq(lv, f)))
	if f.At != "" {
		o.set("at", refV(f.At))
	}
	o.set("branches", refs(f.Branches...))
	if f.Cleared() {
		o.set("cleared_by", refV(f.ClearedBy))
	} else {
		o.set("tips", refs(f.Tips...))
	}
	return o
}

// logForkText is the one human line for the same fork: "FORK at seq N (tips …)" or "merged at seq N by <id>
// (branches …)".
func logForkText(lv keylog.View, f dag.Fork) string {
	seq := strconv.FormatInt(forkSeq(lv, f), 10)
	if f.Cleared() {
		return "merged at seq " + seq + " by " + f.ClearedBy + " (branches " + strings.Join(f.Branches, ", ") + ")"
	}
	return "FORK at seq " + seq + " (tips " + strings.Join(f.Tips, ", ") + ")"
}

// setLogForks adds the forks a statement's line is on, when it is on one of its signer's log: log_forks on JSON,
// one structured entry per fork; one "log:" line on the human surface naming each (the same tokens on both).
func (v *view) setLogForks(o *Obj, signer, id string) {
	lv := v.logView(signer)
	fs := lv.ForksOn(id)
	if len(fs) == 0 {
		return
	}
	js := listV{}
	var hs []string
	for _, f := range fs {
		js = append(js, logForkObj(lv, f))
		hs = append(hs, logForkText(lv, f))
	}
	o.setJSON("log_forks", js).setHuman("log", textV(strings.Join(hs, "; ")))
}

// logForkRows is one row per fork of every held key log, by key then fork point: what fsck reports (open and
// cleared), and, with openOnly, the marker list and status print (open forks only).
func logForkRows(logs *keylog.Store, openOnly bool) listV {
	l := listV{}
	for _, k := range logs.Keys() {
		lv := logs.Log(k).View()
		for _, f := range lv.Forks {
			if openOnly && f.Cleared() {
				continue
			}
			row := rowObj().set("key", refV(k))
			fo := logForkObj(lv, f)
			for _, m := range fo.keys {
				row.set(m, fo.vals[m])
			}
			l = append(l, row)
		}
	}
	return l
}
