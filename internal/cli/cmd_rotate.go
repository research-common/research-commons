package cli

import (
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// rotate: the writer's `rotate_key` (storage note §4.2; claims-model note §4.1; wire-format note §5, §7). A
// rotation names a successor key and retires the signing key. Like a soft revocation it cuts every line of the
// key outside its own history, so the tool builds that history the same way: every held tip is merged, so
// nothing is cut by accident, except a tip whose branch carries a `rotate_key` or `revoke_key` outside the line
// being extended, which is refused (keylog.View.SoftRevokeMerges, C-core-127c). The line is signed and
// committed through the same path as publish and revoke (key file, --prev, --ts, --dry-run, one journal record).
//
// Three refusals are the rotation's own:
//
//   - the successor is the signing key itself: the request alone decides it (exit 2);
//   - the history being extended already holds an in-force key event: a key event signed after another counts
//     only where it makes things stricter (claims-model §4.1), and a rotation never does, so it would count toward
//     nothing (exit 1);
//   - the successor's log held here carries a key event, in force or detached: the successor is already retired,
//     or will be once its gap fills, so it cannot carry the key on (exit 1).
//
// The successor is named by --successor <key> or derived from --successor-key <file>; the file is read under the
// same custody checks as --key and only its signer is used or printed.

// reSuccessor is the shape of a key the format can name as a successor (wire-format note §5: `key`).
var reSuccessor = regexp.MustCompile(`^(0x[0-9a-f]{40}|ed25519:[0-9a-f]{64})$`)

func init() {
	flags := slices.Clone(writerFlags)
	flags = append(flags,
		Flag{Name: "successor", Value: "key", Help: "the successor key (ed25519:<64 hex> or 0x<40 hex>); exactly one of --successor and --successor-key",
			Check: func(v string) error {
				if !reSuccessor.MatchString(v) {
					return errors.New("not a key (ed25519: + 64 lowercase hex, or 0x + 40 lowercase hex)")
				}
				return nil
			}},
		Flag{Name: "successor-key", Value: "file", Help: "the successor's key file: its signer is named (the key is never printed); exactly one of --successor and --successor-key"},
	)
	Register(&Command{Name: "rotate", Summary: "rotate your signing key: sign a rotate_key naming its successor",
		Store: true, Writes: true, Flags: flags, Prepare: prepareRotate, Run: rotateCmd,
		Help: "A rotation retires your key and names its successor; the successor starts its own log and inherits no claims. " +
			"Like a soft revocation, it merges every tip this store holds of your log, so nothing is cut; a tip whose branch carries a rotate_key or revoke_key outside the line you extend is refused (exit 1): use revoke --reason key_compromise with --last-good instead. " +
			"With a forked log and no --prev, the rotation extends the highest tip when no branch carries a key event, and otherwise asks for --prev. " +
			"It is refused (exit 1) when the history it extends already holds an in-force key event (the rotation would count toward nothing) and when the successor's log here carries a key event. " +
			"Every tip is listed with what happens to it. --dry-run signs nothing and writes nothing. " +
			"Exit 0 signed and committed (or the dry run); 1 refused after the check over the logs completed (nothing signed); 2 did not start (no successor or both options, the successor is your own key, no usable key); 3 could not decide (a forked log without --prev, a line it names not held) or a failure after work started.",
	})
}

// rotatePrep is what prepareRotate read.
type rotatePrep struct {
	pubPrep
	successor string
}

func prepareRotate(c *Ctx) *Problem {
	p := &rotatePrep{}
	succ, hasSucc := c.Flag("successor")
	file, hasFile := c.Flag("successor-key")
	switch {
	case hasSucc && hasFile:
		return usage("conflicting-options", "--successor and --successor-key name the same thing",
			"give the successor once; nothing was done", "option --successor-key", "drop one of the two", "")
	case !hasSucc && !hasFile:
		return usage("missing-argument", "rotate needs a successor",
			"a rotation names the key that carries on; there is no default; nothing was done", "option --successor",
			"give --successor <key>, or --successor-key <file> (create one with commons key new --out <file>)", "")
	case hasFile:
		k, prob := loadKey(file, "option --successor-key")
		if prob != nil {
			return prob
		}
		succ = k.Key.Signer()
	}
	p.successor = succ
	if prob := prepareCommon(c, &p.pubPrep); prob != nil {
		return prob
	}
	if p.successor == p.key.Key.Signer() {
		return usage("conflicting-options", "the successor is the signing key itself",
			"a key cannot succeed itself; nothing was done", "option --successor",
			"name another key as the successor (commons key new --out <file>, then --successor-key <file>)", p.successor)
	}
	c.Prep = p
	return nil
}

func rotateCmd(c *Ctx) (*Obj, int, error) {
	p := c.Prep.(*rotatePrep)
	k := p.key.Key
	wl := lockFor(c, k.Signer())
	defer wl.Unlock()
	v, err := loadView(c.Store, nil)
	if err != nil {
		return nil, 0, failed(err, "store", false, "run status, then fsck")
	}
	// the successor's own log: a key event there, in force or waiting on a gap, means it cannot carry the key on
	if evs := v.logs.Log(p.successor).View().KeyState().Events; len(evs) > 0 {
		return nil, 0, &Problem{Slug: "successor-retired", Title: "refused: the successor's log carries a key event",
			Class: refusal.Policy, Scope: "option --successor",
			Detail: "this store holds " + eventList(evs) + " in the successor's log; a retired key (or one that will be once its log's gap fills) cannot carry yours on; nothing was signed or appended",
			Next:   "name a key with no rotate_key or revoke_key (commons key new --out <file>)", Peer: p.successor, Exit: exitWriterRefused}
	}
	lv := v.logs.Log(k.Signer()).View()
	chained := map[string]*wire.Statement{}
	for _, ln := range lv.Lines {
		if ln.State == keylog.Chained {
			chained[ln.St.ID] = ln.St
		}
	}
	plan, prob := planRevoke(c, &revokePrep{}, lv, chained, false)
	if prob != nil {
		if prob.Slug == "refused" && prob.Scope == "this key's log" {
			prob.Detail = "the rotation's merge set (every tip, as for a soft revocation) was checked against every tip of your log held here and cannot be signed; the reason is in peer_text; nothing was signed or appended"
			prob.Next = "revoke with --reason key_compromise and --last-good <your own line> (it cuts the other branch), or extend that tip with --prev if it is yours"
		}
		return nil, 0, prob
	}
	// a key event already in force in the history extended: the rotation would sit after it and count toward nothing
	var before []keylog.KeyEvent
	for _, ev := range lv.KeyState().Events {
		if ev.InForce && plan.history[ev.St.ID] {
			before = append(before, ev)
		}
	}
	if len(before) > 0 {
		return nil, 0, &Problem{Slug: "key-already-retired", Title: "refused: your key already has a key event in force",
			Class: refusal.Policy, Scope: "this key's log",
			Detail: "the history the rotation extends holds " + eventList(before) + "; a key event after another counts only where it is stricter, and a rotation never is, so this one would count toward nothing; nothing was signed or appended",
			Next:   "name the successor from the key that is current, or, if the earlier event is not yours, revoke with --reason key_compromise and --last-good", Peer: before[0].St.ID, Exit: exitWriterRefused}
	}
	out := newObj().set("successor", refV(p.successor))
	noteLock(out, wl)
	afterHead()
	out.set("tips", rotateTips(lv, plan))
	body := &canon.Object{Members: map[string]canon.Value{}}
	setMember(body, "successor", canon.String(p.successor))
	st, err := wire.Write(wire.Draft{Kind: "rotate_key", Seq: plan.h.seq, Prev: plan.h.prev, Merges: plan.merges, TS: p.ts, Body: body}, k, Now())
	if err == nil && st.Status != wire.Valid {
		err = &refusal.Refusal{Class: refusal.Intrinsic, Reason: "not valid", Detail: "the signed line reads back as " + string(st.Status)}
	}
	if err != nil {
		return nil, 0, writeRefused(err)
	}
	sts := []signed{{st, st.Line()}}
	if len(plan.merges) > 0 {
		out.set("merges", refs(plan.merges...))
	}
	if cut := revokeCut(c, k.Signer(), sts); len(cut) > 0 {
		out.set("stop_counting", cut)
	}
	o, code, err := commitUnit(c, out, "rotate", sts, nil, "", head{})
	if err == nil && o != nil {
		o.set("successor_log", textV(successorLog(v.logs.Log(p.successor).View())))
	}
	return o, code, err
}

// successorLog says where the successor's log stands here: its next line starts it, or continues it.
func successorLog(sv keylog.View) string {
	if len(sv.Lines) == 0 && len(sv.Retained) == 0 {
		return "no line of the successor is held here: its next line (publish --key <successor's key file>) is its seq 0; it inherits no claims"
	}
	return "this store holds lines of the successor: its next line continues its own log; it inherits no claims"
}

// rotateTips lists every tip of the log with what the rotation does to it.
func rotateTips(lv keylog.View, plan revokePlan) listV {
	l := listV{}
	for _, t := range lv.Tips {
		r := rowObj().set("tip", refV(t))
		switch {
		case t == plan.h.prev:
			r.set("rotation", textV("extended (prev)"))
		case slices.Contains(plan.merges, t):
			r.set("rotation", textV("merged: keeps counting"))
		case plan.history[t]:
			r.set("rotation", textV("in the history through a merged line: keeps counting"))
		default:
			r.set("rotation", textV("outside the rotation's history: cut (counts toward nothing)"))
		}
		l = append(l, r)
	}
	return l
}

func eventList(evs []keylog.KeyEvent) string {
	var what []string
	for _, ev := range evs {
		s := ev.Kind + " " + keylog.Short(ev.St.ID)
		if !ev.InForce {
			s += " (detached: in force once its gap fills)"
		}
		what = append(what, s)
	}
	return strings.Join(what, ", ")
}
