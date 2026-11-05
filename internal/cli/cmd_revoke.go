package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// revoke: the writer's `revoke_key` (storage note §4.2; claims-model note §4.1; wire-format note §5, §7). A
// revocation cuts every line of the key outside its own history, so the tool builds that history by reason:
//
//   - soft (`superseded`, `cessation_of_operation`): the owner retires a key it still controls, so every held tip
//     is merged and nothing is cut by accident; except a tip whose branch carries a `rotate_key` or `revoke_key`
//     outside the history being extended, which is refused (keylog.View.SoftRevokeMerges), because folding it in
//     would let that event outrank the revocation (C-core-127c);
//   - hard (`key_compromise`): nothing is merged unless the owner names it (--merge), and the owner names
//     `last_good` (--last-good <id>, or none to leave nothing of the key counting). The output lists every tip
//     and says which stay in the revocation's history and which are cut.
//
// The three reasons the format documents are offered and there is no default; without --reason the command asks
// on a terminal and refuses otherwise (exit 2). Another reason token is still a valid statement (it reads as
// hard); it is signed with publish --draft, not offered here. The line is signed and committed through the same
// path as publish (key file, --prev, --ts, --dry-run, one journal record).

// revokeReasons are the documented reasons (wire-format note §5), in prompt order, with what each does.
var revokeReasons = []struct{ name, what string }{
	{"key_compromise", "hard: someone else may hold the key; only the history of --last-good counts, and nothing is merged unless you name it"},
	{"superseded", "soft: you replaced the key; every line you hold of it keeps counting, and every held tip is merged"},
	{"cessation_of_operation", "soft: you stopped using the key; as superseded"},
}

func revokeReasonKnown(r string) bool {
	return slices.ContainsFunc(revokeReasons, func(x struct{ name, what string }) bool { return x.name == r })
}

// revokeHard reports whether a reason is hard, from the one rule the resolver applies (keylog.KeyEvent.Hard).
func revokeHard(reason string) bool {
	return keylog.KeyEvent{Kind: "revoke_key", Reason: reason}.Hard()
}

// exitWriterRefused is the exit of a writer refusal decided by a check over the held statements that ran to
// completion: the request fails it, and only a different request (not more statements, not waiting) changes the
// answer. It is ExitWrong, the code claims-model note §13 gives a completed check that disagreed and that the
// pre-pin check already uses for a failed rule. One constant, so the choice is flipped in one place.
const exitWriterRefused = ExitWrong

// lastGoodNone is the --last-good value that names no line: under a hard reason nothing of the key counts.
const lastGoodNone = "none"

func init() {
	flags := slices.Clone(writerFlags)
	names := make([]string, len(revokeReasons))
	for i, r := range revokeReasons {
		names[i] = r.name
	}
	flags = append(flags,
		Flag{Name: "reason", Value: "reason", Help: "one of " + strings.Join(names, ", ") + "; no default; required when stdin is not a terminal",
			Check: func(v string) error {
				if !revokeReasonKnown(v) {
					return errors.New("not one of " + strings.Join(names, ", "))
				}
				return nil
			}},
		Flag{Name: "last-good", Value: "id|none", Help: "hard reason only, required: the last line of your log you vouch for (it and its ancestors keep counting), or none",
			Check: func(v string) error {
				if v != lastGoodNone && !isID(v) {
					return errors.New("not a statement id (64 lowercase hex) or none")
				}
				return nil
			}},
		Flag{Name: "merge", Value: "id,…", Help: "hard reason only: lines of your log to keep, comma-separated (merged into the revocation's history)",
			Check: func(v string) error {
				for _, x := range strings.Split(v, ",") {
					if !isID(x) {
						return errors.New("not a comma-separated list of statement ids")
					}
				}
				return nil
			}},
		Flag{Name: "note", Value: "text", Help: "a note recorded in the revocation"},
	)
	Register(&Command{Name: "revoke", Summary: "revoke your signing key: sign a revoke_key whose history keeps what you choose",
		Store: true, Writes: true, Flags: flags, Prepare: prepareRevoke, Run: revokeCmd,
		Help: "A revocation cuts every line of the key outside its own history (prev, merges and their ancestors). " +
			"Soft reasons (superseded, cessation_of_operation) merge every tip this store holds of your log, so nothing is cut; a tip whose branch carries a rotate_key or revoke_key outside the line you extend is refused (exit 1), because merging it would let that event outrank the revocation: use key_compromise with --last-good instead. " +
			"With a forked log and no --prev, a soft revocation extends the highest tip when no branch carries a key event, and otherwise asks for --prev. " +
			"key_compromise merges nothing unless you name it with --merge and needs --last-good <id> or --last-good none; on a forked log it needs --prev. " +
			"Every tip is listed with what happens to it, and the lines that stop counting are named. --dry-run signs nothing and writes nothing (with key_compromise it runs without --last-good, to list the tips). " +
			"Exit 0 signed and committed (or the dry run); 1 refused after the check over your log completed (nothing signed); 2 did not start (no reason and no terminal, a missing --last-good, conflicting options, no usable key); 3 could not decide (a forked log without --prev, a line it names not held) or a failure after work started.",
	})
}

// revokePrep is what prepareRevoke read.
type revokePrep struct {
	pubPrep
	reason   string
	lastGood string // "" when not given, lastGoodNone, or an id
	merges   []string
	note     string
}

func prepareRevoke(c *Ctx) *Problem {
	p := &revokePrep{}
	reason, ok := c.Flag("reason")
	if !ok {
		if !c.Env.Interactive {
			return usage("missing-argument", "revoke needs --reason when stdin is not a terminal",
				"there is no default reason, and a revocation's reason decides what keeps counting; nothing was done", "option --reason",
				"give --reason key_compromise, superseded or cessation_of_operation", "")
		}
		r, prob := askReason(c.Env)
		if prob != nil {
			return prob
		}
		reason = r
	}
	p.reason = reason
	hard := revokeHard(reason)
	lg, hasLG := c.Flag("last-good")
	mg, hasMerge := c.Flag("merge")
	_, dry := c.Flag("dry-run")
	switch {
	case !hard && hasLG:
		return usage("conflicting-options", "--last-good applies to a hard reason only",
			"a soft revocation keeps the key's whole history counting, so last_good would change nothing; nothing was done", "option --last-good",
			"drop --last-good, or revoke with key_compromise", lg)
	case !hard && hasMerge:
		return usage("conflicting-options", "--merge applies to a hard reason only",
			"a soft revocation merges every held tip itself; nothing was done", "option --merge", "drop --merge, or revoke with key_compromise", mg)
	case hard && !hasLG && !dry:
		return usage("missing-argument", "a hard revocation needs --last-good",
			"only the history of last_good keeps counting; the tool does not pick it for you; nothing was done", "option --last-good",
			"run with --dry-run to list your log's tips, then give --last-good <id> (or --last-good none to keep nothing)", "")
	}
	p.lastGood = lg
	if hasMerge {
		for _, m := range strings.Split(mg, ",") {
			if !slices.Contains(p.merges, m) {
				p.merges = append(p.merges, m)
			}
		}
		slices.Sort(p.merges)
	}
	p.note, _ = c.Flag("note")
	if prob := prepareCommon(c, &p.pubPrep); prob != nil {
		return prob
	}
	c.Prep = p
	return nil
}

// askReason prompts on stderr and reads one line from stdin: a reason's number or its name.
func askReason(env *Env) (string, *Problem) {
	var b strings.Builder
	b.WriteString("Why is this key being revoked? (no default)\n")
	for i, r := range revokeReasons {
		fmt.Fprintf(&b, "  %d) %s: %s\n", i+1, r.name, r.what)
	}
	b.WriteString("reason: ")
	if env.Stderr != nil {
		io.WriteString(env.Stderr, b.String())
	}
	var line string
	if env.Stdin != nil {
		line, _ = bufio.NewReader(io.LimitReader(env.Stdin, 256)).ReadString('\n')
	}
	line = strings.TrimSpace(line)
	if n, err := strconv.Atoi(line); err == nil && n >= 1 && n <= len(revokeReasons) {
		return revokeReasons[n-1].name, nil
	}
	if revokeReasonKnown(line) {
		return line, nil
	}
	return "", usage("missing-argument", "no reason was chosen", "the answer was not one of the listed reasons; nothing was done",
		"option --reason", "run again and choose 1, 2 or 3, or give --reason", line)
}

// revokePlan is the revocation's place in the log and what it keeps.
type revokePlan struct {
	h       head
	merges  []string
	history map[string]bool // the new line's ancestors (prev, merges, and theirs)
	listing bool            // a hard dry run on a forked log with no --prev: the tips are listed, nothing is placed
}

func revokeCmd(c *Ctx) (*Obj, int, error) {
	p := c.Prep.(*revokePrep)
	k := p.key.Key
	wl := lockFor(c, k.Signer())
	defer wl.Unlock()
	v, err := loadView(c.Store, nil)
	if err != nil {
		return nil, 0, failed(err, "store", false, "run status, then fsck")
	}
	lv := v.logs.Log(k.Signer()).View()
	hard := revokeHard(p.reason)
	chained := map[string]*wire.Statement{}
	for _, ln := range lv.Lines {
		if ln.State == keylog.Chained {
			chained[ln.St.ID] = ln.St
		}
	}
	plan, prob := planRevoke(c, p, lv, chained, hard)
	if prob != nil {
		return nil, 0, prob
	}
	out := newObj().set("reason", textV(p.reason))
	noteLock(out, wl)
	afterHead()
	if hard {
		out.set("reason_kind", textV("hard: only the history of last_good keeps counting"))
	} else {
		out.set("reason_kind", textV("soft: the key retired; its history keeps counting"))
	}
	out.set("tips", revokeTips(lv, plan))
	if hard && p.lastGood == "" {
		// a dry run without --last-good: the tips are the answer; nothing to sign yet
		return out.set("dry_run", boolV(true)).set("committed", boolV(false)).
			set("next", textV("choose last_good (a line whose history you vouch for) and run again with --last-good <id> or --last-good none; name other lines to keep with --merge")), ExitOK, nil
	}
	body := &canon.Object{Members: map[string]canon.Value{}}
	setMember(body, "reason", canon.String(p.reason))
	if hard && p.lastGood != lastGoodNone {
		if !plan.history[p.lastGood] {
			return nil, 0, &Problem{Slug: "last-good-outside-history", Title: "last_good is outside the revocation's history",
				Class: refusal.Policy, Scope: "option --last-good",
				Detail: "the line --last-good names is not prev, a merged line or one of their ancestors in this key's log here, so the revocation would leave nothing of the key counting; nothing was signed or appended",
				Next:   "name a line of the history you extend (or --merge its branch), or give --last-good none to keep nothing", Peer: p.lastGood, Exit: exitWriterRefused}
		}
		setMember(body, "last_good", canon.String(p.lastGood))
	}
	if p.note != "" {
		setMember(body, "note", canon.String(p.note))
	}
	st, err := wire.Write(wire.Draft{Kind: "revoke_key", Seq: plan.h.seq, Prev: plan.h.prev, Merges: plan.merges, TS: p.ts, Body: body}, k, Now())
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
	o, code, err := commitUnit(c, out, "revoke", sts, nil, "", head{})
	if err == nil && o != nil {
		if hard && p.lastGood == lastGoodNone {
			o.set("warning", textV("last_good none: no line of this key counts any more, the revocation's own history included"))
		}
	}
	return o, code, err
}

// planRevoke places the revocation: prev (named, the one tip, or for a soft reason the highest tip of a fork with
// no key event off the common history), and its merges by reason.
func planRevoke(c *Ctx, p *revokePrep, lv keylog.View, chained map[string]*wire.Statement, hard bool) (revokePlan, *Problem) {
	var plan revokePlan
	prev, named := c.Flag("prev")
	switch {
	case named:
		if chained[prev] == nil {
			return plan, &Problem{Slug: "prev-not-held", Title: "the line named by --prev is not a chained line of your log here",
				Class: refusal.Policy, Scope: "option --prev", Detail: "nothing was signed or appended",
				Next: "name a chained line of this key's log (commons show <id>), or omit --prev", Peer: prev, Exit: ExitCouldNot}
		}
	case len(lv.Lines) == 0 && len(lv.Retained) == 0:
		// no line of the key is held: the revocation is its first line
	case len(lv.Tips) == 1:
		prev = lv.Tips[0]
	case len(lv.Tips) > 1:
		if hard && p.lastGood == "" {
			// a dry run listing the tips of a forked log: nothing is extended yet
			plan.listing = true
			return plan, nil
		}
		pick, why := softPrev(lv, chained)
		if hard || pick == "" {
			if hard {
				why = "a hard revocation keeps only the history you choose, so the tool does not pick a tip"
			}
			return plan, &Problem{Slug: "log-fork", Title: "your log has a FORK", Class: refusal.Policy, Scope: "this key's log",
				Detail: "this store holds " + strconv.Itoa(len(lv.Tips)) + " tips of this key's log (" + shortList(lv.Tips) + "); " + why +
					"; nothing was signed or appended",
				Next: "name the line to extend with --prev <id> (run with --dry-run --prev <id> to see what each choice keeps)", Exit: ExitCouldNot}
		}
		prev = pick
	default:
		return plan, &Problem{Slug: "log-detached", Title: "your log's first line is not held here", Class: refusal.Policy, Scope: "this key's log",
			Detail: "this store holds lines of this key, none chained to the first; the next seq is unknown; nothing was signed or appended",
			Next:   "fetch the key's earlier lines, or name --prev <id>", Exit: ExitCouldNot}
	}
	if prev != "" {
		plan.h = head{seq: chained[prev].Seq + 1, prev: prev}
	}
	if !hard && prev != "" {
		merges, r := lv.SoftRevokeMerges(prev)
		if r != nil {
			return plan, &Problem{Slug: "refused", Title: "refused: " + r.Reason, Class: r.Class, Scope: "this key's log",
				Detail: "the soft revocation's merge set was checked against every tip of your log held here and cannot be signed; the reason is in peer_text; nothing was signed or appended",
				Next:   "revoke with --reason key_compromise and --last-good <your own line> (it cuts the other branch), or extend that tip with --prev if it is yours",
				Peer:   r.Detail, Exit: exitWriterRefused}
		}
		plan.merges = merges
	}
	if hard {
		for _, m := range p.merges {
			st := chained[m]
			switch {
			case st == nil:
				return plan, &Problem{Slug: "merge-not-held", Title: "a line named by --merge is not a chained line of your log here",
					Class: refusal.Policy, Scope: "option --merge", Detail: "nothing was signed or appended",
					Next: "name chained lines of this key's log (commons show <id>)", Peer: m, Exit: ExitCouldNot}
			case m == prev || ancestors(prev, chained)[m]:
				return plan, &Problem{Slug: "merge-in-history", Title: "a line named by --merge is already in the history you extend",
					Class: refusal.Intrinsic, Scope: "option --merge", Detail: "merges never names prev or one of its ancestors; nothing was signed or appended",
					Next: "drop it from --merge", Peer: m, Exit: exitWriterRefused}
			case prev == "" || st.Seq >= plan.h.seq:
				return plan, &Problem{Slug: "refused", Title: "refused: " + keylog.TipAboveNext, Class: refusal.Policy, Scope: "option --merge",
					Detail: "merges may name only lines below the new line's seq (" + strconv.FormatInt(plan.h.seq, 10) + "); nothing was signed or appended",
					Next:   "extend that line with --prev instead", Peer: m, Exit: exitWriterRefused}
			}
		}
		plan.merges = p.merges
	}
	plan.history = map[string]bool{}
	for _, x := range append([]string{prev}, plan.merges...) {
		if x == "" {
			continue
		}
		plan.history[x] = true
		for a := range ancestors(x, chained) {
			plan.history[a] = true
		}
	}
	return plan, nil
}

// softPrev picks the line a soft revocation extends on a forked log when --prev is not given: the one tip with the
// highest seq, and only when no tip's branch carries a key event outside any other tip's history. Otherwise which
// branch is extended decides which event outranks which, and that is the owner's call; it returns "" and why.
func softPrev(lv keylog.View, chained map[string]*wire.Statement) (string, string) {
	for _, t := range lv.Tips {
		if f := lv.ForeignKeyEvents(t); len(f) > 0 {
			return "", "a branch carries a key event (" + f[0].Events[0].Kind + " " + keylog.Short(f[0].Events[0].St.ID) +
				" on tip " + keylog.Short(f[0].Tip) + "), so which line you extend decides what the revocation keeps"
		}
	}
	best, top := "", int64(-1)
	tie := false
	for _, t := range lv.Tips {
		switch s := chained[t].Seq; {
		case s > top:
			best, top, tie = t, s, false
		case s == top:
			tie = true
		}
	}
	if tie {
		return "", "two tips share the highest seq, and merges names only lower lines"
	}
	return best, ""
}

// ancestors is every chained line reachable from id through prev and merges, id excluded.
func ancestors(id string, chained map[string]*wire.Statement) map[string]bool {
	seen := map[string]bool{}
	st := chained[id]
	if st == nil {
		return seen
	}
	stack := append([]string{}, st.Merges...)
	if st.Prev != "" {
		stack = append(stack, st.Prev)
	}
	for len(stack) > 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		s, ok := chained[x]
		if !ok || seen[x] {
			continue
		}
		seen[x] = true
		if s.Prev != "" {
			stack = append(stack, s.Prev)
		}
		stack = append(stack, s.Merges...)
	}
	return seen
}

// revokeTips lists every tip of the log with what the revocation does to it, and the key events on its branch
// outside the extended line's history.
func revokeTips(lv keylog.View, plan revokePlan) listV {
	events := map[string][]keylog.KeyEvent{}
	if plan.h.prev != "" {
		for _, f := range lv.ForeignKeyEvents(plan.h.prev) {
			events[f.Tip] = f.Events
		}
	}
	l := listV{}
	for _, t := range lv.Tips {
		r := rowObj().set("tip", refV(t))
		switch {
		case plan.listing:
			r.set("revocation", textV("a candidate: name the line to extend with --prev"))
		case t == plan.h.prev:
			r.set("revocation", textV("extended (prev)"))
		case slices.Contains(plan.merges, t):
			r.set("revocation", textV("merged: keeps counting"))
		case plan.history[t]:
			r.set("revocation", textV("in the history through a merged line: keeps counting"))
		default:
			r.set("revocation", textV("outside the revocation's history: cut (counts toward nothing)"))
		}
		if evs := events[t]; len(evs) > 0 {
			var what []string
			for _, ev := range evs {
				what = append(what, ev.Kind+" "+keylog.Short(ev.St.ID))
			}
			r.set("key_events_on_branch", textV(strings.Join(what, ", ")+" (outside the line you extend; this store keeps no record of which lines it signed)"))
		}
		l = append(l, r)
	}
	return l
}

// revokeCut resolves the key's log with the new line added and lists the lines that counted before and do not
// after: what the revocation takes away, as the resolver will read it.
func revokeCut(c *Ctx, signer string, sts []signed) listV {
	lines, err := c.Store.Statements()
	if err != nil {
		return nil
	}
	build := func(extra []signed) *resolve.Resolver {
		logs := keylog.NewStore()
		for _, l := range lines {
			if st, err := wire.Read(l); err == nil && st.Signer == signer {
				logs.Log(signer).Add(l)
			}
		}
		for _, s := range extra {
			logs.Log(signer).Add(s.line)
		}
		return resolve.New(logs)
	}
	before, after := build(nil), build(sts)
	var ids []string
	for id := range lines {
		b, ok1 := before.Statement(id)
		a, ok2 := after.Statement(id)
		if ok1 && ok2 && b.Counts() && !a.Counts() {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	l := listV{}
	for _, id := range ids {
		st, _ := after.Statement(id)
		l = append(l, rowObj().set("statement", refV(id)).set("kind", peerV(st.St.Kind)).set("seq", intV(st.St.Seq)))
	}
	return l
}
