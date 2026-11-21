package cli

import (
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/keylog"
)

// The two axes of a delegate key (fixed-root identity profile §4.1, "requirements on consumers"): every view of a
// key K shows side by side its bare-key status (its own key events: "self-revoked; bare-key lines after X do not
// count") and, for each grant naming K, that grant's state ("G from I: open / cut at L / cut null / unknown"). A
// key's own revoke_key or rotate_key closes no grant: only the identity's root cuts one (§4.1), so an emergency
// self-revoke shuts off nothing an open grant authorizes.

// freshnessNote is printed beside every identity answer: the evaluator answers relative to the held evidence, and
// a cut this reader does not hold is not ruled out (profile §1: an offline bundle can omit a cut).
const freshnessNote = "relative to held evidence; no claim that no cut exists"

// setFreshness adds the freshness member and its note to an identity answer block. The value is the evaluator's
// own word, printed as text: `freshness` is not a token member (anchor status prints a chain view's freshness there).
func setFreshness(o *Obj) *Obj {
	return o.set("freshness", textV(identity.NotEstablished)).set("freshness_note", textV(freshnessNote))
}

// isKeyRef reports whether s is a signer as the wire writes it (ed25519:<64 hex> or 0x<40 hex>).
func isKeyRef(s string) bool { return reGrantee.MatchString(s) }

// keyObj is `show <key>`: the bare-key axis (the key's log and its key events) beside the grant axis (every grant
// naming the key, by id, with its state). explain adds nothing but the statements behind both.
func (v *view) keyObj(key string) *Obj {
	o := newObj().set("key", refV(key))
	lv := v.logs.Log(key).View()
	o.set("lines", intV(int64(len(lv.Lines)))).set("tips", refs(lv.Tips...))
	o.set("bare_key", bareKeyObj(lv.KeyState()))
	o.set("grants", v.grantsObj(key))
	if rl := v.rootLinesFor(key); len(rl) > 0 {
		o.set("ordinary_root_lines", rl)
	}
	return o
}

// bareKeyObj is the key's own key events and what they leave counting as bare-key evidence (claims-model §4.1;
// identity statements under a grant are not read through these, profile §4.1).
func bareKeyObj(ks keylog.KeyState) *Obj {
	o := newObj()
	var in []keylog.KeyEvent
	for _, ev := range ks.Events {
		if ev.InForce {
			in = append(in, ev)
		}
	}
	if len(in) == 0 {
		return o.set("state", tokV(tok("no key event"))).
			set("detail", textV("no rotate_key or revoke_key of this key is held: its bare-key lines count by the usual rules"))
	}
	events := listV{}
	retired := false
	for _, ev := range ks.Events {
		e := newObj().set("statement", refV(ev.St.ID)).set("kind", peerV(ev.Kind)).set("seq", intV(ev.St.Seq))
		if ev.Reason != "" {
			e.set("reason", peerV(ev.Reason))
		}
		if ev.LastGood != "" {
			e.set("last_good", refV(ev.LastGood))
		}
		if ev.Successor != "" {
			e.set("successor", refV(ev.Successor))
		}
		switch {
		case !ev.InForce:
			e.set("effect", textV("not in force (detached): it changes nothing until its gap fills"))
		case ev.Kind == "rotate_key":
			retired = true
			e.set("effect", textV("rotated: bare-key lines after "+keylog.Short(ev.St.ID)+" do not count; its history counts"))
		case ev.Hard() && ev.LastGood != "":
			retired = true
			e.set("effect", textV("self-revoked (hard): bare-key lines outside last_good "+keylog.Short(ev.LastGood)+"'s history, and after "+keylog.Short(ev.St.ID)+", do not count"))
		case ev.Hard():
			retired = true
			e.set("effect", textV("self-revoked (hard, no last_good): no bare-key line of the key counts"))
		default:
			retired = true
			e.set("effect", textV("self-revoked (soft): bare-key lines after "+keylog.Short(ev.St.ID)+" do not count; its history counts"))
		}
		events = append(events, e)
	}
	state := "no key event"
	if retired {
		state = "self-revoked"
	}
	return o.set("state", tokV(tok(state))).set("events", events).
		set("grants_note", textV("a key's own revoke_key or rotate_key closes no grant naming it; only the identity's root closes one, with identity cut"))
}

// grantsObj lists every grant naming key, by grant id, with its grant-level state. Empty when the reader holds no
// rc/2 line (no evaluator) or no grant names the key.
func (v *view) grantsObj(key string) listV {
	l := listV{}
	a, ok := v.actors.(*identity.Actors)
	if !ok {
		return l
	}
	for _, g := range a.Grants(key) {
		l = append(l, grantRow(g))
	}
	return l
}

// grantRow is one grant of the grant axis: id, identity, state, the last_good lines of a cut at a line, the cuts
// held, the evaluator's reasons and the freshness every identity answer carries.
func grantRow(g identity.Grant) *Obj {
	o := newObj().set("grant", refV(g.Grant)).set("identity", refV(g.Identity)).set("state", tokV(tok(g.State)))
	if len(g.LastGood) > 0 {
		o.set("last_good", refs(g.LastGood...))
	}
	if len(g.Cuts) > 0 {
		o.set("cuts", refs(g.Cuts...))
	}
	if len(g.Why) > 0 {
		o.set("reasons", texts(g.Why...))
	}
	return setFreshness(o)
}

// grantsNotClosedNote is the line printed beside grantsNotClosed.
func grantsNotClosedNote() string {
	return "this key event closes none of the grants below: an act under an open grant after it still counts for the grant's identity " +
		"(with a delegate_self_event warning); only the identity's root closes a grant (commons identity cut)"
}

// keyInputs is every statement explain of a key reads: the key's own lines (its key events among them), and for
// each grant naming it the grant, its identity's inception and the cuts addressed to it.
func (v *view) keyInputs(key string) []string {
	var out []string
	lv := v.logs.Log(key).View()
	for _, ln := range lv.Lines {
		out = append(out, ln.St.ID)
	}
	if a, ok := v.actors.(*identity.Actors); ok {
		for _, g := range a.Grants(key) {
			out = append(out, g.Grant)
			if g.Identity != "" {
				out = append(out, g.Identity)
			}
			out = append(out, g.Cuts...)
			out = append(out, g.LastGood...)
		}
	}
	return out
}

// setGrantsNotClosed adds, to a revoke or rotate output, every grant naming key, by id with its state: a key event
// closes none of them (profile §4.1), so a grant already cut by its root is listed too, showing that state. Nothing
// is added when no grant names the key.
func setGrantsNotClosed(out *Obj, v *view, key string) {
	if l := v.grantsObj(key); len(l) > 0 {
		out.set("grants_not_closed", l).set("grants_note", textV(grantsNotClosedNote()))
	}
}
