package cli

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// anchor stamp [<statement-id>]: the anchor writer's first slice (bitcoin-time note §1, §2; storage note §3.2). It
// stamps a line of the signing key's own log: the raw 32 bytes of its id go to each calendar the author names, the
// pending proofs of every calendar that answered are merged into one (a union at the root, as the reference client
// writes a multi-calendar stamp), and the proof blob and an `anchors` statement {covered, proof, proof_format,
// services} are committed as one journal record. The anchors line extends a line whose history holds the covered
// head (rule 3: the head is in the anchor's own prefix). Every calendar failing appends nothing (exit 3) and prints
// the head's standing under the default by standing (§2 step 3), so the author and a later push see whether the
// head needs an anchor.
//
// Calendars are the author's local policy: --calendar (repeatable) or $COMMONS_CALENDARS; there is no default list.
// This package dials nothing: the calendar client comes from the binary (Env.Calendars), as fetch's transport does.

// CalendarsEnv names the calendars when no --calendar is given: URLs separated by commas or white space.
const CalendarsEnv = "COMMONS_CALENDARS"

// CalendarConfig is the author's choice for one stamping invocation, passed to the calendar factory.
type CalendarConfig struct {
	// AllowPrivate allows a calendar on a loopback, private or other non-global address (a local calendar).
	AllowPrivate bool
	// Timeout bounds one calendar's whole request; zero means the client's default.
	Timeout time.Duration
}

// CalendarBuilder builds the client for one calendar URL; an error refuses the URL before anything is dialled. The
// binary supplies one; nil in a build without network access (anchor stamp then answers "not available in this
// build", exit 3).
type CalendarBuilder func(url string, cfg CalendarConfig) (btctime.Calendar, error)

func init() {
	flags := slices.Clone(writerFlags)
	flags = append(flags,
		Flag{Name: "calendar", Value: "url", Repeat: true, Help: "an OpenTimestamps calendar to submit to (https only; repeatable); else $" + CalendarsEnv + " (comma- or space-separated). There is no default list: calendars are your local policy"},
		Flag{Name: "timeout", Value: "duration", Help: "give up on one calendar after this long (Go duration, e.g. 10s); default 10s", Check: positiveDuration},
		Flag{Name: "allow-private", Help: "allow a calendar on a loopback, private, link-local, shared or other non-global address (a local calendar or mirror); refused by default, checked on the address actually dialled"},
	)
	Register(&Command{Name: "anchor stamp", Summary: "timestamp a line of your log: submit its id to OpenTimestamps calendars and commit the pending proof with an anchors statement",
		Args:  []Arg{{Name: "statement-id", Shape: ShapeID, Optional: true}},
		Store: true, Writes: true, Flags: flags, Prepare: prepareStamp, Run: stampCmd,
		Help: "The covered head is the statement named (a line of your own log: an anchor bounds only its signer's log), else your log's one tip; a FORK in your log is refused until --prev names the line the anchors statement extends. " +
			"The raw 32 bytes of the head's id are submitted to each calendar in turn; with at least one pending proof back, the proofs of every calendar that answered (each checked: it parses, roots at the digest submitted, carries a pending attestation) are merged into one proof holding every calendar's pending attestation, stored as a blob, and an anchors statement {covered, proof, proof_format: " + btctime.ProofFormat + ", services: the calendars that answered} is appended after a line whose history holds the head, the two as one journal record. " +
			"A pending proof is a calendar's promise: readers show it pending, quality local, until an upgraded proof is held: run anchor upgrade once the calendars have put the commitment in a Bitcoin block (hours). Stamping the same head again appends another anchors statement; readers display the later one. " +
			"Calendars are local policy: --calendar or $" + CalendarsEnv + ", no default list (the public OpenTimestamps calendars are examples, not defaults). Only https is dialled, with no proxy; non-global addresses are refused unless --allow-private; a calendar may redirect at most three times, only to https on its own host; a response over 10000 bytes is that calendar's failure. " +
			"publish does not stamp, and nothing yet checks that a head was stamped before it leaves this machine: run anchor stamp after publish. --dry-run prints the head, the digest, the calendars and the head's standing, and contacts nothing. " +
			"Exit 0 stamped and committed (or the dry run; a calendar that failed beside one that answered is a warning); 1 refused after the check over your log (your key has a key event); 2 did not start (no calendar named, a calendar URL that is not https, the statement is not a line of your log, no usable key); 3 every calendar failed (nothing appended; the head's standing is printed: anchor required or anchor: none, and the rule that decided), a forked log without --prev, or calendars not available in this build.",
	})
}

type stampPrep struct {
	pubPrep
	urls []string
	cals []btctime.Calendar // nil when the build has no calendar client
	cfg  CalendarConfig
}

func prepareStamp(c *Ctx) *Problem {
	p := &stampPrep{}
	var prob *Problem
	if p.urls, p.cals, p.cfg, prob = prepareCalendars(c, "anchor stamp submits to"); prob != nil {
		return prob
	}
	if prob := prepareCommon(c, &p.pubPrep); prob != nil {
		return prob
	}
	c.Prep = p
	return nil
}

// prepareCalendars reads the author's calendar policy (--calendar, else $COMMONS_CALENDARS), --timeout and
// --allow-private, and builds one client per calendar through the binary's factory (nil clients in a build without
// one). Nothing is dialled. what completes "no default list" in the problem text ("anchor stamp submits to").
func prepareCalendars(c *Ctx, what string) ([]string, []btctime.Calendar, CalendarConfig, *Problem) {
	var cfg CalendarConfig
	urls := c.Repeated["calendar"]
	scope := "option --calendar"
	if len(urls) == 0 {
		urls = strings.FieldsFunc(c.Env.Getenv(CalendarsEnv), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
		scope = "environment " + CalendarsEnv
	}
	if len(urls) == 0 {
		return nil, nil, cfg, usage("no-calendar", "no calendar named",
			what+" the calendars you choose and there is no default list; nothing was contacted or appended", "invocation",
			"give --calendar <https url> (repeatable) or set "+CalendarsEnv+" (comma- or space-separated)", "")
	}
	seen := map[string]bool{}
	for _, u := range urls {
		if sc := uriScheme(u); sc != "https" {
			return nil, nil, cfg, usage("calendar-refused", "a calendar URL is not https",
				"a calendar is reached over https only; refused before dialling; nothing was contacted or appended", scope, "name an https calendar", u)
		}
		if seen[u] {
			return nil, nil, cfg, usage("calendar-refused", "a calendar is named twice", "nothing was contacted or appended", scope, "name each calendar once", u)
		}
		seen[u] = true
	}
	if t, ok := c.Flag("timeout"); ok {
		cfg.Timeout, _ = time.ParseDuration(t)
	}
	_, cfg.AllowPrivate = c.Flag("allow-private")
	var cals []btctime.Calendar
	if b := c.Env.Calendars; b != nil {
		for _, u := range urls {
			cal, err := b(u, cfg)
			if err != nil {
				return nil, nil, cfg, usage("calendar-refused", "a calendar URL cannot name a calendar",
					"refused before dialling ("+err.Error()+"); nothing was contacted or appended", scope, "name an https calendar URL with a host and no query", u)
			}
			cals = append(cals, cal)
		}
	}
	return urls, cals, cfg, nil
}

// recordingCalendar remembers each calendar's outcome for the output.
type recordingCalendar struct {
	btctime.Calendar
	err   error
	tried bool
}

func (r *recordingCalendar) Submit(d [32]byte) ([]byte, error) {
	r.tried = true
	b, err := r.Calendar.Submit(d)
	r.err = err
	return b, err
}

// heldTransport is the "transport" of the stamping flow: nothing leaves the machine here; it captures the unit the
// flow would send so the command commits it (storage note §3.2: the anchor is its own unit after its head).
type heldTransport struct {
	lines [][]byte
	blobs map[string][]byte
}

func (h *heldTransport) Send(lines [][]byte, blobs map[string][]byte) error {
	h.lines, h.blobs = lines, blobs
	return nil
}

// stampPlace places the anchors line and names the covered head: the line --prev names, the one tip, or (a named
// head on a forked log) the one tip whose history holds the head.
func (v *view) stampPlace(c *Ctx, signer string) (head, string, *wire.Statement, *Problem) {
	lv := v.logs.Log(signer).View()
	chained := map[string]*wire.Statement{}
	held := map[string]bool{}
	for _, l := range lv.Lines {
		held[l.St.ID] = true
		if l.State == keylog.Chained {
			chained[l.St.ID] = l.St
		}
	}
	covered, named := c.Args["statement-id"]
	if named && chained[covered] == nil {
		detail := "this store holds no statement with this id; an anchor stamps a line of your own log, which must be held to be in the anchor's prefix"
		switch p, ok := v.r.Statement(covered); {
		case ok && p.St.Signer != signer:
			detail = "it is a statement of another key (" + p.St.Signer + "); an anchor bounds only its signer's own log"
		case held[covered]:
			detail = "it is a line of your log that is not chained to its first line here (detached); an anchor's head must be in its own prefix"
		}
		return head{}, "", nil, usage("not-your-line", "the statement named is not a chained line of your log",
			detail+"; nothing was contacted or appended", "argument statement-id", "name a line your key signed (commons show <id>), or omit it to stamp your log's tip", covered)
	}
	if len(lv.Lines) == 0 && len(lv.Retained) == 0 {
		return head{}, "", nil, usage("empty-log", "your log has no line here", "there is nothing to anchor; nothing was contacted or appended",
			"this key's log", "publish first, then anchor stamp", "")
	}
	var h head
	_, hasPrev := c.Flag("prev")
	switch {
	case named && !hasPrev && len(lv.Tips) > 1:
		var holding []string
		for _, t := range lv.Tips {
			if t == covered || ancestors(t, chained)[covered] {
				holding = append(holding, t)
			}
		}
		if len(holding) != 1 {
			_, prob := v.placeLine(c, signer)
			return head{}, "", nil, prob
		}
		h = head{seq: chained[holding[0]].Seq + 1, prev: holding[0]}
	default:
		var prob *Problem
		if h, prob = v.placeLine(c, signer); prob != nil {
			return head{}, "", nil, prob
		}
	}
	if !named {
		covered = h.prev
	}
	if covered != h.prev && !ancestors(h.prev, chained)[covered] {
		return head{}, "", nil, usage("head-not-in-prefix", "the statement named is not in the history of the line the anchor extends",
			"an anchors statement must have its covered head in its own prefix (bitcoin-time note §1 rule 3); nothing was contacted or appended",
			"option --prev", "name with --prev a line whose history holds the head, or omit --prev", covered)
	}
	return h, covered, chained[covered], nil
}

func stampCmd(c *Ctx) (*Obj, int, error) {
	p := c.Prep.(*stampPrep)
	signer := p.key.Key.Signer()
	wl := lockFor(c, signer)
	defer wl.Unlock()
	v, err := loadView(c.Store, nil)
	if err != nil {
		return nil, 0, failed(err, "store", false, "run status, then fsck")
	}
	h, covered, headSt, prob := v.stampPlace(c, signer)
	if prob != nil {
		return nil, 0, prob
	}
	if prob := v.keyRetired(signer); prob != nil {
		return nil, 0, prob
	}
	def, why := btctime.DefaultFor(headSt)
	standing := newObj().set("if_every_calendar_fails", textV(string(def))).set("decided_by", textV(why))
	out := newObj().set("covered", refV(covered)).set("stamped_digest", refV(covered)).set("standing", standing)
	noteLock(out, wl)
	if _, dry := c.Flag("dry-run"); dry {
		l := listV{}
		for _, u := range p.urls {
			l = append(l, peerV(u))
		}
		return out.set("calendars", l).set("dry_run", boolV(true)).set("committed", boolV(false)).
			set("would", texts("submit the stamped digest to each calendar in turn", "with at least one pending proof: merge every answering calendar's proof into one, install it and append one anchors statement to "+signer+"'s log in one journal record")).
			set("note", textV("dry run: no calendar was contacted; nothing was written")), ExitOK, nil
	}
	if p.cals == nil {
		return nil, 0, &Problem{Slug: "not-available", Title: "calendars are not available in this build", Class: refusal.Operational, Scope: "invocation",
			Detail: "this build has no calendar client; nothing was contacted or appended", Next: "use a build with network access", Exit: ExitCouldNot}
	}
	rec := make([]*recordingCalendar, len(p.cals))
	cals := make([]btctime.Calendar, len(p.cals))
	for i, cal := range p.cals {
		rec[i] = &recordingCalendar{Calendar: cal}
		cals[i] = rec[i]
	}
	var sts []signed
	appender := func(body *canon.Object) ([]byte, string, error) {
		st, err := wire.Write(wire.Draft{Kind: "anchors", Seq: h.seq, Prev: h.prev, TS: p.ts, Body: body}, p.key.Key, Now())
		if err != nil {
			return nil, "", err
		}
		if st.Status != wire.Valid {
			return nil, "", &refusal.Refusal{Class: refusal.Intrinsic, Reason: "not valid", Detail: "the signed line reads back as " + string(st.Status)}
		}
		sts = append(sts, signed{st, st.Line()})
		return st.Line(), st.ID, nil
	}
	tr := &heldTransport{}
	// the policy is the default by standing, unchanged: it decides only what is printed; a stamp that got no proof
	// appends nothing whatever the standing
	res, perr := btctime.Publish(headSt, nil, nil, cals, btctime.PublishPolicy{}, appender, tr)
	cl := listV{}
	for _, r := range rec {
		row := rowObj().set("calendar", peerV(r.URI()))
		switch {
		case !r.tried:
			row.set("result", textV("not contacted"))
		case r.err != nil:
			row.set("result", textV("failed")).set("error", peerV(r.err.Error()))
		default:
			row.set("result", textV("pending proof returned"))
		}
		cl = append(cl, row)
	}
	out.set("calendars", cl)
	if res == nil || res.Anchor == "" {
		var rf *refusal.Refusal
		if perr != nil && !errors.As(perr, &rf) {
			return nil, 0, writeRefused(perr)
		}
		return out.set("committed", boolV(false)).
			set("note", textV("every calendar failed: no anchors statement was signed or appended; the head stays unanchored. Standing: "+string(def)+" ("+why+")")), ExitCouldNot, nil
	}
	if perr != nil {
		return nil, 0, writeRefused(perr)
	}
	proof := tr.blobs[res.ProofBlob]
	if proof == nil || len(sts) != 1 {
		return nil, 0, failed(errors.New("the stamping flow returned no proof blob"), "this stamp", false, "run the command again")
	}
	out.set("proof", refV(res.ProofBlob))
	if len(res.Warnings) > 0 {
		out.set("warnings", texts("a calendar failed beside one that answered; the anchors statement names only the calendars that answered (see calendars)"))
	}
	open := func(store.Digest) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(proof)), nil }
	return commitUnitFrom(c, out, "anchor", sts, []store.Digest{store.Digest(res.ProofBlob)}, open, "calendar response", h)
}
