package btctime

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// events records the order of everything publish does, so the order is observable (§2).
type events struct{ log []string }

type mockCalendar struct {
	uri    string
	fail   bool
	ev     *events
	height int64 // > 0: answer with a proof already attested at this height (an upgraded proof); else pending
	w      *world
	name   string
	got    [32]byte
}

func (c *mockCalendar) URI() string { return c.uri }

func (c *mockCalendar) Submit(d [32]byte) ([]byte, error) {
	c.ev.log = append(c.ev.log, "submit "+c.uri)
	c.got = d
	if c.fail {
		return nil, errors.New("timeout")
	}
	if c.height > 0 {
		c.w.roots[c.height] = sha(d[:], nonce(c.name))
		return otsFile(d[:], opAppendB(nonce(c.name)), opSHA256B(), attBitcoin(uint64(c.height))), nil
	}
	return otsFile(d[:], attPending(c.uri)), nil
}

type mockTransport struct {
	ev    *events
	lines [][]byte
	blobs map[string][]byte
}

func (m *mockTransport) Send(lines [][]byte, blobs map[string][]byte) error {
	m.ev.log = append(m.ev.log, fmt.Sprintf("transport %d lines", len(lines)))
	m.lines, m.blobs = lines, blobs
	return nil
}

// appender signs the anchors statement as key n's next line in w.
func (w *world) appender(n, name string, ev *events) Appender {
	return func(body *canon.Object) ([]byte, string, error) {
		id := w.sign(name, n, "anchors", body)
		ev.log = append(ev.log, "append anchors")
		return w.lines[len(w.lines)-1], id, nil
	}
}

// TestStampBeforeTransport: C-btc-03. publish against a mock transport: the stamped digest is the raw bytes of the
// head, the anchors statement is appended before the first byte out, and it travels with the statements. A copier
// C who sees the push publishes its own authored and anchor; its verified bound is later; the original is default
// author and C a later claimant.
func TestStampBeforeTransport(t *testing.T) {
	conformance.Covers(t, "C-btc-03")
	w := newWorld(t)
	ev := &events{}
	head := w.authored("A1", "A", "X", "licence", "CC0-1.0")
	cal := &mockCalendar{uri: "https://a.calendar.test", ev: ev, w: w, name: "AA", height: 10}
	tr := &mockTransport{ev: ev}
	res, err := Publish(w.sts["A1"], [][]byte{w.lines[0]}, nil, []Calendar{cal}, PublishPolicy{}, w.appender("A", "AA", ev), tr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ev.log, "; ") != "submit https://a.calendar.test; append anchors; transport 2 lines" {
		t.Fatalf("order: %v", ev.log)
	}
	if fmt.Sprintf("%x", cal.got) != head {
		t.Fatalf("stamped %x, head %s (no hex, no newline: the raw 32 bytes)", cal.got, head)
	}
	if string(tr.lines[1]) != string(w.lines[1]) || tr.blobs[res.ProofBlob] == nil {
		t.Fatal("the anchors statement or its proof blob did not travel")
	}
	an, _ := wire.Read(tr.lines[1])
	if str(an.Body, "covered") != head || str(an.Body, "proof_format") != ProofFormat || str(an.Body, "proof") != res.ProofBlob {
		t.Fatalf("anchors body %s", canon.Encode(an.Body))
	}
	for k, v := range tr.blobs {
		w.blobs[k] = v
	}
	// the copier sees the push, then publishes and stamps; the calendar's next block is later
	w.authored("C1", "CC", "X", "licence", "MIT")
	cev := &events{}
	ccal := &mockCalendar{uri: "https://a.calendar.test", ev: cev, w: w, name: "CA", height: 11}
	cres, err := Publish(w.sts["C1"], [][]byte{w.lines[2]}, nil, []Calendar{ccal}, PublishPolicy{}, w.appender("CC", "CA", cev), &mockTransport{ev: cev})
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range cres.Blobs {
		w.blobs[k] = v
	}
	v := w.chain(30).fresh(w.blobs)
	everyOrder(t, w, "X", v, func(a *resolveArtifact) {
		if a.Default == nil || a.Default.Claims[0].Signer != w.signer("A") {
			t.Fatalf("%s", a.Render())
		}
		has(t, a.Render(), "later claimant "+shortKey(w.signer("CC")))
	})
	// a pending proof travels too and is shown pending
	w2 := newWorld(t)
	ev2 := &events{}
	w2.authored("A1", "A", "X")
	r2, err := Publish(w2.sts["A1"], [][]byte{w2.lines[0]}, nil, []Calendar{&mockCalendar{uri: "https://b.calendar.test", ev: ev2}}, PublishPolicy{}, w2.appender("A", "AA", ev2), &mockTransport{ev: ev2})
	if err != nil || ev2.log[1] != "append anchors" {
		t.Fatalf("pending: %v %v", err, ev2.log)
	}
	for k, b := range r2.Blobs {
		w2.blobs[k] = b
	}
	if e := w2.chain(10).fresh(w2.blobs).Evaluate(w2.sts["AA"]); e.State != StatePending {
		t.Fatalf("pending proof: %s", e)
	}
}

// TestCalendarFailureDefaults: C-btc-03a. Every calendar fails, default policy: (a)–(d) refused, nothing
// transported, the refusal names the calendars tried and the override; (e), (f) published with anchor: none and a
// warning. Then (a) and (f) under overrides: the outcomes swap. Every outcome names the policy that decided it.
func TestCalendarFailureDefaults(t *testing.T) {
	conformance.Covers(t, "C-btc-03a")
	capture := func(evidence string) *canon.Object {
		return obj("content", canon.Value(obj("digest", dig("OBS"), "size", 3)), "class", "none-yet", "referent", obj(),
			"capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", evidence)))
	}
	edRef := obj("resource", strings.Repeat("ab", 32), "edition", strings.Repeat("cd", 32))
	for _, c := range []struct {
		name     string
		build    func(w *world) string
		override AnchorDefault
		refused  bool
		rule     string
	}{
		{"(a) authored without provenance", func(w *world) string { return w.authored("S", "A", "X") }, "", true, "authored without provenance"},
		{"(b) carries fulfills", func(w *world) string {
			return w.authored("S", "A", "X", "prov", []string{"W", "I"}, "fulfills", canon.Value(edRef))
		}, "", true, "fulfills"},
		{"(c) withheld", func(w *world) string {
			return w.authored("S", "A", "X", "prov", []string{"W", "I"}, "availability", canon.Value(obj("redistribution", "withheld", "obtainable", false)))
		}, "", true, "withheld"},
		{"(d) anchored-at-capture", func(w *world) string { return w.sign("S", "A", "observed", capture("anchored-at-capture")) }, "", true, "anchored-at-capture"},
		{"(e) authored with provenance", func(w *world) string { return w.authored("S", "A", "X", "prov", []string{"W", "I"}) }, "", false, "authored with provenance"},
		{"(f) self-asserted capture", func(w *world) string { return w.sign("S", "A", "observed", capture("self-asserted")) }, "", false, "observed capture without anchored-at-capture"},
		{"(a) under override anchor: none", func(w *world) string { return w.authored("S", "A", "X") }, AnchorNone, false, "local policy override"},
		{"(f) under override anchor required", func(w *world) string { return w.sign("S", "A", "observed", capture("self-asserted")) }, AnchorRequired, true, "local policy override"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			c.build(w)
			ev := &events{}
			cals := []Calendar{&mockCalendar{uri: "https://a.calendar.test", fail: true, ev: ev}, &mockCalendar{uri: "https://b.calendar.test", fail: true, ev: ev}}
			tr := &mockTransport{ev: ev}
			res, err := Publish(w.sts["S"], w.lines, nil, cals, PublishPolicy{Override: c.override}, w.appender("A", "AA", ev), tr)
			if !strings.Contains(res.DecidedBy, c.rule) {
				t.Fatalf("decided by %q, want %q", res.DecidedBy, c.rule)
			}
			if c.refused {
				var r *refusal.Refusal
				if !errors.As(err, &r) || r.Reason != string(AnchorRequired) || tr.lines != nil {
					t.Fatalf("not refused: %v, transported %d", err, len(tr.lines))
				}
				for _, s := range []string{"https://a.calendar.test", "https://b.calendar.test", "override", "nothing transported", c.rule} {
					has(t, r.Detail, s)
				}
				return
			}
			if err != nil || len(tr.lines) != len(w.lines) || res.Anchor != "" || len(res.Warnings) != 1 {
				t.Fatalf("not published with anchor: none: %v %+v", err, res)
			}
			has(t, res.Warnings[0], "anchor: none")
			has(t, res.Warnings[0], c.rule)
			if strings.Contains(strings.Join(ev.log, ";"), "append anchors") {
				t.Fatal("an anchors statement was appended with no proof")
			}
		})
	}
	// the defaults by standing, directly
	w := newWorld(t)
	w.sign("G", "A", "genesis", obj("type", "collection", "name", "n", "controllers", []string{w.signer("A")}, "rule", canon.Value(obj("any_one", true))))
	if d, _ := DefaultFor(w.sts["G"]); d != AnchorNone {
		t.Fatalf("genesis: %s", d)
	}
}

// TestBoundsInDisplay: C-btc-27 and C-btc-28 (bound half). The same evidence record serves capture evidence and
// pre-registration (I12): local evidence displays as (local, self-declared), verified evidence as a time labelled
// miner-reported with its height. The resolver views that print these lines are not built.
func TestBoundsInDisplay(t *testing.T) {
	conformance.Partial(t, "C-btc-27", "the evidence record renders local vs verified (time, miner-reported, height); the observation view's 'anchored at capture' line is not built")
	conformance.Partial(t, "C-btc-28", "the evidence record renders local vs verified; the exchange view's 'pre-registered <edition>' line is not built")
	w := newWorld(t)
	w.sign("O1", "A", "observed", obj("content", canon.Value(obj("digest", dig("OBS"), "size", 3)), "class", "none-yet", "referent", obj(),
		"capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "anchored-at-capture"))))
	w.anchorAt("AA", "A", 10)
	s := w.chain(30)
	v := s.fresh(w.blobs)
	e := v.Evaluate(w.sts["AA"])
	b := BoundOf(e, 0)
	if b.Quality != resolve.Bitcoin || !strings.Contains(e.String(), "(miner-reported)") || !strings.Contains(e.String(), "height 10") {
		t.Fatalf("verified: %s / %s", e, b)
	}
	none := (&Verifier{Policy: DefaultPolicy(), Blobs: w.blobs}).Evaluate(w.sts["AA"])
	if lb := BoundOf(none, 0); lb.Quality != resolve.Local || !strings.Contains(lb.String(), "(local, self-declared)") {
		t.Fatalf("local: %s", lb)
	}
}
