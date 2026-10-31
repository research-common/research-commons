package resolve

import (
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// timedBitcoin is fakeBitcoin with a block header time: proofs named "btc:<height>" verify at that height, and
// the bound carries the header time the test gives for it.
type timedBitcoin struct {
	fakeBitcoin
	at map[int64]time.Time
}

func (f timedBitcoin) Verify(a *wire.Statement) Bound {
	b := f.fakeBitcoin.Verify(a)
	if b.verified() {
		b.Time = f.at[b.Height].Unix()
	}
	return b
}

func line(t *testing.T, out, prefix string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	t.Fatalf("no line %q in\n%s", prefix, out)
	return ""
}

// TestAvailabilitySeparate: C-core-68. Redistribution permitted with bytes not obtainable, and redistribution
// restricted with bytes obtainable: the display carries both values, each in its own words, and swapping one
// never changes the other's words. The structured reading keeps them as two members.
func TestAvailabilitySeparate(t *testing.T) {
	conformance.Covers(t, "C-core-68")
	cases := []struct {
		red        string
		obtainable bool
		want, not  []string
	}{
		{"permitted", false, []string{"redistribution permitted", "bytes not obtainable (declared)"}, []string{"restricted", "bytes obtainable (declared)"}},
		{"restricted", true, []string{"redistribution restricted", "bytes obtainable (declared)"}, []string{"permitted", "not obtainable"}},
		// control: the remaining two combinations, so each value is shown independently of the other
		{"permitted", true, []string{"redistribution permitted", "bytes obtainable (declared)"}, []string{"not obtainable"}},
		{"restricted", false, []string{"redistribution restricted", "bytes not obtainable (declared)"}, []string{"permitted"}},
	}
	for _, c := range cases {
		w := newWorld(t)
		w.authored("A1", "A", "X", "availability", obj("redistribution", c.red, "obtainable", c.obtainable))
		w.sign("H", "A", "holds", obj("content", contentOf("X")))
		a := w.store(nil).Artifact(dig("X"))
		if a.Availability == nil || a.Availability.Redistribution != c.red || a.Availability.Obtainable != c.obtainable {
			t.Fatalf("%s/%v: structured reading %+v", c.red, c.obtainable, a.Availability)
		}
		l := line(t, a.Render(), "  availability:")
		for _, s := range c.want {
			has(t, l, s)
		}
		for _, s := range c.not {
			hasNot(t, l, s)
		}
		// I6: neither value moves the grade or the exit
		if code, _ := a.VerifyExit(); code != 0 || a.Grade.Why != NoDerivation {
			t.Fatalf("availability moved the grade/exit: %s %d", a.Grade, code)
		}
	}
}

// TestShelfLifeAge: C-core-74. Declared validity 30 days; the reader reads 45 days after the verified anchor's
// block time: `45 days … past declared validity`, grade and exit unchanged against the same artifact without a
// shelf life. Controls: 29 days reads within; a local (unverified) anchor gives age unknown even with a read
// time, so a self-declared time is never turned into an age; no read time gives no age; the signer-declared ts
// never moves the age (two statements with different ts, same anchor time, same age).
func TestShelfLifeAge(t *testing.T) {
	conformance.Covers(t, "C-core-74")
	anchorAt := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	tv := WithTimeVerifier(timedBitcoin{newFakeBitcoin(800000), map[int64]time.Time{800000: anchorAt}})
	build := func(shelf bool, proof string) *world {
		w := newWorld(t)
		w.workflow("WA", "W", "bytes", "")
		kv := []any{"prov", []string{"W", "I"}}
		if shelf {
			kv = append(kv, "shelf_life_days", 30)
		}
		w.authored("A1", "A", "X", kv...)
		w.authored("B1", "BB", "X", "prov", []string{"W", "I"})
		w.anchor("AN", "A", proof)
		return w
	}
	read := func(w *world, opts ...Option) *Artifact {
		return w.store(nil, opts...).Artifact(dig("X"))
	}
	at45 := WithReadTime(anchorAt.Add(45*24*time.Hour + time.Hour))
	at29 := WithReadTime(anchorAt.Add(29 * 24 * time.Hour))

	past := read(build(true, "btc:800000"), tv, at45)
	l := line(t, past.Render(), "  shelf_life_days:")
	has(t, l, "30 days declared")
	has(t, l, "age 45 days")
	has(t, l, "past declared validity")
	has(t, l, "bitcoin height 800000")
	if past.ShelfLife == nil || !past.ShelfLife.Aged || past.ShelfLife.Age != 45 || !past.ShelfLife.UsedReadTime {
		t.Fatalf("structured: %+v", past.ShelfLife)
	}
	// grade and exit unchanged: the same world without the shelf life
	base := read(build(false, "btc:800000"), tv, at45)
	pc, _ := past.VerifyExit()
	bc, _ := base.VerifyExit()
	if past.Grade != base.Grade || pc != bc || past.Grade.Tier != "T0" {
		t.Fatalf("shelf life moved the grade/exit: %s %d vs %s %d", past.Grade, pc, base.Grade, bc)
	}

	within := read(build(true, "btc:800000"), tv, at29)
	l = line(t, within.Render(), "  shelf_life_days:")
	has(t, l, "age 29 days")
	hasNot(t, l, "past declared validity")

	// a local anchor: the time is self-declared, so no age, whatever the read time
	local := read(build(true, "not-a-verified-proof"), tv, at45)
	l = line(t, local.Render(), "  shelf_life_days:")
	has(t, l, "age unknown (no verified time")
	has(t, l, "(local, self-declared)")
	hasNot(t, l, "past declared validity")
	if local.ShelfLife.Aged || local.ShelfLife.UsedReadTime {
		t.Fatalf("a self-declared time became an age: %+v", local.ShelfLife)
	}

	// no read time given: no age computed (the resolver reads no clock of its own)
	none := read(build(true, "btc:800000"), tv)
	has(t, line(t, none.Render(), "  shelf_life_days:"), "age not computed (no read time given)")

	// the answer is a function of the held set and the read time: every delivery order, one rendering
	sampledOrderArtifact(t, build(true, "btc:800000"), "X", func(a *Artifact) {
		if a.ShelfLife == nil || a.ShelfLife.Age != 45 {
			t.Fatalf("%+v", a.ShelfLife)
		}
	}, tv, at45)
}

// TestWithheldRevealResolver: C-core-75 and C-core-76, the resolver half. An `authored` with
// `availability: withheld until <edition>` and no holds: withheld, not revealed, and the statement verifies
// (exit 0, sole author). A later holds by the author with the bytes held here (verified by full hash): revealed.
// A holds whose bytes are not held here (a fetch refused them on hash mismatch, so nothing was installed): the
// holder's word, not revealed, and the declared value still reads withheld.
func TestWithheldRevealResolver(t *testing.T) {
	conformance.Partial(t, "C-core-75", "resolver: before the reveal withheld until <condition>, not revealed, statement verifies (exit 0); after a holds with the bytes held and verified, revealed; the fetch by full hash is internal/cli.TestWithheldReveal and internal/store; the anchored-at-publish half rests on the anchor of the publish path, which no command writes yet")
	conformance.Partial(t, "C-core-76", "resolver: a holds whose bytes were not installed is the holder's word and the statement stays withheld; the intrinsic hash-mismatch refusal scoped to the fetch is internal/cli.TestWithheldReveal and internal/store; no `fetch` command prints it yet")
	av := obj("redistribution", "withheld", "obtainable", false, "withheld_until", "task edition T2")

	w := newWorld(t)
	w.authored("A1", "A", "X", "availability", av)
	before := w.store(nil, WithBlobIndex(blobSet{dig("X"): true})).Artifact(dig("X")) // the author's own copy
	l := line(t, before.Render(), "  availability:")
	has(t, l, `redistribution withheld until "task edition T2"`)
	has(t, l, "bytes not obtainable (declared)")
	has(t, l, "no holds published (not revealed)")
	hasNot(t, l, "revealed:")
	wantExit(t, before, 0, "")
	if before.Availability.Revealed || len(before.Holders) != 0 {
		t.Fatal("a withheld artifact without holds read as revealed")
	}
	reader := w.store(nil).Artifact(dig("X")) // another reader: no bytes, no holds
	has(t, line(t, reader.Render(), "  availability:"), "not revealed (no holds held)")

	w.sign("H", "A", "holds", obj("content", contentOf("X")))
	// the holds exists and the bytes are held and re-hashed: revealed
	after := w.store(nil, WithBlobIndex(blobSet{dig("X"): true})).Artifact(dig("X"))
	has(t, line(t, after.Render(), "  availability:"), "revealed: holds by "+shortKey(w.signer("A"))+", bytes held here and verified by full hash")
	if !after.Availability.Revealed {
		t.Fatal("not revealed")
	}
	wantExit(t, after, 0, "")
	// the holds exists but the bytes were refused (not installed): the holder's word, still withheld
	refused := w.store(nil).Artifact(dig("X"))
	l = line(t, refused.Render(), "  availability:")
	has(t, l, "redistribution withheld")
	has(t, l, "holder's word; the reveal is not verified until the bytes are")
	hasNot(t, l, "revealed:")
	if refused.Availability.Revealed {
		t.Fatal("a holds whose bytes were not installed revealed the artifact")
	}
}

// TestRetractionIsDisplay: C-core-139, the resolver half. The author retracts X; a second key holds X. The
// retraction is listed beside X, the second key stays a holder (retraction stops nobody serving), and the
// retraction moves no field, grade or exit.
func TestRetractionIsDisplay(t *testing.T) {
	conformance.Partial(t, "C-core-139", "resolver: the author's retracts is listed beside X with `(retracted)`, a mirror's holds keeps it a holder, and nothing else moves; the CLI label on every surface and the fetch from the mirror are internal/cli.TestRetractionEverywhere; a mirror on another hub needs pull between two stores (internal/cli covers one store holding both)")
	w := newWorld(t)
	a1 := w.authored("A1", "A", "X", "licence", "CC0-1.0")
	w.sign("H", "A", "holds", obj("content", contentOf("X")))
	w.sign("M", "M", "holds", obj("content", contentOf("X"), "locations", []string{"https://mirror.example/x"}))
	pre := w.store(nil).Artifact(dig("X"))
	w.sign("R", "A", "retracts", obj("of", a1, "reason", "superseded"))
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		has(t, a.Render(), "held retracts "+keylog.Short(w.ids["R"])+" by "+shortKey(w.signer("A"))+" (retracted) of "+keylog.Short(a1))
		if len(a.Holders) != 2 {
			t.Fatalf("holders %v", a.Holders)
		}
		if a.Outcome() != pre.Outcome() || a.Grade != pre.Grade {
			t.Fatalf("retraction moved the answer: %s vs %s", a.Outcome(), pre.Outcome())
		}
		wantExit(t, a, 0, "")
	})
}
