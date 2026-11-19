package resolve

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/policy"
)

// An `observed` statement's single-party disclosures are signed (wire §5: "disclosures (on `authored`,
// `observed`)"), so a blob with no counted `authored` claim must show them: the default display comes from one
// key's `authored` or `observed` statement (claims §5.1). The rule is the one the input summary already applies to
// an observation input (inputValue): the value its counted observations agree on.

// noteObs signs a none-yet observation of x by signer n carrying kv (disclosures).
func noteObs(w *world, name, n, x string, kv ...any) string {
	return w.observed(name, n, x, "none-yet", obj(), kv...)
}

// TestObservedDisclosuresShown: the four states of a single-party field on an observation-only blob.
func TestObservedDisclosuresShown(t *testing.T) {
	w := newWorld(t)
	o1 := noteObs(w, "O1", "O", "OBS", "licence", "CC0-1.0", "replication", "bytes", "shelf_life_days", 30,
		"availability", obj("redistribution", "permitted", "obtainable", true), "attribution", "A. Observer")
	a := w.store(nil).Artifact(dig("OBS"))
	if a.State != NoClaim {
		t.Fatalf("state %s, want no authorship claim", a.State)
	}
	// agreed: one observation carries every value → default, From = that statement
	f := a.Field("licence")
	if v, ok := f.Default(); !ok || v != `"CC0-1.0"` {
		t.Fatalf("licence = %v %v (state %s), want default \"CC0-1.0\"", v, ok, f.State)
	}
	if len(f.From) != 1 || f.From[0].Statement != o1 || f.From[0].Signer != w.signer("O") {
		t.Fatalf("licence From = %+v, want the observation %s by its signer", f.From, o1)
	}
	out := a.Render()
	has(t, out, "licence: CC0-1.0")
	has(t, out, "replication: \"bytes\" ("+shortKey(w.signer("O"))+" in "+keylog.Short(o1)+")")
	has(t, out, "shelf_life_days:")
	has(t, out, "availability: redistribution permitted")
	has(t, out, "attribution:")
	hasNot(t, out, "licence: unknown")
	hasNot(t, out, "replication: undeclared")
	// none sets it → absent: sampling is not declared; the licence token stays `unknown` for a missing licence
	if s := a.Field("sampling"); s.State != FieldAbsent {
		t.Fatalf("sampling state %s, want undeclared", s.State)
	}
	has(t, out, "sampling: undeclared")
	// a second observer that says nothing about the licence does not change the agreed value, and a second that
	// repeats it adds its statement to From
	noteObs(w, "O2", "P", "OBS", "licence", "CC0-1.0")
	noteObs(w, "O3", "Q", "OBS", "replication", "bytes")
	b := w.store(nil).Artifact(dig("OBS"))
	if f := b.Field("licence"); f.State != FieldDefault || len(f.From) != 2 {
		t.Fatalf("licence after agreeing observer: state %s From %+v, want default from 2 statements", f.State, f.From)
	}
	if f := b.Field("replication"); f.State != FieldDefault || len(f.From) != 2 {
		t.Fatalf("replication after a silent+agreeing observer: state %s From %+v", f.State, f.From)
	}
}

// TestObservedDisclosuresContestedMutation: mutation check. The same world with one observation's licence flipped
// goes from default to contested, every value listed with its signer, and nothing moves the exit (I6).
func TestObservedDisclosuresContestedMutation(t *testing.T) {
	build := func(second string) *Artifact {
		w := newWorld(t)
		noteObs(w, "O1", "O", "OBS", "licence", "CC0-1.0")
		noteObs(w, "O2", "P", "OBS", "licence", second)
		return w.store(nil).Artifact(dig("OBS"))
	}
	agree := build("CC0-1.0")
	if f := agree.Field("licence"); f.State != FieldDefault {
		t.Fatalf("agreeing observers: licence %s, want default", f.State)
	}
	flip := build("MIT")
	f := flip.Field("licence")
	if f.State != FieldContested || len(f.From) != 2 || distinctValues(f.From) != 2 {
		t.Fatalf("disagreeing observers: licence %s From %+v, want contested with both values", f.State, f.From)
	}
	out := flip.Render()
	has(t, out, "licence: contested")
	has(t, out, `"CC0-1.0" by `)
	has(t, out, `"MIT" by `)
	// the mutation reached the field, but the exit is the one an observation has with agreeing disclosures
	ac, awhy := agree.VerifyExit()
	fc, why := flip.VerifyExit()
	if ac != fc || strings.Join(why, ";") != strings.Join(awhy, ";") {
		t.Fatalf("a disagreeing disclosure moved the exit or its causes: %d %v vs %d %v", fc, why, ac, awhy)
	}
	// the disclosures are signed beside the claim, not part of it: Verify (the exit-only path) agrees
	w := newWorld(t)
	noteObs(w, "O1", "O", "OBS", "licence", "CC0-1.0")
	noteObs(w, "O2", "P", "OBS", "licence", "MIT")
	if vc, _ := w.store(nil).Verify(dig("OBS")); vc != ac {
		t.Fatalf("Verify exit %d, want %d", vc, ac)
	}
}

// TestObservedDisclosuresSelectionUnmet: with the reader's observation selection unmet the field is unknown and
// says why, in the words the input summary uses; a met selection reads only the selected statement.
func TestObservedDisclosuresSelectionUnmet(t *testing.T) {
	w := newWorld(t)
	o1 := noteObs(w, "O1", "O", "OBS", "licence", "CC0-1.0")
	o2 := noteObs(w, "O2", "P", "OBS", "licence", "MIT")
	w.authored("A1", "A", "Z") // an authored statement, not an observation: an ineligible selection target
	unmet := w.store(nil, WithPolicy(pol(t, []*canon.Object{pinSel(dig("OBS"), policy.RoleObservation, w.ids["A1"])}, nil))).Artifact(dig("OBS"))
	f := unmet.Field("licence")
	want := "reader's observation selection " + SelIneligible
	if f.State != FieldUnknown || f.Why != want {
		t.Fatalf("unmet selection: licence %s why %q, want unknown / %q", f.State, f.Why, want)
	}
	has(t, unmet.Render(), "licence: unknown")
	met := w.store(nil, WithPolicy(pol(t, []*canon.Object{pinSel(dig("OBS"), policy.RoleObservation, o2)}, nil))).Artifact(dig("OBS"))
	if v, ok := met.Field("licence").Default(); !ok || v != `"MIT"` {
		t.Fatalf("met selection: licence %v %v, want the selected statement's MIT", v, ok)
	}
	if f := met.Field("licence"); len(f.From) != 1 || f.From[0].Statement != o2 {
		t.Fatalf("met selection From %+v, want only %s (not %s)", f.From, o2, o1)
	}
}

// TestObservedDisclosuresAuthoredWins: when the blob also has a counted authored claim the authored rules are
// unchanged: its licence is the default, and a disagreeing observation's licence is not read into the field.
func TestObservedDisclosuresAuthoredWins(t *testing.T) {
	w := newWorld(t)
	noteObs(w, "O1", "O", "OBS", "licence", "MIT", "replication", "none")
	w.authored("A1", "A", "OBS", "licence", "CC0-1.0")
	a := w.store(nil).Artifact(dig("OBS"))
	if a.State == NoClaim {
		t.Fatal("expected an authorship claim")
	}
	f := a.Field("licence")
	if v, ok := f.Default(); !ok || v != `"CC0-1.0"` || len(f.From) != 1 || f.From[0].Signer != w.signer("A") || f.Observed {
		t.Fatalf("licence %s %+v, want the authored CC0-1.0 alone", f.State, f.From)
	}
	if r := a.Field("replication"); r.State != FieldAbsent {
		t.Fatalf("replication %s: an observation's value must not fill an authored blob's undeclared field", r.State)
	}
	hasNot(t, a.Render(), "MIT")
}

// TestObservedDisclosuresOneRule: the input summary and the blob display share one helper, so for every
// disclosure they cannot disagree (a contested field is "its observations disagree" in the summary).
func TestObservedDisclosuresOneRule(t *testing.T) {
	w := newWorld(t)
	noteObs(w, "O1", "O", "OBS", "replication", "bytes", "shelf_life_days", 30)
	noteObs(w, "O2", "P", "OBS", "replication", "none", "shelf_life_days", 30)
	r := w.store(nil)
	a := r.Artifact(dig("OBS"))
	for _, name := range []string{"replication", "shelf_life_days", "licence"} {
		v, ok, why := r.inputValue(dig("OBS"), name)
		f := a.Field(name)
		switch f.State {
		case FieldDefault:
			if !ok || string(canon.Encode(v)) != f.From[0].Value {
				t.Fatalf("%s: display default %s but input value %v %v", name, f.From[0].Value, v, ok)
			}
		case FieldContested:
			if ok || !strings.Contains(why, "disagree") {
				t.Fatalf("%s: display contested but input value ok=%v why=%q", name, ok, why)
			}
		default:
			if ok {
				t.Fatalf("%s: display %s but input value ok", name, f.State)
			}
		}
	}
	if f := a.Field("replication"); f.State != FieldContested {
		t.Fatalf("replication %s, want contested", f.State)
	}
	if f := a.Field("shelf_life_days"); f.State != FieldDefault {
		t.Fatalf("shelf_life_days %s, want default", f.State)
	}
}

// TestObservedPreRegistration: the pre-registration display reads the observation's own declaration.
func TestObservedPreRegistration(t *testing.T) {
	w := newWorld(t)
	noteObs(w, "O1", "O", "OBS", "pre_registration", "exploratory")
	a := w.store(nil).Artifact(dig("OBS"))
	if a.PreReg == nil || a.PreReg.Display != "exploratory" {
		t.Fatalf("pre-registration = %+v, want exploratory", a.PreReg)
	}
	has(t, a.Render(), "pre_registration: exploratory")
}
