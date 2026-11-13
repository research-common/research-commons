package resolve

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
)

// methodRef is a method-class referent under edition id ed pinning the given system object.
func methodRef(ed string, system *canon.Object) *canon.Object {
	return obj("method_edition", ed, "environment", obj("image_digest", dig("img"), "platform", "linux/amd64", "harness_commit", strings.Repeat("c", 40)),
		"system", system, "inputs", []string{dig("seeds")}, "window", obj("from", "2026-10-01T00:00:00Z", "to", "2026-10-02T00:00:00Z"))
}

// subset delivers only the lines at the given indexes, in each of k seeded orders as well as as given, and
// requires one observation view across them (I14).
func subsetView(t *testing.T, w *world, lines []int, id string) *Observation {
	t.Helper()
	var first string
	var out *Observation
	for i, perm := range append([][]int{nil}, sampleOrders(len(lines), uint64(len(lines))*17+uint64(len(w.lines)), 8)...) {
		order := slices.Clone(lines)
		if perm != nil {
			for j, p := range perm {
				order[j] = lines[p]
			}
		}
		o, ok := w.store(order).Observation(id)
		if !ok {
			t.Fatalf("observation %s not held", keylog.Short(id))
		}
		if i == 0 {
			first, out = o.Render(), o
		} else if r := o.Render(); r != first {
			t.Fatalf("order %v changed the view:\n%s\nvs\n%s", order, r, first)
		}
	}
	return out
}

// upTo is the indexes of the first n lines.
func upTo(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

// TestMethodSystemKeysMissing: C-core-32b. M1 (authorized) declares model, provider, routing_era. O1 lacks
// routing_era: admitted, unpinned naming system.routing_era, no agreement model (a corroboration of it is not
// applied), verify exit 3. O2 and O3 pin all three; O3 also pins an undeclared region, which is shown and does
// not make them incomparable, so a corroboration of O2 on O3 counts.
func TestMethodSystemKeysMissing(t *testing.T) {
	conformance.Covers(t, "C-core-32b")
	w := newWorld(t)
	g := w.genesis("G", "MC", 0, "MC")
	m1 := w.ed(w.editionWith("M1", "MC", g, []string{g}, "system_keys", []string{"model", "provider", "routing_era"}))
	o1 := w.observed("O1", "P1", "B1", "method", methodRef(m1, obj("model", "m", "provider", "p")))
	o2 := w.observed("O2", "P2", "B2", "method", methodRef(m1, obj("model", "m", "provider", "p", "routing_era", "q3")))
	o3 := w.observed("O3", "P3", "B3", "method", methodRef(m1, obj("model", "m", "provider", "p", "region", "eu", "routing_era", "q3")))
	w.workflow("WA", "W", "bytes", "")
	r1 := w.result("R1", "C", "cmp1", "W", "B1", "B2")
	r2 := w.result("R2", "C", "cmp2", "W", "B2", "B3")
	w.corroborates("C1", "C", o1, r1, "supports")
	w.corroborates("C2", "C", o2, r2, "supports")

	v1 := obsView(t, w, o1)
	wantRef(t, v1, RefUnpinned)
	if !slices.Equal(v1.Unpinned, []string{"referent.system.routing_era"}) {
		t.Fatalf("unpinned %v", v1.Unpinned)
	}
	has(t, v1.Render(), "system.routing_era")
	has(t, v1.Render(), "method edition "+keylog.Short(m1)+" (authorized) declares system_keys model, provider, routing_era")
	wantStatus(t, v1, "unchecked within statements you hold")
	has(t, v1.Render(), "not applied: referent unpinned")
	if code, why := v1.VerifyExit(); code != 3 || !strings.Contains(strings.Join(why, ";"), "referent.system.routing_era") {
		t.Fatalf("verify %d %v", code, why)
	}
	// the statement's own unpinned slice (schema level) is untouched: the declaration is the reader's
	if p, _ := w.store(nil).Statement(o1); len(p.St.Unpinned) != 0 {
		t.Fatalf("statement mutated: %v", p.St.Unpinned)
	}

	v2 := obsView(t, w, o2)
	wantRef(t, v2, RefPinned)
	if code, _ := v2.VerifyExit(); code != 0 {
		t.Fatalf("O2 verify %d", code)
	}
	var vs3 *Comparability
	for i, c := range v2.Comparability {
		if c.With == o3 {
			vs3 = &v2.Comparability[i]
		}
		// O1 lacks the declared routing_era: named once, as unpinned, not again as a key O1 does not pin
		if c.With == o1 && (c.Comparable || !slices.Equal(c.Unpinned, []string{"referent.system.routing_era"}) || len(c.MissingThere)+len(c.MissingHere) != 0) {
			t.Fatalf("O2 vs O1: %+v", c)
		}
	}
	if vs3 == nil || !vs3.Comparable || !slices.Equal(vs3.MissingHere, []string{"system.region"}) {
		t.Fatalf("O2 vs O3: %+v", v2.Comparability)
	}
	has(t, v2.Render(), "every declared system key pinned on both")
	has(t, v2.Render(), "this observation does not pin system.region")
	wantStatus(t, v2, "corroborated 1 within statements you hold")

	v3 := obsView(t, w, o3)
	has(t, v3.Render(), `referent.system: {"model":"m","provider":"p","region":"eu","routing_era":"q3"}`)
	wantRef(t, v3, RefPinned)
}

// TestMethodSystemKeysPinnedEdition: C-core-32c. M1 declares model; O1 under M1 pins model only. A later
// authorized edition M2 declares model and routing_era; O2 under M2 pins model only. O1 is judged by M1 in every
// delivery order, with M2 delivered before and after O1, and explain cites M1; O2 is unpinned naming
// system.routing_era.
func TestMethodSystemKeysPinnedEdition(t *testing.T) {
	conformance.Covers(t, "C-core-32c")
	w := newWorld(t)
	g := w.genesis("G", "MC", 0, "MC")               // line 0
	m1s := w.editionWith("M1", "MC", g, []string{g}, // line 1
		"system_keys", []string{"model"})
	m1 := w.ed(m1s)
	o1 := w.observed("O1", "P1", "B1", "method", methodRef(m1, obj("model", "m"))) // line 2
	m2 := w.ed(w.editionWith("M2", "MC", g, []string{m1s},                         // line 3
		"system_keys", []string{"model", "routing_era"}))
	o2 := w.observed("O2", "P2", "B2", "method", methodRef(m2, obj("model", "m"))) // line 4

	r := w.store(nil)
	res, _ := r.Resource(g)
	if res.Current != m2 {
		t.Fatalf("M2 is not the current edition: %s", res.Render())
	}
	// every order of the five lines: M2 before and after O1 are both among them
	var first string
	before, after := 0, 0
	for _, order := range permutations(5) {
		if slices.Index(order, 3) < slices.Index(order, 2) {
			before++
		} else {
			after++
		}
		v, _ := w.store(order).Observation(o1)
		if v.ReferentStatus != RefPinned || len(v.Unpinned) != 0 {
			t.Fatalf("order %v: O1 %s %v\n%s", order, v.ReferentStatus, v.Unpinned, v.Render())
		}
		if first == "" {
			first = v.Render()
		} else if v.Render() != first {
			t.Fatalf("order %v changed O1:\n%s\nvs\n%s", order, v.Render(), first)
		}
	}
	if before == 0 || after == 0 {
		t.Fatalf("orders: M2 before O1 %d, after %d", before, after)
	}
	has(t, first, "method edition "+keylog.Short(m1)+" (authorized) declares system_keys model: every one is pinned")
	hasNot(t, first, keylog.Short(m2))
	// O1 alone with M1 (M2 not yet held) reads the same
	if v := subsetView(t, w, upTo(3), o1); v.Render() != first {
		t.Fatalf("M2 changed O1:\n%s\nvs\n%s", v.Render(), first)
	}

	v2 := obsView(t, w, o2)
	wantRef(t, v2, RefUnpinned)
	if !slices.Equal(v2.Unpinned, []string{"referent.system.routing_era"}) {
		t.Fatalf("O2 unpinned %v", v2.Unpinned)
	}
	has(t, v2.Render(), "method edition "+keylog.Short(m2)+" (authorized) declares system_keys model, routing_era")
}

// TestMethodSystemKeysUnread: C-core-32d. O1 and O2 under edition id M pin model and provider. (a) M not held,
// (b) M held only as pending (one of two approvals) declaring model, provider, routing_era: neither referent is
// unpinned on account of a declaration, comparability is unchecked naming the edition not held / pending, never
// comparable, and a corroboration of O1 on O2 does not count. (c) the second approval arrives: both unpinned
// naming system.routing_era, explain cites M. verify exits 3 in (a) and (b) naming the edition, and in (c) for the
// unpinned key only. Control: an authorized M declaring model, provider makes the pair
// comparable, the corroboration counts and verify exits 0, so the unchecked and the exit 3 in (a) and (b) are the
// edition's state.
func TestMethodSystemKeysUnread(t *testing.T) {
	conformance.Covers(t, "C-core-32d")
	w := newWorld(t)
	g := w.genesis("G", "MA", 2, "MA", "MBB") // line 0
	sys := obj("model", "m", "provider", "p")
	body := w.editionBody(g, []string{g}, nil, "system_keys", []string{"model", "provider", "routing_era"})
	m := EditionID(body)
	o1 := w.observed("O1", "P1", "B1", "method", methodRef(m, sys)) // 1
	o2 := w.observed("O2", "P2", "B2", "method", methodRef(m, sys)) // 2
	w.workflow("WA", "W", "bytes", "")                              // 3
	res := w.result("R", "C", "cmp", "W", "B1", "B2")               // 4
	w.corroborates("CS", "C", o1, res, "supports")                  // 5
	w.sign("MA1", "MA", "edition", body)                            // 6
	w.sign("MB1", "MBB", "edition", body)                           // 7

	for _, c := range []struct {
		name, unread string
		lines        []int
	}{
		{"(a) not held", DeclNotHeld, upTo(6)},
		{"(b) pending", string(Pending), upTo(7)},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, id := range []string{o1, o2} {
				v := subsetView(t, w, c.lines, id)
				if v.ReferentStatus != RefPinned || len(v.Unpinned) != 0 {
					t.Fatalf("unpinned on account of a declaration: %s %v", v.ReferentStatus, v.Unpinned)
				}
				if len(v.Comparability) != 1 || v.Comparability[0].Comparable || v.Comparability[0].EditionUnread != c.unread {
					t.Fatalf("comparability %+v", v.Comparability)
				}
				has(t, v.Render(), "comparability unchecked (method edition "+c.unread)
				hasNot(t, v.Render(), "comparable;")
				has(t, v.Render(), "method edition "+keylog.Short(m)+" "+c.unread)
				// the pins cannot be judged without the declaration: verify could not check (claims §13)
				code, why := v.VerifyExit()
				if code != 3 || !strings.Contains(strings.Join(why, ";"), "method edition "+keylog.Short(m)+" "+c.unread+": whether it declares system_keys cannot be read") {
					t.Fatalf("verify %d %v", code, why)
				}
			}
			v := subsetView(t, w, c.lines, o1)
			wantStatus(t, v, "unchecked within statements you hold")
			has(t, v.Render(), "comparability unchecked: its comparison data includes")
		})
	}
	t.Run("(c) authorized", func(t *testing.T) {
		for _, id := range []string{o1, o2} {
			v := subsetView(t, w, upTo(8), id)
			wantRef(t, v, RefUnpinned)
			if !slices.Equal(v.Unpinned, []string{"referent.system.routing_era"}) {
				t.Fatalf("unpinned %v", v.Unpinned)
			}
			has(t, v.Render(), "method edition "+keylog.Short(m)+" (authorized) declares system_keys model, provider, routing_era")
			// read now: verify exits 3 for the unpinned key, not for the edition
			code, why := v.VerifyExit()
			if j := strings.Join(why, ";"); code != 3 || !strings.Contains(j, "referent.system.routing_era") || strings.Contains(j, "cannot be read") {
				t.Fatalf("verify %d %v", code, why)
			}
		}
	})
	t.Run("control: an authorized declaration both meet", func(t *testing.T) {
		w := newWorld(t)
		g := w.genesis("G", "MA", 0, "MA")
		m := w.ed(w.editionWith("M", "MA", g, []string{g}, "system_keys", []string{"model", "provider"}))
		o1 := w.observed("O1", "P1", "B1", "method", methodRef(m, sys))
		o2 := w.observed("O2", "P2", "B2", "method", methodRef(m, sys))
		w.workflow("WA", "W", "bytes", "")
		w.corroborates("CS", "C", o1, w.result("R", "C", "cmp", "W", "B1", "B2"), "supports")
		v := obsView(t, w, o1)
		if len(v.Comparability) != 1 || v.Comparability[0].With != o2 || !v.Comparability[0].Comparable || v.Comparability[0].EditionUnread != "" {
			t.Fatalf("comparability %+v", v.Comparability)
		}
		wantStatus(t, v, "corroborated 1 within statements you hold")
		// the declaration read and met: verify passes, so the exit 3 in (a) and (b) is the edition's state
		if code, why := v.VerifyExit(); code != 0 {
			t.Fatalf("verify %d %v", code, why)
		}
	})
	// an approval's statement id names no edition (wire §3): pinning it reads as not held, never as the edition
	t.Run("an approval's statement id is not an edition id", func(t *testing.T) {
		w := newWorld(t)
		g := w.genesis("G", "MA", 0, "MA")
		ms := w.editionWith("M", "MA", g, []string{g}, "system_keys", []string{"model", "provider"})
		o1 := w.observed("O1", "P1", "B1", "method", methodRef(ms, sys))
		w.observed("O2", "P2", "B2", "method", methodRef(ms, sys))
		v := obsView(t, w, o1)
		if len(v.Comparability) != 1 || v.Comparability[0].Comparable || v.Comparability[0].EditionUnread != DeclNotHeld {
			t.Fatalf("comparability %+v", v.Comparability)
		}
	})
}

// TestMethodSystemKeysEmptyValue: C-core-32b, empty-value variant. An empty string identifies nothing, so a
// referent.system member whose value is "" counts as absent wherever system keys are compared; the statement
// itself stays admissible (no schema refusal, and the statement's own unpinned slice is untouched).
// Declared key: M1 declares model, provider, routing_era; O1 pins routing_era as "" and is unpinned naming
// referent.system.routing_era (verify exit 3), exactly as if the member were missing (O4); a value that only
// looks empty (" ") is a pinned key and is not unpinned. Undeclared comparison (C-core-32): M2 declares nothing;
// an "" member is not a key either side pins, so O5 (era "") and O6 (no era) are comparable, while O5 against O7
// (era "q3") is not, and the display names system.routing_era as the member O5 does not pin.
func TestMethodSystemKeysEmptyValue(t *testing.T) {
	conformance.Covers(t, "C-core-32b")
	t.Run("declared key", func(t *testing.T) {
		w := newWorld(t)
		g := w.genesis("G", "MC", 0, "MC")
		m1 := w.ed(w.editionWith("M1", "MC", g, []string{g}, "system_keys", []string{"model", "provider", "routing_era"}))
		o1 := w.observed("O1", "P1", "B1", "method", methodRef(m1, obj("model", "m", "provider", "p", "routing_era", "")))
		o2 := w.observed("O2", "P2", "B2", "method", methodRef(m1, obj("model", "m", "provider", "p", "routing_era", "q3")))
		o3 := w.observed("O3", "P3", "B3", "method", methodRef(m1, obj("model", "m", "provider", "p", "routing_era", " ")))
		o4 := w.observed("O4", "P4", "B4", "method", methodRef(m1, obj("model", "m", "provider", "p")))

		v1 := obsView(t, w, o1)
		wantRef(t, v1, RefUnpinned)
		if !slices.Equal(v1.Unpinned, []string{"referent.system.routing_era"}) {
			t.Fatalf("unpinned %v", v1.Unpinned)
		}
		has(t, v1.Render(), "this referent lacks referent.system.routing_era, so it is unpinned")
		if code, why := v1.VerifyExit(); code != 3 || !strings.Contains(strings.Join(why, ";"), "referent.system.routing_era") {
			t.Fatalf("verify %d %v", code, why)
		}
		// the statement is admitted whole: the schema never saw a defect
		if p, ok := w.store(nil).Statement(o1); !ok || len(p.St.Unpinned) != 0 {
			t.Fatalf("statement held=%v unpinned %v", ok, p.St.Unpinned)
		}
		// an empty value reads as a missing member: same unpinned set, same verdict
		v4 := obsView(t, w, o4)
		wantRef(t, v4, RefUnpinned)
		if !slices.Equal(v4.Unpinned, v1.Unpinned) {
			t.Fatalf("missing %v vs empty %v", v4.Unpinned, v1.Unpinned)
		}
		// controls: a real value, and a value that is not empty, are pinned
		for _, id := range []string{o2, o3} {
			v := obsView(t, w, id)
			wantRef(t, v, RefPinned)
			if code, _ := v.VerifyExit(); code != 0 {
				t.Fatalf("verify %d", code)
			}
		}
		// the unpinned key is named once in a comparison, whether it is missing or empty on the other side
		v2 := obsView(t, w, o2)
		for _, c := range v2.Comparability {
			if (c.With == o1 || c.With == o4) && (c.Comparable || !slices.Equal(c.Unpinned, []string{"referent.system.routing_era"}) || len(c.MissingHere)+len(c.MissingThere) != 0) {
				t.Fatalf("O2 vs %s: %+v", keylog.Short(c.With), c)
			}
		}
	})
	t.Run("undeclared comparison", func(t *testing.T) {
		w := newWorld(t)
		g := w.genesis("G", "MC", 0, "MC")
		m2 := w.ed(w.editionWith("M2", "MC", g, []string{g}, "selection", "curated"))
		o5 := w.observed("O5", "P5", "B5", "method", methodRef(m2, obj("model", "m", "provider", "p", "routing_era", "")))
		o6 := w.observed("O6", "P6", "B6", "method", methodRef(m2, obj("model", "m", "provider", "p")))
		o7 := w.observed("O7", "P7", "B7", "method", methodRef(m2, obj("model", "m", "provider", "p", "routing_era", "q3")))

		v5 := obsView(t, w, o5)
		wantRef(t, v5, RefPinned) // nothing declared, so nothing is unpinned on that account
		if len(v5.Unpinned) != 0 {
			t.Fatalf("unpinned %v", v5.Unpinned)
		}
		var vs6, vs7 *Comparability
		for i, c := range v5.Comparability {
			switch c.With {
			case o6:
				vs6 = &v5.Comparability[i]
			case o7:
				vs7 = &v5.Comparability[i]
			}
		}
		if vs6 == nil || !vs6.Comparable || len(vs6.MissingHere)+len(vs6.MissingThere) != 0 {
			t.Fatalf("O5 vs O6 (an empty member is not a pinned key): %+v", v5.Comparability)
		}
		if vs7 == nil || vs7.Comparable || !slices.Equal(vs7.MissingThere, []string(nil)) || !slices.Equal(vs7.MissingHere, []string{"system.routing_era"}) {
			t.Fatalf("O5 vs O7: %+v", v5.Comparability)
		}
		has(t, v5.Render(), "this observation does not pin system.routing_era")
		// the member is still shown as the observer wrote it
		has(t, v5.Render(), `"routing_era":""`)
	})
}
