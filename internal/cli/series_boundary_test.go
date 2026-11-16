package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/resolve"
)

// seriesWorld is a store holding a series of five monthly segments (the settlement profile's states, one per month
// of 2025) and an edition declaring frozen_before frozen (a `date`, or a `height` when the declaration is in another
// unit). pin installs the profile and the store-root policy that pins it: without a pin no segment's state is
// re-checked. It returns the world and the series' genesis id.
func seriesWorld(t *testing.T, states []string, frozen *canon.Object, pin bool) (*world, string) {
	t.Helper()
	prof := canon.Encode(obj("profile", resolve.SourceProfileTag, "source", "https://api.example/settlement",
		"dialect", resolve.DialectOrderedLabel, "labels", []string{"SF", "R1", "R2", "RF", "DF"}))
	pd := dig(string(prof))
	w := newWorld(t)
	g := w.sign("G", "C", "genesis", obj("type", "series", "name", "settlements", "controllers", []string{w.signer("C")}, "rule", obj("any_one", true)))
	segs := canon.Array{}
	for i, st := range states {
		m := fmt.Sprintf("2025-%02d", i+1)
		ref := obj("endpoint", "https://api.example/settlement", "parameters", obj("period", m), "response_digest", dig(m),
			"window", obj("from", m+"-01T00:00:00Z", "to", m+"-28T00:00:00Z"))
		id := w.sign("S"+m, "O", "observed", obj("content", content(m), "class", "source", "referent", canon.Value(ref),
			"capture", obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted"),
			"finality", obj("rule", "run >= RF", "rule_source", pd, "state_at_capture", obj("run", st))))
		segs = append(segs, obj("statement", id, "role", "segment"))
	}
	contents := []any{"members", canon.Value(segs)}
	if frozen != nil {
		contents = append(contents, "frozen_before", canon.Value(frozen))
	}
	w.sign("E", "C", "edition", obj("resource", g, "predecessors", []string{g}, "contents", obj(contents...)))
	if pin {
		w.blob("profile", prof)
		if err := os.WriteFile(filepath.Join(w.root, PolicyFile), []byte(profilePin(pd)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return w, g
}

// seriesCase is one state of the series boundary comparison and the series that yields it.
type seriesCase struct {
	name   string
	states []string
	frozen *canon.Object
	pin    bool
	want   string
	wantIn []string // substrings of the JSON member, besides the state
}

// seriesCases is every state of the comparison, one series each.
func seriesCases() []seriesCase {
	date := func(d string) *canon.Object { return obj("date", d) }
	ok := []string{"DF", "RF", "DF", "RF", "DF"}
	return []seriesCase{
		// every segment final: the boundary is the last window; a declaration no later agrees (as captured)
		{"agrees", ok, date("2025-02-01"), true, "agrees", []string{`"basis":"as captured, not re-checked"`, `"members_final_to":"2025-05-28"`}},
		// April is provisional (R2): the boundary is 2025-04-01; a declaration of 2025-06-01 is later
		{"flagged", []string{"DF", "RF", "DF", "R2", "SF"}, date("2025-06-01"), true, "flagged",
			[]string{`"members_final_to":"2025-04-01"`, `"provisional_segments":2`}},
		// a declaration in another unit is never converted
		{"not comparable", ok, obj("height", 800000), true, "not comparable", []string{"never converted"}},
		// no pinned profile: no segment is re-checked, so nothing is decided, however late the declaration
		{"unchecked, no profile", ok, date("2025-06-01"), false, "unchecked", []string{"finality could not be checked"}},
		// no declaration: nothing to compare
		{"unchecked, undeclared", ok, nil, true, "unchecked", []string{"no frozen_before declared"}},
	}
}

// TestSeriesBoundaryIsTyped: C-core-132, C-core-104 on the series view. The comparison of an edition's declared
// `frozen_before` with the boundary its members' finality rules compute is a typed `series_boundary` member of the
// series resource, its `state` one of `agrees`, `flagged`, `not comparable`, `unchecked` (its own closed set: a
// comparison, not a rule evaluation) beside a `why`, and the human surface prints the same word. It moves no exit:
// show and verify of the series exit as they do without a declaration.
func TestSeriesBoundaryIsTyped(t *testing.T) {
	conformance.Partial(t, "C-core-132", "the series boundary comparison is a typed state member of the series view (`series_boundary`: `state` one of agrees, flagged, not comparable, unchecked, beside `why`), here and on the gate rows (TestGateSeriesBoundaryIsTyped)")
	for _, c := range seriesCases() {
		t.Run(c.name, func(t *testing.T) {
			w, g := seriesWorld(t, c.states, c.frozen, c.pin)
			for _, cmd := range []string{"show", "explain"} {
				r := w.run(cmd, g, "--json")
				if r.code != ExitOK {
					t.Fatalf("%s: exit %d\n%s", cmd, r.code, r.stdout)
				}
				rv, _ := jsonOf(t, r).Members["resource_view"].(*canon.Object)
				sb, isObj := rv.Members["series_boundary"].(*canon.Object)
				if !isObj {
					t.Fatalf("%s: series_boundary is not a typed member: %s", cmd, r.stdout)
				}
				if sb.Members["state"] != canon.String(c.want) || !IsToken(c.want) {
					t.Fatalf("%s: state %s, want %s", cmd, canon.Encode(sb.Members["state"]), c.want)
				}
				if why, _ := sb.Members["why"].(canon.String); why == "" {
					t.Fatalf("%s: no why: %s", cmd, canon.Encode(sb))
				}
				for _, want := range c.wantIn {
					if !strings.Contains(string(canon.Encode(sb)), want) {
						t.Errorf("%s: series_boundary lacks %q: %s", cmd, want, canon.Encode(sb))
					}
				}
				if cmd == "show" && sb.Members["reasoning"] != nil {
					t.Errorf("show prints the reasoning, which is explain's")
				}
				if h := w.run(cmd, g); !humanSeriesState(h.stdout, c.want) {
					t.Fatalf("%s: the human surface lacks `state: %s` under `series boundary`:\n%s", cmd, c.want, h.stdout)
				}
			}
			// the sweep of the resource surface (tokens in the table, on both surfaces) over this series
			sweepRefs(t, w, []string{g})
			// it moves no exit: the series' verify is what it is without a declaration
			if v := w.run("verify", g); v.code != ExitOK && v.code != ExitCouldNot {
				t.Fatalf("verify of the series: %d", v.code)
			}
		})
	}
	// a collection prints no series boundary at all
	w, refs := resourceWorld(t)
	for _, ref := range refs {
		if rv, _ := jsonOf(t, w.run("show", ref, "--json")).Members["resource_view"].(*canon.Object); rv != nil && rv.Members["series_boundary"] != nil {
			t.Fatalf("a non-series %s printed a series boundary", ref)
		}
	}
}

// TestGateSeriesBoundaryIsTyped: C-core-132, C-core-104 on the gate. A receiver whose policy sets
// series.refuse_premature_freeze carries the comparison on the row of the edition it judged as the same typed
// `series_boundary` member `show` prints: flagged on the refused row, unchecked on the could-not-check row (no
// pinned profile: the shipped reason), and the one-line human row prints the same word beside the labels.
func TestGateSeriesBoundaryIsTyped(t *testing.T) {
	conformance.Partial(t, "C-core-132", "the gate's series boundary comparison is a typed state member of the report row (this test)")
	src, prof, pd := settlementPackage(t)
	for _, c := range []struct {
		name, state, verdict string
		pin                  bool
		code                 int
	}{
		{"flagged", "flagged", "refused", true, 1},
		{"unchecked", "unchecked", "could not check", false, 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			dst := newWorld(t)
			pol := `{"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":true}}`
			if c.pin {
				dst.blob("profile", prof)
				pol = profilePin(pd)
			}
			os.WriteFile(filepath.Join(dst.root, PolicyFile), []byte(pol), 0o644)
			r := dst.run("pull", src.root, "--json")
			if r.code != c.code {
				t.Fatalf("exit %d, want %d\n%s", r.code, c.code, r.stdout)
			}
			var row *canon.Object
			for _, x := range jsonOf(t, r).Members["objects"].(canon.Array) {
				if o := x.(*canon.Object); o.Members["id"] == canon.String(src.ids["E"]) {
					row = o
				}
			}
			if row == nil || row.Members["verdict"] != canon.String(c.verdict) {
				t.Fatalf("the edition's row: %v\n%s", row, r.stdout)
			}
			sb, ok := row.Members["series_boundary"].(*canon.Object)
			if !ok || sb.Members["state"] != canon.String(c.state) || !IsToken(c.state) {
				t.Fatalf("series_boundary on the row: %s", canon.Encode(row))
			}
			if h := dst.run("pull", src.root); !strings.Contains(h.stdout, "series boundary state: "+c.state) {
				t.Fatalf("the human row lacks `series boundary state: %s`:\n%s", c.state, h.stdout)
			}
		})
	}
}

// humanSeriesState reports whether the human output has a `series boundary:` block whose first member is `state: want`.
func humanSeriesState(out, want string) bool {
	lines := strings.Split(out, "\n")
	for i, l := range lines[:len(lines)-1] {
		if strings.TrimSpace(l) == "series boundary:" && strings.TrimSpace(lines[i+1]) == "state: "+want {
			return true
		}
	}
	return false
}
