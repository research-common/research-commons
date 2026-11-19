package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
)

// timeMember is the `time` member of a statement view, or nil when the view has none.
func timeMember(t *testing.T, w *world, args ...string) *canon.Object {
	t.Helper()
	o := jsonOf(t, w.run(append(args, "--json")...))
	tm, _ := o.Members["time"].(*canon.Object)
	return tm
}

// encTime renders a time member for a failure message, nil-safe.
func encTime(tm *canon.Object) string {
	if tm == nil {
		return "(absent)"
	}
	return string(canon.Encode(tm))
}

// withoutTime is a view's JSON with the `time` member dropped, as bytes.
func withoutTime(t *testing.T, r result) string {
	t.Helper()
	o := jsonOf(t, r)
	rest := &canon.Object{Members: map[string]canon.Value{}}
	for k, v := range o.Members {
		if k != "time" {
			rest.Members[k] = v
		}
	}
	return string(canon.Encode(rest))
}

// TestStatementViewShowsTimeBound: a statement covered by an anchors line of its signer shows the bound the reader
// derives (bitcoin-time note §2: the reader's conclusion that S existed by P, at the quality it assigns) on
// `show`, `verify` and `explain`, in the shape an authored artifact's claim shows it: quality, anchor, time_state.
// A statement no anchors line covers shows quality `none`. The bound is a disclosure: it never moves an exit and
// changes no other member. An anchors line keeps its own evidence member.
func TestStatementViewShowsTimeBound(t *testing.T) {
	w := newWorld(t)
	first := w.authored("A1", "A", "X")
	covered := w.authored("A2", "A", "Y", "type", "dataset")

	views := [][]string{{"show", covered}, {"verify", covered}, {"explain", covered}}
	type snap struct {
		code int
		rest string
	}
	before := map[string]snap{}
	for _, args := range views {
		if tm := timeMember(t, w, args...); tm == nil || tm.Members["quality"] != canon.String("none") || len(tm.Members) != 1 {
			t.Fatalf("%v before any anchor: time = %s, want {quality: none}", args, encTime(tm))
		}
		r := w.run(append(args, "--json")...)
		before[args[0]] = snap{r.code, withoutTime(t, r)}
	}

	anchor := w.anchorHead("AA1", "A", covered, 100)
	later := w.authored("A3", "A", "Z", "type", "dataset") // chained after the covered head: no anchor covers it

	for _, ref := range []string{first, covered} { // the covered head and a statement in its history
		for _, args := range [][]string{{"show", ref}, {"verify", ref}, {"explain", ref}} {
			tm := timeMember(t, w, args...)
			if tm == nil {
				t.Fatalf("%v: no time member although anchor %s covers it", args, anchor)
			}
			if tm.Members["quality"] != canon.String("local") || tm.Members["anchor"] != canon.String(anchor) ||
				tm.Members["time_state"] != canon.String(string(btctime.StateUnconfigured)) {
				t.Fatalf("%v: time = %s, want quality local, anchor %s, time_state backend-unconfigured", args, encTime(tm), anchor)
			}
		}
	}
	for _, args := range views {
		r := w.run(append(args, "--json")...)
		if b := before[args[0]]; r.code != b.code || withoutTime(t, r) != b.rest {
			t.Fatalf("%v: covering the statement changed more than the time member (exit %d → %d)\n%s\n%s", args, b.code, r.code, b.rest, withoutTime(t, r))
		}
	}
	for _, args := range [][]string{{"show", later}, {"verify", later}, {"explain", later}} {
		if tm := timeMember(t, w, args...); tm == nil || tm.Members["quality"] != canon.String("none") || tm.Members["anchor"] != nil {
			t.Fatalf("%v: a statement after the covered head: time = %s, want quality none", args, encTime(tm))
		}
	}

	// the human rendering names it too
	if h := w.run("show", covered).stdout; !strings.Contains(h, "time:") || !strings.Contains(h, "quality: local") {
		t.Fatalf("human show of a covered statement lacks its time:\n%s", h)
	}

	// the anchors statement keeps its own evidence member (policy fingerprint and verifier version), not a bound
	for _, args := range [][]string{{"show", anchor}, {"verify", anchor}} {
		tm := timeMember(t, w, args...)
		if tm == nil || tm.Members["policy_fingerprint"] == nil || tm.Members["verifier_version"] == nil || tm.Members["anchor"] != nil {
			t.Fatalf("%v: an anchors line's time = %s, want its evidence member", args, encTime(tm))
		}
	}
}

// TestEditionStatementShowsTimeBound is the shape of the reported case: an `edition` statement, covered by an
// anchors line of its signer, shows the bound on `show` and `verify`; its exit is what it was before the anchor.
func TestEditionStatementShowsTimeBound(t *testing.T) {
	w := newWorld(t)
	g := w.genesisOf("G", "A", 0, "A")
	ed, _ := w.approve("E1", "A", editionBody(g, []string{g}, []string{"M"}))
	verifyBefore := w.run("verify", ed, "--json")
	if tm := timeMember(t, w, "show", ed); tm == nil || tm.Members["quality"] != canon.String("none") {
		t.Fatalf("show of an uncovered edition: time = %s, want quality none", encTime(tm))
	}
	anchor := w.anchorHead("AA1", "A", ed, 100)
	for _, cmd := range []string{"show", "verify"} {
		tm := timeMember(t, w, cmd, ed)
		if tm == nil || tm.Members["quality"] != canon.String("local") || tm.Members["anchor"] != canon.String(anchor) ||
			tm.Members["time_state"] != canon.String(string(btctime.StateUnconfigured)) {
			t.Fatalf("%s of a covered edition: time = %s", cmd, encTime(tm))
		}
	}
	after := w.run("verify", ed, "--json")
	if after.code != verifyBefore.code || withoutTime(t, after) != withoutTime(t, verifyBefore) {
		t.Fatalf("verify of the edition statement changed beyond its time member: exit %d → %d\n%s\n%s",
			verifyBefore.code, after.code, verifyBefore.stdout, after.stdout)
	}
}
