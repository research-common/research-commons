package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// TestExplainSinceNamesTimeContext: P-08's time-context half. A configured chain backend is the source of a
// read-time-dependent answer: in the chain world (two keys claim X, anchored at heights 10 and 12), X's answer is
// contested before any sync, a ranked default author once the headers are synced, and verified-historical (not
// ranked) two hours later when the view is past its maximum age. explain --since the saved explain of each
// earlier state names `time context changed` (from the earlier context, to the current one) and no statement,
// reader policy or evaluator change: no statement was added, so nothing else may be named (the time policy
// aside, see onlyTime). Unchanged state (the same
// clock, re-read) names nothing, and the answer is unchanged. The control: the answer does change across the
// three states, so the check is not vacuous.
func TestExplainSinceNamesTimeContext(t *testing.T) {
	conformance.Partial(t, "P-08", "the time context: a chain backend configured by `anchor headers sync`, then the view aging past its maximum age, each moves X's answer, and explain --since names `time context changed` as the only cause; an execution-context change is not an explain input: verify --rerun names it as `environment mismatch: <field>` (C-exec-13), and whether that meets the case is open")
	c := newChainWorld(t, 30)
	now := c.tip.Add(10 * time.Minute)
	useTestChain(t, &now, 0)
	x := dig("X")
	save := func() string {
		t.Helper()
		r := c.run("explain", x, "--json")
		f := filepath.Join(t.TempDir(), "saved.json")
		if err := os.WriteFile(f, []byte(r.stdout), 0o644); err != nil {
			t.Fatal(err)
		}
		return f
	}
	since := func(f string) (*canon.Object, []string) {
		t.Helper()
		r := c.run("explain", x, "--since", f, "--json")
		if r.code != ExitOK {
			t.Fatalf("explain --since: %d %s", r.code, r.stdout)
		}
		s, ok := jsonOf(t, r).Members["since"].(*canon.Object)
		if !ok {
			t.Fatalf("no since member: %s", r.stdout)
		}
		var changes []string
		for _, x := range s.Members["changes"].(canon.Array) {
			changes = append(changes, stringMember(x.(*canon.Object), "change"))
		}
		h := c.run("explain", x, "--since", f)
		for _, ch := range changes {
			if !strings.Contains(h.stdout, "change: "+ch) {
				t.Fatalf("human surface lacks change %q:\n%s", ch, h.stdout)
			}
		}
		return s, changes
	}
	// onlyTime: the answer changed, `time context changed` is named, and nothing else is, except (policyToo) the
	// time policy: useTestChain gives the chain view a test network's policy while a reader with no backend reads
	// DefaultPolicy, so going from no backend to a backend changes the fingerprint too in this harness (in a
	// release build both are DefaultPolicy). That row is a true cause, named with its digests.
	onlyTime := func(state string, s *canon.Object, changes []string, policyToo bool) {
		t.Helper()
		if s.Members["answer"] != canon.String("answer changed") {
			t.Fatalf("%s: the answer did not change across the time context: %s", state, canon.Encode(s))
		}
		want := []string{"time context changed"}
		if policyToo {
			want = []string{"time policy changed", "time context changed"}
		}
		if !slices.Equal(changes, want) {
			t.Fatalf("%s: changes %q, want %q\n%s", state, changes, want, canon.Encode(s))
		}
		if _, ok := s.Members["unexplained"]; ok {
			t.Fatalf("%s: unexplained difference: %s", state, canon.Encode(s))
		}
	}

	// S0: no chain backend
	s0 := save()
	if s, ch := since(s0); s.Members["answer"] != canon.String("answer unchanged") || len(ch) != 0 {
		t.Fatalf("unchanged state: %s %q", canon.Encode(s), ch)
	}
	// S1: the headers are synced; the same statements now rank
	if r := c.run("anchor", "headers", "sync", "--from", c.headers); r.code != ExitOK {
		t.Fatalf("sync: %d %s", r.code, r.stdout+r.stderr)
	}
	s, ch := since(s0)
	onlyTime("after sync", s, ch, true)
	s1 := save()
	if s, ch := since(s1); s.Members["answer"] != canon.String("answer unchanged") || len(ch) != 0 {
		t.Fatalf("unchanged state after sync: %s %q", canon.Encode(s), ch)
	}
	// S2: the clock moves two hours: the view is past its maximum age, the bounds verified-historical
	now = now.Add(2 * time.Hour)
	s, ch = since(s1)
	onlyTime("aged view", s, ch, false)
	if tc := stringMember(jsonOf(t, c.run("explain", x, "--json")), "time_context"); !strings.Contains(tc, "not fresh") {
		t.Fatalf("aged view: time context %q does not name the staleness", tc)
	}
	// and from S0 straight to S2: still the time context alone
	s, ch = since(s0)
	onlyTime("no backend to aged view", s, ch, true)
}
