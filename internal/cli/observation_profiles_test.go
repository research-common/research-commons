package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/resolve"
)

// profileWorld is a store holding an ordered-label source profile P (labels SF < R1 < RF) and one source-class
// observation whose rule `run >= RF` cites P's digest, captured at state; pin writes the store-root policy
// pinning P (or, with pin false, a policy without it).
func profileWorld(t *testing.T, state string, pin bool) (w *world, id, pd string) {
	t.Helper()
	prof := canon.Encode(obj("profile", resolve.SourceProfileTag, "source", "https://api.example/settlement",
		"dialect", resolve.DialectOrderedLabel, "labels", []string{"SF", "R1", "RF"}))
	pd = dig(string(prof))
	w = newWorld(t)
	w.blob("p", prof)
	pol := `{"policy":"rc-hub-policy/1"}`
	if pin {
		pol = `{"policy":"rc-hub-policy/1","series":{"source_profiles":[{"digest":"` + pd + `"}]}}`
	}
	if err := os.WriteFile(filepath.Join(w.root, PolicyFile), []byte(pol), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := obj("endpoint", "https://api.example/settlement", "parameters", obj("period", "x"), "response_digest", dig("x"))
	id = w.sign("O", "O", "observed", obj("content", content("x"), "class", "source", "referent", canon.Value(ref),
		"capture", obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted"),
		"finality", obj("rule", "run >= RF", "rule_source", pd, "state_at_capture", obj("run", state))))
	return w, id, pd
}

// TestObservationReadsPinnedProfile: the read commands resolve an observation's ordered-label rule through the
// source profile the store-root policy pins and its rule_source cites (claims-model note §5.3.1a). At `RF` the
// referent is `final (as captured, not re-checked)`, never plain `final` (the profile orders the observer's
// asserted state; nothing re-checked the source), exit 0; at `R1` it is provisional, final at `RF`, exit 0; the
// same store with the pin removed is `finality unchecked`, exit 3, as before profiles were read. show and explain
// read the same status. A pin this store does not hold stops every read command (exit 2) naming the entry.
func TestObservationReadsPinnedProfile(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		pin         bool
		exit        int
		want        []string // on verify, show and explain
		not         []string
	}{
		{"pinned, met", "RF", true, ExitOK, []string{"referent:\n  status: final (as captured, not re-checked)\n"},
			[]string{"status: final\n", "finality unchecked"}},
		{"pinned, unmet", "R1", true, ExitOK, []string{"referent:\n  status: provisional\n  detail: R1; final at RF\n"},
			[]string{"finality unchecked", "as captured"}},
		{"unpinned (control)", "RF", false, ExitCouldNot, []string{"referent:\n  status: finality unchecked\n"},
			[]string{"as captured", "provisional"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, id, pd := profileWorld(t, tc.state, tc.pin)
			for _, cmd := range []string{"verify", "show", "explain"} {
				r := w.run(cmd, id)
				if cmd == "verify" && r.code != tc.exit {
					t.Fatalf("verify: exit %d, want %d:\n%s", r.code, tc.exit, r.stdout)
				}
				for _, s := range tc.want {
					if !strings.Contains(r.stdout, s) {
						t.Fatalf("%s: want %q:\n%s", cmd, s, r.stdout)
					}
				}
				for _, s := range tc.not {
					if strings.Contains(r.stdout, s) {
						t.Fatalf("%s: has %q:\n%s", cmd, s, r.stdout)
					}
				}
				// the history (show and explain) names the profile that ordered the asserted state
				if named := strings.Contains(r.stdout, "under source profile "+keylog.Short(pd)); cmd != "verify" && named != tc.pin {
					t.Fatalf("%s: profile named %v, want %v:\n%s", cmd, named, tc.pin, r.stdout)
				}
			}
			if !tc.pin {
				has := w.run("verify", id).stdout
				if !strings.Contains(has, "about: referent\n    state: finality unchecked") {
					t.Fatalf("control: the exit-3 cause is gone:\n%s", has)
				}
			}
		})
	}
	t.Run("pin not held", func(t *testing.T) {
		w, id, _ := profileWorld(t, "RF", false)
		missing := dig("a profile this store does not hold")
		if err := os.WriteFile(filepath.Join(w.root, PolicyFile),
			[]byte(`{"policy":"rc-hub-policy/1","series":{"source_profiles":[{"digest":"`+missing+`"}]}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"verify", id}, {"show", id}, {"explain", id}, {"list"}} {
			r := w.run(args...)
			if r.code != ExitDidNotStart || !strings.Contains(r.stdout+r.stderr, "series.source_profiles[0] "+missing+" is not held at this store") {
				t.Fatalf("%s: exit %d, want %d naming the entry:\n%s%s", args[0], r.code, ExitDidNotStart, r.stdout, r.stderr)
			}
		}
	})
}

// TestPublishOneClassPerStatement: C-core-35 through the writer. A draft `observed` asserting two classes (one blob
// mixing chain state and an API read) is refused before signing: intrinsic, malformed statement, scope this
// statement only, the text says to publish separate blobs, and nothing is pinned or appended. Control: the same
// draft with one class publishes.
func TestPublishOneClassPerStatement(t *testing.T) {
	conformance.Covers(t, "C-core-35")
	p := newPubWorld(t)
	draft := func(class string) string {
		return `{"kind":"observed","body":{"content":{"digest":"` + dig("mixed") + `","size":5},"class":` + class +
			`,"referent":{"endpoint":"https://api.example/x","parameters":{},"response_digest":"` + dig("mixed") +
			`"},"capture":{"at":"2026-01-02T00:00:00Z","evidence":"self-asserted"}}}`
	}
	before := snapshot(t, p.root)
	r := p.publish("--draft", p.file("two", draft(`["exact-bytes","source"]`)))
	o := outObj(t, r)
	if r.code != ExitDidNotStart || o.Members["class"] != canon.String("intrinsic") || o.Members["scope"] != canon.String("this statement") ||
		o.Members["committed"] != canon.Bool(false) || !strings.Contains(r.stdout, "malformed statement") || !strings.Contains(r.stdout, "publish separate blobs") {
		t.Fatalf("two classes: %d %s", r.code, r.stdout)
	}
	if snapshot(t, p.root) != before {
		t.Fatal("a refused draft changed the store")
	}
	if r := p.publish("--draft", p.file("one", draft(`"source"`))); r.code != ExitOK {
		t.Fatalf("control: %d %s", r.code, r.stdout)
	}
}
