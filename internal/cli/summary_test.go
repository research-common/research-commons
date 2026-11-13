package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// TestDerivedScopedSummarySurfaces: C-core-73 through the commands. A derived result over three observations
// (replication bytes/protocol/bytes, shelf lives 30/7/90, per-input n 10/20/5, finality 2 final + 1 provisional
// under `confirmations >= 6`, one input contradicted once): show, verify, explain and list print, beside the grade,
// replication `protocol` (weakest), shelf life 7 days (shortest), the per-input n, `rests on 3 observation(s): 2
// final (as captured, not re-checked); 1 provisional until 6; 1 contradicted within statements you hold`, every line scoped; the grade
// and exit are those of the same derivation over inputs with no disclosures; explain lists the statements that
// declared each input's disclosures.
func TestDerivedScopedSummarySurfaces(t *testing.T) {
	conformance.Covers(t, "C-core-73")
	build := func(disclose bool) (*world, []string) {
		w := newWorld(t)
		ref := func(i int) *canon.Object {
			return obj("chain_id", "bip122:000000000019d6689c085ae165831e93", "block_hash", strings.Repeat(string(rune('a'+i)), 64), "depth", 12)
		}
		var obs []string
		for i, s := range []struct {
			repl         string
			shelf, n, dp int
		}{{"bytes", 30, 10, 12}, {"protocol", 7, 20, 12}, {"bytes", 90, 5, 2}} {
			kv := []any{"content", canon.Value(content("in" + string(rune('0'+i)))), "class", "exact-bytes", "referent", canon.Value(ref(i)),
				"capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted")),
				"finality", canon.Value(obj("rule", "confirmations >= 6", "state_at_capture", obj("depth", s.dp)))}
			if disclose {
				kv = append(kv, "replication", s.repl, "shelf_life_days", s.shelf, "sampling", canon.Value(obj("n", s.n, "unit", "blocks")))
			}
			name := "O" + string(rune('0'+i))
			w.sign(name, "K"+string(rune('4'+i)), "observed", obj(kv...))
			obs = append(obs, name)
		}
		w.sign("CC", "K8", "corroborates", obj("of", w.ids["O0"], "result", strings.Repeat("ab", 32), "verdict", "contradicts", "model", "bounds/1",
			"cohort", canon.Value(obj("rule", "chain record"))))
		w.workflow("K1", "wf", "bytes", "")
		w.authored("A", "K1", "res", "prov", []string{"wf", "in0", "in1", "in2"})
		w.authored("B", "K2", "res", "prov", []string{"wf", "in0", "in1", "in2"})
		return w, obs
	}
	w, obs := build(true)
	base, _ := build(false)
	d := dig("res")
	want := []string{
		"replication: protocol (weakest; 3 of 3 inputs declare one) (within statements you hold)",
		"shelf life: 7 days (shortest; 3 of 3 inputs declare one) (within statements you hold)",
		"sampling per input (3 of 3 declare): ",
	}
	restsOn := "rests on 3 observation(s): 2 final (as captured, not re-checked); 1 provisional until 6; 1 contradicted within statements you hold"
	list := jsonOf(t, w.run("list", "--json")).Members["blobs"].(canon.Array)
	var surfaces []*canon.Object
	for _, b := range list {
		if bo := b.(*canon.Object); bo.Members["digest"] == canon.String(d) {
			surfaces = append(surfaces, bo)
		}
	}
	for _, cmd := range []string{"show", "verify", "explain"} {
		surfaces = append(surfaces, jsonOf(t, w.run(cmd, d, "--json")))
	}
	var first string
	for i, o := range surfaces {
		lines := string(canon.Encode(o.Members["inputs_summary"]))
		for _, x := range want {
			if !strings.Contains(lines, x) {
				t.Fatalf("surface %d: summary lacks %q: %s", i, x, lines)
			}
		}
		for _, n := range []string{" 10 blocks", " 20 blocks", " 5 blocks"} {
			if !strings.Contains(lines, n) {
				t.Fatalf("surface %d: per-input n lacks %q: %s", i, n, lines)
			}
		}
		ro := string(canon.Encode(o.Members["rests_on"]))
		if !strings.Contains(ro, restsOn) {
			t.Fatalf("surface %d: rests_on %s", i, ro)
		}
		if first == "" {
			first = lines + ro
		} else if lines+ro != first {
			t.Fatalf("surface %d disagrees:\n%s\n%s", i, lines+ro, first)
		}
	}
	h := w.run("show", d).stdout
	for _, x := range append(want, restsOn) {
		if !strings.Contains(h, x) {
			t.Fatalf("human surface lacks %q:\n%s", x, h)
		}
	}
	// grade and exit are those of the same derivation without any disclosure
	a, b := w.run("verify", d, "--json"), base.run("verify", d, "--json")
	if a.code != b.code || jsonOf(t, a).Members["grade"] != jsonOf(t, b).Members["grade"] {
		t.Fatalf("the summary moved the grade or exit: %d %s vs %d %s", a.code, canon.Encode(jsonOf(t, a).Members["grade"]), b.code, canon.Encode(jsonOf(t, b).Members["grade"]))
	}
	// explain expands each: every observation behind the summary, the contradiction and each input's authors
	ex := jsonOf(t, w.run("explain", d, "--json"))
	listed := map[string]bool{}
	for _, x := range ex.Members["statements"].(canon.Array) {
		listed[string(x.(*canon.Object).Members["statement"].(canon.String))] = true
	}
	for _, n := range obs {
		if !listed[w.ids[n]] {
			t.Fatalf("explain does not list %s, whose disclosures the summary read", n)
		}
	}
}
