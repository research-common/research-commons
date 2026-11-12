package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// TestUnknownKindGrantsNothing: C-core-13 through the CLI. A store with a blob with one author, a collection with
// an edition, and an observation with a corroboration. Then a well-formed, validly signed statement of an
// unregistered kind, by a key with no standing, asserting authorship-like, licence-like and membership-like
// fields on that blob, that collection and that observation. The new statement is stored in its signer's log and
// shown as an unknown kind; for every other ref, show, verify and list answer exactly as before (defaults, grade,
// membership, corroboration status, exit), with the signer's own statement the only difference.
func TestUnknownKindGrantsNothing(t *testing.T) {
	conformance.Covers(t, "C-core-13")
	w := newWorld(t)
	w.blob("X", []byte("X"))
	w.authored("A:X", "K1", "X", "licence", "CC0-1.0")
	g := w.genesisOf("G", "K1", 0, "K1")
	_, e1 := w.approve("E1", "K1", editionBody(g, []string{g}, []string{"X"}))
	ref := obj("chain_id", "bip122:000000000019d6689c085ae165831e93", "block_hash", strings.Repeat("a1", 32), "depth", 3)
	ob := w.sign("O", "K5", "observed", obj("content", canon.Value(content("X")), "class", "exact-bytes", "referent", canon.Value(ref),
		"capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted"))))
	w.sign("C", "K6", "corroborates", obj("of", ob, "result", w.ids["A:X"], "verdict", "supports", "model", "M",
		"cohort", canon.Value(obj("rule", "every station in R"))))

	refs := []string{dig("X"), w.ids["A:X"], g, e1, ob, w.ids["C"]}
	view := func() map[string]string {
		m := map[string]string{}
		for _, r := range refs {
			for _, c := range []string{"show", "verify"} {
				o := w.run(c, r, "--json")
				m[c+" "+r] = string(rune('0'+o.code)) + o.stdout
			}
		}
		m["list"] = w.run("list", "--json").stdout
		return m
	}
	before := view()
	u := w.sign("U", "K9", "x_endorses", obj("content", canon.Value(content("X")), "author", w.signer("K9"), "licence", "MIT",
		"members", canon.Array{obj("content", dig("X"), "role", "member")}, "resource", g, "of", ob, "verdict", "contradicts", "result", w.ids["A:X"]))
	after := view()
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s changed under an unknown kind:\n%s\nvs\n%s", k, v, after[k])
		}
	}
	// the unknown kind is stored in its signer's log and shown as one, counting toward nothing it asserts
	s := w.run("show", u, "--json")
	if s.code != 0 || !strings.Contains(s.stdout, `"kind":"x_endorses"`) || !strings.Contains(s.stdout, "unknown kind") {
		t.Fatalf("the unknown kind is not shown as one: %d %s", s.code, s.stdout)
	}
	if !strings.Contains(w.run("show", u).stdout, "line: chained") {
		t.Fatal("not stored in its signer's log")
	}
	for _, bad := range []string{`"MIT"`, w.signer("K9")} {
		for k, v := range after {
			if strings.Contains(v, bad) && !strings.HasPrefix(k, "list") {
				t.Errorf("%s shows %s as an asserted value", k, bad)
			}
		}
	}
}
