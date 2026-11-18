package cli

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/resolve"
)

// absenceClaim is a phrase asserting the absence of what a reader never received (the resolver half's
// completenessClaim, plus the words a CLI surface could add: "not found", "missing", "does not exist").
var absenceClaim = regexp.MustCompile(`(?i)\b(no (other|more|further|newer|later) (corroborations?|contradictions?|editions?|retractions?|statements?|refutations?)|no contradictions?|uncontradicted|not contradicted|all (corroborations|statements|editions)|none exist|nothing else|up[- ]to[- ]date|is the latest|latest edition|does not exist|nonexistent|not found|missing)\b`)

// TestWithheldEditionAndContradictionAreScoped: P-12 through `pull` and the resource and membership views. The
// source holds a resource G whose edition E1 lists an exact-bytes observation X as a member; X has two
// supporting corroborations and one contradicting; a newer edition E2 (after E1, dropping X) is approved. A
// relayer serves everything except E2 and the contradiction. The reader's show, verify and explain of G, of E1
// and of X: the resource's current edition is E1, the corroboration status reads `corroborated 2 … within
// statements you hold` with no contradiction, every surface carries one status_scope footer, and no surface
// claims the absence of a newer edition or a contradiction, or lists the withheld statements. Pulling the rest
// moves every answer the expected way (current E2, a contradiction counted), still scoped. The control is that
// move: the views do read the withheld statements once held.
func TestWithheldEditionAndContradictionAreScoped(t *testing.T) {
	// with C-core-01 (TestRelayerOmissionIsScoped: a withheld retraction and corroboration through pull), the
	// footer on every view command (TestStatusScopeFooter), the resolver half over generated worlds with each
	// statement withheld in turn (internal/resolve.TestPropertyWithheldStatementsScopeTheStatus) and the exchange
	// view (internal/resolve.TestPropertyExchangeWithheldClaimsNoAbsence), every withheld kind the case names
	// (a retraction, a contradiction, a newer edition) is checked on every surface
	conformance.Covers(t, "P-12")
	src := newWorld(t)
	src.blob("x", []byte("x"))
	ref := obj("chain_id", "bip122:000000000019d6689c085ae165831e93", "block_hash", strings.Repeat("a1", 32), "depth", 3)
	x := src.sign("X", "K5", "observed", obj("content", canon.Value(content("x")), "class", "exact-bytes", "referent", canon.Value(ref),
		"capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted"))))
	src.authored("R", "K1", "x")
	corr := func(name, by, verdict string) {
		src.sign(name, by, "corroborates", obj("of", x, "result", strings.Repeat("ab", 32), "verdict", verdict, "model", "M",
			"cohort", canon.Value(obj("rule", "every station in R"))))
	}
	corr("S1", "K10", "supports")
	corr("S2", "K20", "supports")
	corr("CX", "K30", "contradicts")
	g := src.genesisOf("G", "A", 0, "A")
	e1s, e1 := src.approve("E1", "A", obj("resource", g, "predecessors", []string{g}, "contents",
		obj("members", canon.Value(canon.Array{obj("statement", x, "role", "member")}))))
	e2s, e2 := src.approve("E2", "A", editionBody(g, []string{e1}, []string{"other"}))

	blobs, stmts := dataObjects(t, src.root)
	pathOf := func(id string) string {
		for _, s := range stmts {
			if strings.Contains(filepath.Base(s), id) {
				return s
			}
		}
		t.Fatalf("no statement file for %s", id)
		return ""
	}
	withheld := map[string]bool{pathOf(e2s): true, pathOf(src.ids["CX"]): true}
	var served, rest []string
	for _, s := range stmts {
		if withheld[s] {
			rest = append(rest, s)
		} else {
			served = append(served, s)
		}
	}
	rd := newWorld(t)
	pull := func(objs []string) {
		t.Helper()
		pkg := t.TempDir()
		writePackage(t, src.root, pkg, objs)
		if r := rd.run("pull", pkg); r.code != 0 {
			t.Fatalf("pull: exit %d\n%s", r.code, r.stdout)
		}
	}
	pull(append(append([]string{}, blobs...), served...))

	refs := []string{g, e1, e1s, x}
	check := func(current, status string, withheldIDs ...string) {
		t.Helper()
		rv := members(t, jsonOf(t, rd.run("show", g, "--json")), "resource_view")
		if rv.Members["current"] != canon.String(current) {
			t.Fatalf("show %s: current %s, want %s", g, canon.Encode(rv.Members["current"]), current)
		}
		st := string(canon.Encode(members(t, jsonOf(t, rd.run("show", x, "--json")), "corroboration").Members["summary"]))
		if !strings.Contains(st, status) || !strings.Contains(st, resolve.ScopeHeld) {
			t.Fatalf("show %s: corroboration %s, want %q within statements you hold", x, st, status)
		}
		for _, r := range refs {
			for _, cmd := range []string{"show", "verify", "explain"} {
				j := rd.run(cmd, r, "--json")
				if o := jsonOf(t, j); o.Members["status_scope"] != canon.String(resolve.ScopeHeld) {
					t.Errorf("%s %s: status_scope %v", cmd, r, o.Members["status_scope"])
				}
				h := rd.run(cmd, r)
				if !strings.HasSuffix(h.stdout, "status scope: "+resolve.ScopeHeld+"\n") {
					t.Errorf("%s %s: no scope footer\n%s", cmd, r, h.stdout)
				}
				for _, out := range []string{h.stdout, j.stdout} {
					if m := absenceClaim.FindString(out); m != "" {
						t.Errorf("%s %s claims %q:\n%s", cmd, r, m, out)
					}
					for _, id := range withheldIDs {
						if strings.Contains(out, id) || strings.Contains(out, id[:16]) {
							t.Errorf("%s %s names the withheld %s:\n%s", cmd, r, id[:16], out)
						}
					}
				}
			}
		}
	}
	check(e1, "corroborated 2", e2s, e2, src.ids["CX"])
	if s := string(canon.Encode(members(t, jsonOf(t, rd.run("show", x, "--json")), "corroboration").Members["summary"])); strings.Contains(s, "contradicted") {
		t.Fatalf("a contradiction the reader never received is counted: %s", s)
	}
	// delivering the rest moves the answers the expected way, still scoped
	pull(rest)
	check(e2, "contradicted 1")
}
