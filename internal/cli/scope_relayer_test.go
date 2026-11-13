package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/resolve"
)

// TestRelayerOmissionIsScoped: C-core-01 through `pull`. The source holds an observation X, three corroborations
// (S1, S2, S3) and the observer's retraction of X. A relayer serves the history minus the retraction and S3, and
// a reader pulls that: every surface that prints X's status (list, show of the blob, show/verify/explain of the
// statement) prints `corroborated 2 … within statements you hold`, never an unscoped count; X does not read
// `retracted`, no surface says an omitted statement does not exist or claims completeness, and the omitted
// statements are absent from `explain`'s inputs, not reported as missing. A control pull of the rest then moves
// the answer in the expected direction (3 corroborations, X retracted), still scoped.
func TestRelayerOmissionIsScoped(t *testing.T) {
	conformance.Covers(t, "C-core-01")
	src := newWorld(t)
	src.blob("x", []byte("x"))
	ref := obj("chain_id", "bip122:000000000019d6689c085ae165831e93", "block_hash", strings.Repeat("a1", 32), "depth", 3)
	x := src.sign("X", "K5", "observed", obj("content", canon.Value(content("x")), "class", "exact-bytes", "referent", canon.Value(ref),
		"capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted"))))
	src.authored("R", "K1", "x")
	for _, n := range []string{"S1", "S2", "S3"} {
		src.sign(n, "K"+n[1:]+"0", "corroborates", obj("of", x, "result", strings.Repeat("ab", 32), "verdict", "supports", "model", "M",
			"cohort", canon.Value(obj("rule", "every station in R"))))
	}
	src.sign("RT", "K5", "retracts", obj("of", x))

	blobs, stmts := dataObjects(t, src.root)
	pathOf := func(name string) string {
		for _, s := range stmts {
			if strings.Contains(filepath.Base(s), src.ids[name]) {
				return s
			}
		}
		t.Fatalf("no statement file for %s", name)
		return ""
	}
	omitted := map[string]bool{pathOf("RT"): true, pathOf("S3"): true}
	var served, rest []string
	for _, s := range stmts {
		if omitted[s] {
			rest = append(rest, s)
		} else {
			served = append(served, s)
		}
	}
	pull := func(dst *world, objs []string) {
		t.Helper()
		pkg := t.TempDir()
		writePackage(t, src.root, pkg, objs)
		if r := dst.run("pull", pkg); r.code != 0 {
			t.Fatalf("pull: exit %d\n%s", r.code, r.stdout)
		}
	}
	rd := newWorld(t)
	pull(rd, append(append([]string{}, blobs...), served...))

	statusOf := func(o *canon.Object) string { return string(canon.Encode(o.Members["summary"])) }
	check := func(rd *world, want string, label bool) {
		t.Helper()
		var seen []string
		for _, b := range jsonOf(t, rd.run("list", "--json")).Members["blobs"].(canon.Array) {
			if bo := b.(*canon.Object); bo.Members["digest"] == canon.String(dig("x")) {
				seen = append(seen, statusOf(firstObservation(t, bo, x)))
			}
		}
		for _, cmd := range []string{"show", "verify", "explain"} {
			seen = append(seen, statusOf(firstObservation(t, jsonOf(t, rd.run(cmd, dig("x"), "--json")), x)))
			seen = append(seen, statusOf(members(t, jsonOf(t, rd.run(cmd, x, "--json")), "corroboration")))
		}
		if len(seen) != 7 {
			t.Fatalf("%d surfaces printed the status, want 7", len(seen))
		}
		for _, s := range seen {
			if !strings.Contains(s, want) || !strings.Contains(s, resolve.ScopeHeld) {
				t.Fatalf("status %s, want %q within statements you hold", s, want)
			}
		}
		for _, cmd := range []string{"show", "verify", "explain"} {
			for _, ref := range []string{dig("x"), x} {
				for _, out := range []string{rd.run(cmd, ref).stdout, rd.run(cmd, ref, "--json").stdout} {
					l := strings.ToLower(out)
					for _, bad := range []string{"no other", "all corroborations", "none exist", "does not exist", "nonexistent", "not found", "complete", "missing"} {
						if strings.Contains(l, bad) {
							t.Fatalf("%s %s claims %q:\n%s", cmd, ref, bad, out)
						}
					}
					// the statement's own views carry the `retracted` label once the retraction is held
					// (the blob's view prints the observation's status, not its label); never before
					if retracted := strings.Contains(l, "retracted"); retracted && !label || !retracted && label && cmd == "show" && ref == x {
						t.Fatalf("%s %s: retracted=%v, want %v:\n%s", cmd, ref, retracted, label, out)
					}
				}
			}
		}
	}
	check(rd, "corroborated 2", false)
	// the omitted statements are absent from explain, not listed as missing
	ex := jsonOf(t, rd.run("explain", x, "--json"))
	for _, s := range ex.Members["statements"].(canon.Array) {
		if id := string(s.(*canon.Object).Members["statement"].(canon.String)); id == src.ids["RT"] || id == src.ids["S3"] {
			t.Fatalf("explain lists the omitted %s", id)
		}
	}
	// delivering them moves the answer the expected way, still scoped
	pull(rd, rest)
	check(rd, "corroborated 3", true)
}
