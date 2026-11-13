package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// idSetup runs the simple path up to a grant: root identity, worker first line, grant; the worker store holds all.
func idSetup(t *testing.T, alg, perms string) (root, worker *idHome, ident, d, grant string) {
	t.Helper()
	root, worker = newIDHome(t, alg), newIDHome(t, alg)
	ident = string(root.ok("identity", "new").Members["identity"].(canon.String))
	d = firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("c0", "worker first line"), "--licence", "CC0-1.0"))
	root.pullFrom(worker)
	grant = string(root.ok("identity", "grant", "--identity", ident, "--delegate", worker.signer, "--delegate-inception", d, "--permissions", perms).Members["grant"].(canon.String))
	worker.pullFrom(root)
	return
}

// TestPublishAs: publish --as/--grant writes an rc/2 act carrying x_actor_v1 in the signed envelope, read back
// eligible for the identity; the holds beside it stays rc/1. Refusals: an act the held evidence denies (exit 2, why
// named), one it cannot decide (exit 3), a kind that takes no actor (exit 2), --as without --grant (exit 2); each
// leaves the store byte-identical.
func TestPublishAs(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			root, worker, ident, _, grant := idSetup(t, alg, `[{"kind":"authored","targets":{"any_content":true},"amend":true}]`)
			o := worker.ok("publish", "--kind", "authored", "--content", worker.file("c1", "act one"), "--licence", "CC0-1.0", "--as", ident, "--grant", grant)
			if member(o, "actor", "state") != canon.String("eligible") || member(o, "actor", "identity") != canon.String(ident) {
				t.Fatalf("act: %s", canon.Encode(o))
			}
			sts := o.Members["statements"].(canon.Array)
			act := string(sts[0].(*canon.Object).Members["statement"].(canon.String))
			holds := string(sts[1].(*canon.Object).Members["statement"].(canon.String))
			sh := jsonOf(t, worker.read("show", act))
			if member(sh, "actor", "state") != canon.String("eligible") || sh.Members["counted"] != canon.String("counted") {
				t.Fatalf("show act: %s", canon.Encode(sh))
			}
			lines, _ := mustStore(t, worker.store).Statements()
			if !strings.Contains(string(lines[act]), `"rc":"rc/2"`) || !strings.Contains(string(lines[act]), `"x_actor_v1":{"grant":"`+grant) {
				t.Fatalf("act line: %s", lines[act])
			}
			if !strings.Contains(string(lines[holds]), `"rc":"rc/1"`) {
				t.Fatalf("holds line: %s", lines[holds])
			}
			// amends: an act amending the identity's earlier claim
			o = worker.ok("publish", "--kind", "authored", "--content", worker.file("c2", "act two"), "--licence", "CC0-1.0", "--as", ident, "--grant", grant, "--amends", act)
			if member(o, "actor", "state") != canon.String("eligible") {
				t.Fatalf("amending act: %s", canon.Encode(o))
			}
			before := storeBytes(t, worker.store)
			for _, bad := range []struct {
				args []string
				code int
				slug string
			}{
				{[]string{"--kind", "authored", "--content", worker.file("c3", "x"), "--as", ident}, ExitDidNotStart, "missing-argument"},
				{[]string{"--kind", "describes", "--about", act, "--as", ident, "--grant", grant}, ExitDidNotStart, "malformed-argument"},
				{[]string{"--kind", "retracts", "--of", act, "--as", ident, "--grant", grant}, ExitDidNotStart, "act-not-eligible"},
				{[]string{"--kind", "authored", "--content", worker.file("c4", "y"), "--as", ident, "--grant", strings.Repeat("ab", 32)}, ExitCouldNot, "act-undecided"},
				{[]string{"--kind", "holds", "--content", worker.file("c5", "z"), "--amends", act}, ExitDidNotStart, "conflicting-options"},
			} {
				r := worker.run(append([]string{"publish"}, bad.args...)...)
				if r.code != bad.code || !strings.Contains(r.stdout, bad.slug) {
					t.Fatalf("%v: %d %s", bad.args, r.code, r.stdout)
				}
			}
			// the root cuts the grant (keep nothing): a new act is denied
			root.pullFrom(worker)
			cut := root.ok("identity", "cut", "--identity", ident, "--grant", grant, "--last-good", "none", "--reason", "superseded")
			if acts := cut.Members["acts"].(canon.Array); len(acts) != 2 {
				t.Fatalf("cut lists %d acts: %s", len(acts), canon.Encode(cut))
			}
			worker.pullFrom(root)
			before = storeBytes(t, worker.store)
			r := worker.run("publish", "--kind", "authored", "--content", worker.file("c6", "after cut"), "--as", ident, "--grant", grant)
			if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "act-not-eligible") || !strings.Contains(r.stdout, "cut_excluded") {
				t.Fatalf("act after cut: %d %s", r.code, r.stdout)
			}
			if storeBytes(t, worker.store) != before {
				t.Fatal("a refused act wrote")
			}
		})
	}
}

func mustStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	s, err := store.Open(dir, store.Options{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
