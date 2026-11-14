package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/wire"
)

// TestIdentitySimplePathDrill is the simple-path custody drill (identity profile §8, "Simple-path drill, recorded"),
// run through the command line only, both algorithms, over three separate stores standing for three machines:
//
//  1. root machine: key new (R), identity new: I is R's seq-0 inception;
//  2. worker machine: key new (K), its first line (a bare-key publish) is D, K's seq 0;
//  3. root: pull D, identity grant I -> (K, D); worker: pull the grant;
//  4. worker: two acts for I under G (publish --as I --grant G); a third reader store pulls both: each `eligible`,
//     `counted`, and verify names I as the sole author;
//  5. steal: a second copy of K's key file (another machine) publishes as I under G, forking K's log;
//  6. root: identity cut G with --last-good = the last legitimate act L, reason key_compromise;
//  7. reader: pulls everything: the legitimate acts up to L still count; the thief's act counts toward nothing
//     (denied, cut_excluded);
//  8. abort: a signing step that cannot complete (a cut without --last-good, a stale --prev, a grant from a store
//     missing the identity, a refused act) leaves every store byte-identical, and restoring R's key file from a
//     backup copy signs as the same root (a later grant by the restored copy is valid and eligible).
//
// What it does not exercise: hardware signers, a compromised operational host. The external-signing package is
// TestExternalSigningEndToEnd and TestExternalSigningAborts.
func TestIdentitySimplePathDrill(t *testing.T) {
	conformance.Partial(t, "C-id-40", "the simple path (§8, rc-key/0 files, the CLI signs) is drilled through the commands on three stores: inception, grant, acts counted, a stolen worker key cut at last_good, aborts leave nothing appended, a root key file restored from backup signs as the same root; a compromised operational host and hardware or connector signing are not drilled")
	conformance.Partial(t, "C-id-18", "through the commands: a root key file restored from backup on a new machine signs a valid grant for the same identity and the act under it is eligible; the evaluator half (lost key, evidence unchanged) is TestCaseRootKeyLossChangesNothing")
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			// 1-3
			root, worker, ident, d, grant := idSetup(t, alg, `[{"kind":"authored","targets":{"any_content":true},"amend":false}]`)
			_ = d
			// 4
			a1 := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("a1", "legit one"), "--licence", "CC0-1.0", "--as", ident, "--grant", grant))
			a2 := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("a2", "legit two"), "--licence", "CC0-1.0", "--as", ident, "--grant", grant))
			reader := newIDHome(t, alg)
			reader.pullFrom(worker)
			for _, id := range []string{a1, a2} {
				sh := jsonOf(t, reader.read("show", id))
				if member(sh, "actor", "state") != canon.String("eligible") || sh.Members["counted"] != canon.String("counted") {
					t.Fatalf("legit act %s: %s", id[:12], canon.Encode(sh))
				}
			}
			dg := string(member(jsonOf(t, reader.read("show", a1)), "body", "content", "digest").(canon.String))
			if r := reader.read("verify", dg); r.code != ExitOK || member(jsonOf(t, r), "authorship") != canon.String("sole author") {
				t.Fatalf("verify legit: %d %s", r.code, r.stdout)
			}
			// 5: the thief holds a copy of K's file on another machine whose store holds the history up to a1
			thief := &idHome{t: t, store: drillStore(t), key: worker.file("stolen.key", ""), signer: worker.signer}
			b, _ := os.ReadFile(worker.key)
			os.WriteFile(thief.key, b, 0o600)
			os.Chmod(thief.key, 0o600)
			thief.pullFrom(worker)
			stolen := firstID(t, thief.ok("publish", "--kind", "authored", "--content", thief.file("s", "stolen"), "--licence", "CC0-1.0",
				"--as", ident, "--grant", grant, "--prev", a1))
			// 6: the root, told of the theft, cuts G keeping the legitimate history through a2
			root.pullFrom(worker)
			before := storeBytes(t, root.store)
			if r := root.run("identity", "cut", "--identity", ident, "--grant", grant, "--reason", "key_compromise"); r.code != ExitDidNotStart {
				t.Fatalf("cut without --last-good: %d %s", r.code, r.stdout)
			}
			if storeBytes(t, root.store) != before {
				t.Fatal("an aborted cut wrote")
			}
			cut := root.ok("identity", "cut", "--identity", ident, "--grant", grant, "--last-good", a2, "--reason", "key_compromise")
			for _, a := range cut.Members["acts"].(canon.Array) {
				if a.(*canon.Object).Members["state"] != canon.String("eligible") {
					t.Fatalf("a legitimate act stops counting at the cut: %s", canon.Encode(cut))
				}
			}
			// 7
			reader.pullFrom(thief)
			reader.pullFrom(root)
			for _, id := range []string{a1, a2} {
				if sh := jsonOf(t, reader.read("show", id)); member(sh, "actor", "state") != canon.String("eligible") || sh.Members["counted"] != canon.String("counted") {
					t.Fatalf("legit act %s after the cut: %s", id[:12], canon.Encode(sh))
				}
			}
			sh := jsonOf(t, reader.read("show", stolen))
			if member(sh, "actor", "state") != canon.String("denied") || sh.Members["counted"] != canon.String("not counted") ||
				!strings.Contains(string(canon.Encode(member(sh, "actor", "reasons"))), "cut_excluded") {
				t.Fatalf("stolen act: %s", canon.Encode(sh))
			}
			// 8: aborts leave nothing appended
			thief.pullFrom(root)
			for _, h := range []*idHome{root, worker, thief} {
				before := storeBytes(t, h.store)
				var r result
				switch h {
				case root:
					r = h.run("identity", "grant", "--identity", ident, "--delegate", worker.signer, "--delegate-inception", d, "--permissions", "[]")
				case worker:
					r = h.run("publish", "--kind", "authored", "--content", h.file("x", "x"), "--as", ident, "--grant", grant, "--prev", strings.Repeat("0", 64))
				case thief:
					r = h.run("publish", "--kind", "authored", "--content", h.file("y", "y"), "--as", ident, "--grant", grant, "--prev", stolen)
				}
				if r.code == ExitOK {
					t.Fatalf("an abort step succeeded: %s", r.stdout)
				}
				if storeBytes(t, h.store) != before {
					t.Fatalf("an aborted step wrote: %s", r.stdout)
				}
			}
			// root key restored from backup on a new machine: the same root
			restored := &idHome{t: t, store: drillStore(t), key: root.file("restored.key", ""), signer: root.signer}
			rb, _ := os.ReadFile(root.key)
			os.WriteFile(restored.key, rb, 0o600)
			os.Chmod(restored.key, 0o600)
			restored.pullFrom(root)
			w2 := newIDHome(t, alg)
			d2 := firstID(t, w2.ok("publish", "--kind", "authored", "--content", w2.file("f", "new worker"), "--licence", "CC0-1.0"))
			restored.pullFrom(w2)
			g2 := string(restored.ok("identity", "grant", "--identity", ident, "--delegate", w2.signer, "--delegate-inception", d2,
				"--permissions", `[{"kind":"authored","targets":{"any_content":true},"amend":false}]`).Members["grant"].(canon.String))
			w2.pullFrom(restored)
			o := w2.ok("publish", "--kind", "authored", "--content", w2.file("g", "after restore"), "--licence", "CC0-1.0", "--as", ident, "--grant", g2)
			if member(o, "actor", "state") != canon.String("eligible") {
				t.Fatalf("act under the restored root's grant: %s", canon.Encode(o))
			}
		})
	}
}
