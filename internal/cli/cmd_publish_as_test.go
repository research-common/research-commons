package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
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
	conformance.Covers(t, "C-id-02") // written by the commands: identity new, identity grant, publish --as; eligible and counted on show
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

// TestPublishAsAmendsOtherKeyOwn: under one identity with two granted keys K1 and K2, both carrying amend "own"
// (profile §3, §5.1), K1 naming K2's claim in --amends is refused as an act that would not count (exit 2,
// act-not-eligible, scope_excluded), and the refused act leaves the store byte-identical. The positive controls show
// the refusal is the target's signer and not something else about the request: K1 amending its own claim under the
// same grant is eligible, and K1 amending K2's claim under an amend:true grant is eligible (identity-wide, §3).
func TestPublishAsAmendsOtherKeyOwn(t *testing.T) {
	const ownPerm = `[{"kind":"authored","targets":{"any_content":true},"amend":"own"}]`
	const widePerm = `[{"kind":"authored","targets":{"any_content":true},"amend":true}]`
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			root, k1, k2 := newIDHome(t, alg), newIDHome(t, alg), newIDHome(t, alg)
			ident := string(root.ok("identity", "new").Members["identity"].(canon.String))
			d1 := firstID(t, k1.ok("publish", "--kind", "authored", "--content", k1.file("c0", "k1 first line"), "--licence", "CC0-1.0"))
			d2 := firstID(t, k2.ok("publish", "--kind", "authored", "--content", k2.file("c0", "k2 first line"), "--licence", "CC0-1.0"))
			root.pullFrom(k1)
			root.pullFrom(k2)
			grant := func(k *idHome, d, perms string) string {
				return string(root.ok("identity", "grant", "--identity", ident, "--delegate", k.signer, "--delegate-inception", d, "--permissions", perms).Members["grant"].(canon.String))
			}
			g1, g2 := grant(k1, d1, ownPerm), grant(k2, d2, ownPerm)
			k1.pullFrom(root)
			k2.pullFrom(root)
			// K2 makes a claim of I; K1's store learns it (and K2's first line, which pins the grant)
			shared := k2.file("shared", "the claimed blob")
			k2act := firstID(t, k2.ok("publish", "--kind", "authored", "--content", shared, "--licence", "CC0-1.0", "--as", ident, "--grant", g2))
			k1.pullFrom(k2)
			before := storeBytes(t, k1.store)
			r := k1.run("publish", "--kind", "authored", "--content", shared, "--licence", "MIT", "--as", ident, "--grant", g1, "--amends", k2act)
			if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "act-not-eligible") || !strings.Contains(r.stdout, "scope_excluded") {
				t.Fatalf("K1 amending K2's claim under amend own: %d\n%s", r.code, r.stdout)
			}
			if storeBytes(t, k1.store) != before {
				t.Fatal("the refused amendment wrote to the store")
			}
			// control 1: the same request naming K1's own claim is eligible, so the refusal above is about the target's signer
			k1act := firstID(t, k1.ok("publish", "--kind", "authored", "--content", k1.file("mine", "k1 blob"), "--licence", "CC0-1.0", "--as", ident, "--grant", g1))
			o := k1.ok("publish", "--kind", "authored", "--content", k1.file("mine", "k1 blob"), "--licence", "MIT", "--as", ident, "--grant", g1, "--amends", k1act)
			if member(o, "actor", "state") != canon.String("eligible") {
				t.Fatalf("K1 amending its own claim under amend own: %s", canon.Encode(o))
			}
			// control 2: under amend:true the cross-key amendment is eligible
			g1wide := grant(k1, d1, widePerm)
			k1.pullFrom(root)
			o = k1.ok("publish", "--kind", "authored", "--content", shared, "--licence", "MIT", "--as", ident, "--grant", g1wide, "--amends", k2act)
			if member(o, "actor", "state") != canon.String("eligible") {
				t.Fatalf("K1 amending K2's claim under amend:true: %s", canon.Encode(o))
			}
		})
	}
}

// TestIdentityCutLastGoodBareKeyLine: --last-good accepts any held line of the grant's delegate key, a bare-key line
// (signed without --as) included: it marks a prefix of the key's log (profile §4). Here L is the delegate's first
// line: the act after it stops counting, and the cut is signed; a line of another key is still refused, nothing written.
func TestIdentityCutLastGoodBareKeyLine(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			root, worker, ident, d, grant := idSetup(t, alg, `[{"kind":"authored","targets":{"any_content":true},"amend":false}]`)
			act := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("a", "act"), "--licence", "CC0-1.0", "--as", ident, "--grant", grant))
			root.pullFrom(worker)
			cut := root.ok("identity", "cut", "--identity", ident, "--grant", grant, "--last-good", d, "--reason", "superseded")
			acts := cut.Members["acts"].(canon.Array)
			if len(acts) != 1 || acts[0].(*canon.Object).Members["state"] == canon.String("eligible") {
				t.Fatalf("an act after a bare-key last_good keeps counting: %s", canon.Encode(cut))
			}
			reader := newIDHome(t, alg)
			reader.pullFrom(worker)
			reader.pullFrom(root)
			if sh := jsonOf(t, reader.read("show", act)); member(sh, "actor", "state") != canon.String("denied") {
				t.Fatalf("act after the cut: %s", canon.Encode(sh))
			}
		})
	}
}

// TestPublishAsReclaimIsNotARerun: one key's bare `authored` of a derived output (carrying an environment record)
// plus its own identity-context `authored` of the same bytes and provenance is one run, not two: `verify` reads
// `not re-derived` and exits 3, not T0 / exit 0 (I4). Control: the identity claim made by a DIFFERENT key is a
// second run, T0, exit 0. Through the commands: identity new, identity grant, publish, publish --as.
func TestPublishAsReclaimIsNotARerun(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			setup := func() (*idHome, *idHome, string, string, string, string) {
				root, worker, ident, _, grant := idSetup(t, alg, `[{"kind":"authored","targets":{"any_content":true},"amend":"own"}]`)
				wf := worker.file("wf.json", `{"step":"sum"}`)
				in := worker.file("in.csv", "a,1\n")
				worker.ok("publish", "--kind", "authored", "--type", "workflow", "--content", wf, "--licence", "CC0-1.0", "--replication", "bytes")
				worker.ok("publish", "--kind", "authored", "--content", in, "--licence", "CC0-1.0")
				wfd := fileDigest(t, wf)
				ind := fileDigest(t, in)
				return root, worker, ident, grant, wfd, ind
			}
			root, worker, ident, grant, wfd, ind := setup()
			out := worker.file("out.csv", "a,1\n# derived\n")
			withEnv := `{"workflow":"` + wfd + `","inputs":["` + ind + `"],"environment":{"image_digest":"sha256:` + strings.Repeat("d9", 32) + `","platform":"linux/amd64"}}`
			bare := `{"workflow":"` + wfd + `","inputs":["` + ind + `"]}`
			worker.ok("publish", "--kind", "authored", "--content", out, "--licence", "CC0-1.0", "--provenance", withEnv)
			od := fileDigest(t, out)
			if r := worker.read("verify", od); r.code != ExitCouldNot || !strings.Contains(r.stdout, "not re-derived") {
				t.Fatalf("one bare run: %d %s", r.code, r.stdout)
			}
			worker.ok("publish", "--kind", "authored", "--content", out, "--licence", "CC0-1.0", "--provenance", bare, "--as", ident, "--grant", grant)
			r := worker.read("verify", od)
			if r.code != ExitCouldNot || !strings.Contains(r.stdout, "not re-derived") || strings.Contains(r.stdout, `"T0"`) {
				t.Fatalf("one key bare + for its identity read as a re-derivation: %d %s", r.code, r.stdout)
			}
			if r := worker.read("explain", od); !strings.Contains(r.stdout, "not counted as a further run") {
				t.Fatalf("explain does not say why: %s", r.stdout)
			}
			_ = root

			// control: a different key (a second delegate of the identity) makes the identity claim: two runs, T0
			root, worker, ident, _, wfd, ind = setup()
			other := newIDHome(t, alg)
			other.pullFrom(worker)
			d2 := firstID(t, other.ok("publish", "--kind", "authored", "--content", other.file("o0", "other first line"), "--licence", "CC0-1.0"))
			root.pullFrom(other)
			g2 := string(root.ok("identity", "grant", "--identity", ident, "--delegate", other.signer, "--delegate-inception", d2, "--permissions", `[{"kind":"authored","targets":{"any_content":true},"amend":"own"}]`).Members["grant"].(canon.String))
			other.pullFrom(root)
			out = worker.file("out.csv", "a,1\n# derived\n")
			withEnv = `{"workflow":"` + wfd + `","inputs":["` + ind + `"],"environment":{"image_digest":"sha256:` + strings.Repeat("d9", 32) + `","platform":"linux/amd64"}}`
			bare = `{"workflow":"` + wfd + `","inputs":["` + ind + `"]}`
			worker.ok("publish", "--kind", "authored", "--content", out, "--licence", "CC0-1.0", "--provenance", withEnv)
			other.pullFrom(worker)
			other.ok("publish", "--kind", "authored", "--content", other.file("out.csv", "a,1\n# derived\n"), "--licence", "CC0-1.0", "--provenance", bare, "--as", ident, "--grant", g2)
			if r := other.read("verify", od); r.code != ExitOK || !strings.Contains(r.stdout, `"T0"`) {
				t.Fatalf("two keys (one bare, one for I): %d %s", r.code, r.stdout)
			}
		})
	}
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
