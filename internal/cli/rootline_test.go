package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/wire"
)

// TestRootOrdinaryLineRefused: issue #271. An identity's root key signing a statement outside the closed root
// vocabulary stops the identity (unsupported_root_event), so every writer path refuses it: exit 1, nothing written,
// the message names the identity. describes stays allowed; a key that is not a root (no inception held) is
// unaffected. With the guard off the same line lands and the identity's delegate's next act is refused, which shows
// the refusal is what keeps the identity working (the mutation reaches the boundary).
func TestRootOrdinaryLineRefused(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			root, worker := newIDHome(t, alg), newIDHome(t, alg)
			ident := string(root.ok("identity", "new").Members["identity"].(canon.String))
			d := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("c0", "worker first line"), "--licence", "CC0-1.0"))
			root.pullFrom(worker)
			grant := string(root.ok("identity", "grant", "--identity", ident, "--delegate", worker.signer, "--delegate-inception", d,
				"--permissions", anyContentPerm).Members["grant"].(canon.String))
			genesis := root.file("gen.json", `{"kind":"genesis","body":{"type":"collection","name":"t","controllers":[{"identity":"`+ident+`"}],"rule":{"any_one":true}}}`)
			for _, bad := range []struct {
				name string
				args []string
			}{
				{"authored", []string{"publish", "--kind", "authored", "--content", root.file("y", "root bytes"), "--licence", "CC0-1.0"}},
				{"authored --no-holds", []string{"publish", "--kind", "authored", "--content", root.file("y2", "root bytes 2"), "--licence", "CC0-1.0", "--no-holds"}},
				{"holds", []string{"publish", "--kind", "holds", "--content", root.file("h", "held bytes")}},
				{"genesis", []string{"publish", "--draft", genesis}},
				{"retracts", []string{"publish", "--kind", "retracts", "--of", d}},
				{"authored --dry-run", []string{"publish", "--kind", "authored", "--content", root.file("y3", "root bytes 3"), "--licence", "CC0-1.0", "--dry-run"}},
			} {
				before := storeBytes(t, root.store)
				r := root.run(bad.args...)
				if r.code != ExitWrong || !strings.Contains(r.stdout, "root-ordinary-line") || !strings.Contains(r.stdout, ident) ||
					!strings.Contains(r.stdout, "stops the identity's delegates' acts from counting") {
					t.Fatalf("%s by the root: %d %s%s", bad.name, r.code, r.stdout, r.stderr)
				}
				if storeBytes(t, root.store) != before {
					t.Fatalf("%s: a refused line wrote", bad.name)
				}
			}
			// describes is inert on the root's lineage: allowed, and the delegate still acts
			root.ok("publish", "--kind", "describes", "--about", ident, "--note", "the root's own note")
			worker.pullFrom(root)
			worker.ok("publish", "--kind", "authored", "--content", worker.file("c1", "act one"), "--licence", "CC0-1.0", "--as", ident, "--grant", grant)
			// a key that is no identity's root is unaffected, in a store that holds identities
			worker.ok("publish", "--kind", "holds", "--content", worker.file("c2", "worker holds"))
			// a store that does not hold the inception cannot know: the root's line is not refused there
			bare := newIDHome(t, alg)
			bare.key = root.key
			bare.ok("publish", "--kind", "authored", "--content", bare.file("c3", "elsewhere"), "--licence", "CC0-1.0")

			// a sound identity: show names no ordinary root line (describes is in the vocabulary)
			for _, ref := range []string{ident, root.signer} {
				if r := root.read("show", ref); r.code != ExitOK || strings.Contains(r.stdout, "ordinary_root_lines") {
					t.Fatalf("show %s on a sound identity: %d %s", ref, r.code, r.stdout)
				}
			}

			// mutation: with the guard off, the line lands and the delegate's next act no longer counts
			rootLineGuard = false
			defer func() { rootLineGuard = true }()
			bad := firstID(t, root.ok("publish", "--kind", "authored", "--content", root.file("y4", "root bytes 4"), "--licence", "CC0-1.0"))
			rootLineGuard = true
			// the reader's pointer: show <identity> and show <root key> name the line (and its holds)
			for _, ref := range []string{ident, root.signer} {
				r := root.read("show", ref)
				if r.code != ExitOK || !strings.Contains(r.stdout, "ordinary_root_lines") || !strings.Contains(r.stdout, bad) {
					t.Fatalf("show %s does not name the root's ordinary line %s: %d %s", ref, bad, r.code, r.stdout)
				}
				h := runIn(root.store, nil, "show", ref)
				if !strings.Contains(h.stdout, bad) || !strings.Contains(h.stdout, "outside the closed root vocabulary") {
					t.Fatalf("human show %s: %s", ref, h.stdout)
				}
			}
			// gc --release signs a holds (withdrawn) with the root: refused too, nothing signed or deleted
			before := storeBytes(t, root.store)
			lines, _ := mustStore(t, root.store).Statements()
			var digest string
			for _, l := range lines {
				if st, err := wire.ReadStored(l); err == nil && st.Signer == root.signer && st.Kind == "holds" {
					digest = contentOf(st)
				}
			}
			if r := root.run("gc", "--release", digest); r.code != ExitWrong || !strings.Contains(r.stdout, "root-ordinary-line") {
				t.Fatalf("gc --release by the root: %d %s", r.code, r.stdout)
			}
			if storeBytes(t, root.store) != before {
				t.Fatal("a refused release wrote")
			}
			worker.pullFrom(root)
			if r := worker.run("publish", "--kind", "authored", "--content", worker.file("c4", "act two"), "--licence", "CC0-1.0",
				"--as", ident, "--grant", grant); r.code != ExitCouldNot || !strings.Contains(r.stdout, "unsupported_root_event") {
				t.Fatalf("the delegate's act after the root's ordinary line: %d %s", r.code, r.stdout)
			}
		})
	}
}

// TestRootVocabularyWriterMatchesReader: the writer's allowed set is the reader's: every kind the writer can sign,
// read as the root's line, is allowed exactly when identitymodel's root walk does not read it unsupported_root_event.
// Both go through identity.InRootVocabulary, so this pins the list against the note's text.
func TestRootVocabularyWriterMatchesReader(t *testing.T) {
	allowed := map[string]bool{"identity_grant": true, "identity_cut": true, "describes": true, "anchors": true,
		"rotate_key": true, "revoke_key": true}
	for _, kind := range []string{"authored", "observed", "holds", "describes", "reproduced", "corroborates", "refutes", "retracts",
		"anchors", "genesis", "edition", "intent", "withdraw", "progress", "submit", "decide", "grant", "withdraw_approval",
		"rotate_key", "revoke_key", "task", "identity_grant", "identity_cut", "identity_inception"} {
		rc := "rc/1"
		if strings.HasPrefix(kind, "identity_") {
			rc = "rc/2"
		}
		st := &wire.Statement{RC: rc, Kind: kind, Status: wire.Valid, Verified: true}
		if got := identity.InRootVocabulary(st); got != allowed[kind] {
			t.Errorf("%s: in the root vocabulary = %v, the note says %v", kind, got, allowed[kind])
		}
	}
	if identity.InRootVocabulary(&wire.Statement{RC: "rc/1", Kind: "describes", Status: wire.Invalid, Verified: true}) {
		t.Error("an invalid describes is in the root vocabulary")
	}
}
