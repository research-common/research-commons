package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/store"
)

// aliasCollision is a pair of blobs whose sha256 digests share their first 12 hex characters (48 bits), the
// display-alias length (wire-format note §3). It was found by Pollard's rho over the blob text (the walk
// aliasWalk below): a birthday search needs about 2^24 hashes, about half a minute on one core, so the pair is
// pinned here and the search itself runs only under RC_ALIAS_BRUTEFORCE=1 (TestAliasBruteForce). The test
// re-hashes both blobs, so a wrong pin fails rather than proving nothing.
var aliasCollision = [2]string{
	"research-commons alias collision 40af3312e42d\n",
	"research-commons alias collision 43dd5cae2797\n",
}

const aliasPrefix = "6c68d0ad8f3e"

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TestAmbiguousAlias: C-core-03. Two held blobs whose full hashes share the display alias: a lookup by the
// shared alias is an error listing both full hashes and selecting nothing, on every command that takes a ref;
// a lookup by either full hash succeeds; an alias matching exactly one held object is accepted and answers
// exactly as its full hash does; an alias matching nothing is `not found`. The control (a unique alias) shows
// the lookup reaches the store, so the ambiguity error is the alias rule's and not a shape refusal.
func TestAmbiguousAlias(t *testing.T) {
	conformance.Covers(t, "C-core-03")
	a, b := sha(aliasCollision[0]), sha(aliasCollision[1])
	if a == b || a[:store.AliasLen] != aliasPrefix || b[:store.AliasLen] != aliasPrefix {
		t.Fatalf("the pinned pair does not collide on the alias: %s %s", a, b)
	}
	w := newWorld(t)
	da := w.blob("a", []byte(aliasCollision[0]))
	db := w.blob("b", []byte(aliasCollision[1]))
	w.sign("A:a", "K1", "authored", obj("content", canon.Value(obj("digest", da, "size", len(aliasCollision[0]))), "type", "dataset"))
	w.sign("A:b", "K2", "authored", obj("content", canon.Value(obj("digest", db, "size", len(aliasCollision[1]))), "type", "dataset"))
	sole := w.blob("sole", []byte("sole"))
	w.authored("A:sole", "K1", "sole")
	stmt := w.ids["A:sole"]

	// shared prefix: an error naming both candidates, nothing selected, nothing written
	for _, cmd := range []string{"show", "verify", "explain"} {
		for _, alias := range []string{aliasPrefix, "sha256:" + aliasPrefix} {
			before := snapshot(t, w.root)
			r := w.run(cmd, alias, "--json")
			p := jsonOf(t, r)
			if r.code != ExitDidNotStart || p.Members["type"] != canon.String(ProblemTypeBase+"ambiguous-alias") {
				t.Fatalf("%s %s: exit %d\n%s", cmd, alias, r.code, r.stdout)
			}
			detail := string(p.Members["detail"].(canon.String))
			if !strings.Contains(detail, da) || !strings.Contains(detail, db) || strings.Contains(r.stdout, `"authorship"`) {
				t.Fatalf("%s %s: both candidates not listed, or something was selected\n%s", cmd, alias, r.stdout)
			}
			if p.Members["committed"] != canon.Bool(false) || snapshot(t, w.root) != before {
				t.Fatalf("%s %s: committed or root changed", cmd, alias)
			}
			// the human surface lists them too
			if h := w.run(cmd, alias); h.code != ExitDidNotStart || !strings.Contains(h.stderr, da) || !strings.Contains(h.stderr, db) {
				t.Fatalf("%s %s human: exit %d\n%s", cmd, alias, h.code, h.stderr)
			}
		}
	}

	// either full hash succeeds, and names its own blob
	for _, d := range []string{da, db} {
		r := w.run("show", d, "--json")
		if r.code != ExitOK || jsonOf(t, r).Members["digest"] != canon.String(d) {
			t.Fatalf("show %s: exit %d\n%s", d, r.code, r.stdout)
		}
		if r := w.run("verify", d, "--json"); r.code != ExitOK {
			t.Fatalf("verify %s: exit %d\n%s", d, r.code, r.stdout)
		}
	}

	// control: a unique alias (a blob, with and without the prefix, and a statement) answers exactly as the full
	// hash does, so the lookup reached the store and the error above is the ambiguity rule
	for full, aliases := range map[string][]string{sole: {sole[7:19], sole[:19]}, stmt: {stmt[:12]}} {
		want := w.run("show", full, "--json")
		for _, al := range aliases {
			if got := w.run("show", al, "--json"); got.code != want.code || got.stdout != want.stdout {
				t.Fatalf("alias %s does not answer as %s:\n%s\nvs\n%s", al, full, got.stdout, want.stdout)
			}
		}
	}
	// a statement alias with the sha256: prefix names blobs only, so it finds nothing
	if r := w.run("show", "sha256:"+stmt[:12], "--json"); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "alias-not-found") {
		t.Fatalf("sha256: + statement alias: exit %d\n%s", r.code, r.stdout)
	}
	// no match: not found, nothing selected
	none := "ffffffffffff"
	if c, _ := store.AliasCandidates(w.root, none); len(c) != 0 {
		t.Skip("fixture happens to hold an object under the not-found alias")
	}
	if r := w.run("verify", none, "--json"); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "alias-not-found") {
		t.Fatalf("no match: exit %d\n%s", r.code, r.stdout)
	}
	// verify --rerun takes a blob: an alias naming a statement is the same malformed --rerun as the full id
	if r := w.run("verify", stmt[:12], "--rerun", "--json"); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "malformed-argument") {
		t.Fatalf("--rerun on a statement alias: exit %d\n%s", r.code, r.stdout)
	}
	// other alias lengths are malformed, never a prefix lookup (a 13-character prefix is not an alias)
	for _, bad := range []string{aliasPrefix[:11], aliasPrefix + "0", strings.ToUpper(aliasPrefix)} {
		if r := w.run("show", bad, "--json"); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "malformed-argument") {
			t.Fatalf("%q: exit %d\n%s", bad, r.code, r.stdout)
		}
	}
}

// aliasWalk is the rho step: the blob text for x, hashed, truncated to the alias's 48 bits.
func aliasWalk(x uint64) uint64 {
	h := sha256.Sum256([]byte(fmt.Sprintf("research-commons alias collision %012x\n", x)))
	var v uint64
	for i := 0; i < store.AliasLen/2; i++ {
		v = v<<8 | uint64(h[i])
	}
	return v
}

// TestAliasBruteForce re-runs the search that found aliasCollision (Floyd cycle finding, then the meeting point)
// and checks it reaches the pinned pair. Opt-in: about 2^24 hashes, half a minute on one core.
func TestAliasBruteForce(t *testing.T) {
	if os.Getenv("RC_ALIAS_BRUTEFORCE") != "1" {
		t.Skip("set RC_ALIAS_BRUTEFORCE=1 to re-run the 48-bit collision search (about 2^24 hashes)")
	}
	f := aliasWalk
	for start := uint64(1); ; start++ {
		tort, hare := f(start), f(f(start))
		for tort != hare {
			tort, hare = f(tort), f(f(hare))
		}
		tort = start
		if tort == hare {
			continue
		}
		for f(tort) != f(hare) {
			tort, hare = f(tort), f(hare)
		}
		if tort == hare {
			continue
		}
		got := []string{fmt.Sprintf("research-commons alias collision %012x\n", tort), fmt.Sprintf("research-commons alias collision %012x\n", hare)}
		slices.Sort(got)
		if got[0] != aliasCollision[0] || got[1] != aliasCollision[1] {
			t.Fatalf("the search found another pair: %q", got)
		}
		return
	}
}
