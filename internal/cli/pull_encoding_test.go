package cli

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/sig"
	"github.com/research-common/research-commons/internal/wire"
)

// TestPullEquivalentEncodingsOneStatement: C-core-10 (and C-core-02a's second pair). One EIP-191 statement is
// delivered by `pull` in its stored (canonical) form and, in a second package, with each other valid encoding of
// the same signature (v as 0/1, high s, both). Every encoding verifies to one statement id; a package carrying a
// non-canonical encoding is refused `not canonical` (intrinsic) naming that id and installs nothing, before or
// after the canonical delivery; the reader's log holds one line for the statement, and every read surface answers
// exactly as a reader that received the canonical form once.
func TestPullEquivalentEncodingsOneStatement(t *testing.T) {
	conformance.Covers(t, "C-core-10")
	conformance.Partial(t, "C-core-02a", "second pair through pull: one id, the stored form only; the first pair's display is elsewhere")
	src := newWorld(t)
	src.blob("x", []byte("x"))
	id := src.authored("A:x", "K2", "x", "licence", "CC0-1.0") // even-length name: an EIP-191 key
	signer := src.signer("K2")
	if !strings.HasPrefix(signer, "0x") {
		t.Fatalf("fixture key %s is not EIP-191: the case needs a scheme with equivalent encodings", signer)
	}
	rel := stmtPath(signer, id)
	canonical := mustRead(t, filepath.Join(src.root, rel))

	st, err := wire.Read(canonical)
	if err != nil || st.ID != id {
		t.Fatalf("canonical line: %v", err)
	}
	raw, _ := hex.DecodeString(strings.TrimPrefix(st.Sig, "0x"))
	var others [][]byte
	for _, e := range sig.Equivalents(raw) {
		v, err := canon.Parse(canonical)
		if err != nil {
			t.Fatal(err)
		}
		o := v.(*canon.Object)
		o.Members["sig"] = canon.String("0x" + hex.EncodeToString(e))
		line := canon.Encode(o)
		// each other encoding verifies to the same id (the id does not cover sig) and differs in bytes
		got, err := wire.Read(line)
		if err != nil || got.ID != id || string(line) == string(canonical) || string(got.Line()) != string(canonical) {
			t.Fatalf("equivalent encoding: err %v, id %s", err, got.ID)
		}
		others = append(others, line)
	}
	if len(others) != 3 {
		t.Fatalf("%d equivalent encodings", len(others))
	}

	// pkgWith is a package carrying the statement file in the given bytes (no blob: the blob is the source's).
	pkgWith := func(line []byte) string {
		pkg := t.TempDir()
		os.WriteFile(filepath.Join(pkg, "rc-store"), mustRead(t, filepath.Join(src.root, "rc-store")), 0o644)
		p := filepath.Join(pkg, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, line, 0o644)
		return pkg
	}
	refs := []string{id, dig("x")}
	wantRefusedNotCanonical := func(dst *world, line []byte) {
		t.Helper()
		before := snapshot(t, dst.root)
		r := dst.run("pull", pkgWith(line), "--json")
		row := refusedRow(t, r)
		detail, _ := row.Members["detail"].(canon.String)
		if r.code != 1 || row.Members["class"] != canon.String("intrinsic") || row.Members["reason"] != canon.String("not canonical") ||
			!strings.Contains(string(detail), "canonical sig") {
			t.Fatalf("exit %d: %s", r.code, canon.Encode(row))
		}
		if !strings.Contains(r.stdout, id) {
			t.Fatalf("the refusal does not name the statement id %s: %s", id, r.stdout)
		}
		if snapshot(t, dst.root) != before {
			t.Fatal("a refused encoding changed the reader's store")
		}
	}
	held := func(dst *world) int {
		t.Helper()
		ents, _ := os.ReadDir(filepath.Join(dst.root, filepath.Dir(rel)))
		n := 0
		for _, e := range ents {
			if e.Name() == id {
				n++
				if b := mustRead(t, filepath.Join(dst.root, rel)); string(b) != string(canonical) {
					t.Fatal("the stored line is not the canonical form")
				}
			}
		}
		return n
	}

	// reference: a reader that received the canonical form once
	ref := newWorld(t)
	if r := ref.run("pull", src.root, "--json"); r.code != 0 {
		t.Fatalf("reference pull: exit %d: %s", r.code, r.stdout)
	}
	want := viewDigest(surfaces(t, ref.root, refs))
	if held(ref) != 1 {
		t.Fatal("reference holds no line")
	}

	// canonical first, then each other encoding: refused, one line, the reference's answers
	first := newWorld(t)
	if r := first.run("pull", src.root, "--json"); r.code != 0 {
		t.Fatalf("pull: exit %d: %s", r.code, r.stdout)
	}
	for _, l := range others {
		wantRefusedNotCanonical(first, l)
	}
	if held(first) != 1 || viewDigest(surfaces(t, first.root, refs)) != want {
		t.Fatal("canonical first: the reader's answers differ from one canonical delivery")
	}
	// the canonical form again is a no-op labelled already held
	if r := first.run("pull", pkgWith(canonical), "--json"); r.code != 0 || !strings.Contains(r.stdout, "already held") {
		t.Fatalf("second canonical delivery: exit %d: %s", r.code, r.stdout)
	}
	if held(first) != 1 || viewDigest(surfaces(t, first.root, refs)) != want {
		t.Fatal("a second canonical delivery changed an answer")
	}

	// the other order: each non-canonical encoding first (refused, nothing held), then the canonical form
	second := newWorld(t)
	for _, l := range others {
		wantRefusedNotCanonical(second, l)
	}
	if held(second) != 0 {
		t.Fatal("a refused encoding was installed")
	}
	if r := second.run("pull", src.root, "--json"); r.code != 0 {
		t.Fatalf("pull: exit %d: %s", r.code, r.stdout)
	}
	if held(second) != 1 || viewDigest(surfaces(t, second.root, refs)) != want {
		t.Fatal("non-canonical first: the reader's answers differ from one canonical delivery")
	}
}
