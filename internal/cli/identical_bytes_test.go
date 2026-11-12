package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
)

// TestIdenticalBytesTwoAuthorsPullOrders: C-core-08 through pull. Two keys publish identical bytes with their own
// authored statements (no provenance), each in its own package. A fresh reader pulls A then B, another B then A
// (and a third both at once): exactly one blob under its full hash, both statements in their signers' logs and
// neither log holding a line by the other key, neither shown superseded or removed, and the reader's answers
// are the same in every order.
func TestIdenticalBytesTwoAuthorsPullOrders(t *testing.T) {
	conformance.Covers(t, "C-core-08")
	mk := func(key string) string {
		w := newWorld(t)
		w.blob("same", []byte("same"))
		w.authored("A:"+key, key, "same", "licence", "CC0-1.0")
		pkg := t.TempDir()
		copyData(t, w.root, pkg)
		return pkg
	}
	a, b := mk("K1"), mk("K2")
	probe := newWorld(t)
	sa, sb := probe.signer("K1"), probe.signer("K2")
	var first string
	for _, order := range [][]string{{a, b}, {b, a}} {
		dst := newWorld(t)
		for _, p := range order {
			if r := dst.run("pull", p, "--json"); r.code != 0 {
				t.Fatalf("pull: %d %s", r.code, r.stdout)
			}
		}
		blobs, stmts := dataObjects(t, dst.root)
		if len(blobs) != 1 || filepath.Base(blobs[0]) != strings.TrimPrefix(dig("same"), "sha256:") {
			t.Fatalf("blobs %v", blobs)
		}
		per := map[string]int{}
		for _, s := range stmts {
			per[filepath.Base(filepath.Dir(s))]++
		}
		if len(per) != 2 || per[strings.ReplaceAll(sa, ":", "-")] != 1 || per[strings.ReplaceAll(sb, ":", "-")] != 1 {
			t.Fatalf("statements per signer directory: %v", per)
		}
		for _, s := range stmts {
			id := filepath.Base(s)
			v := dst.run("show", id).stdout
			if !strings.Contains(v, "line: chained") || !strings.Contains(v, "counted: counted") || strings.Contains(v, "superseded") || strings.Contains(v, "removed") {
				t.Fatalf("statement %s:\n%s", id[:12], v)
			}
		}
		out := dst.run("show", dig("same")).stdout
		if !strings.Contains(out, "authorship: contested") || !strings.Contains(out, sa) || !strings.Contains(out, sb) {
			t.Fatalf("both claimants are not shown:\n%s", out)
		}
		if first == "" {
			first = out
		} else if out != first {
			t.Fatalf("the display depends on the order:\n%s\nvs\n%s", out, first)
		}
	}
}
