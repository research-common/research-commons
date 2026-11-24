package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/wire"
)

// TestCutKeyCannotHoldResource: C-id-30 through the commands, on five stores. A collection is controlled by one
// identity; delegates A and B each hold an edition grant. A's grant is cut. Whoever still holds A's key file then
// signs another edition from a store that never took the cut, and a reader receives it.
//
// The reader's answer does not move: the edition is unauthorized, nothing is contested, current stays where the
// controllers put it and verify exits 0. The view names the edition and the cut (`cut_excluded`). A store that
// receives the cut after the edition labels the cut's row on pull (`cut: editions not counted`), and the writer
// warns when an edition names a predecessor that is not an authorized edition. Before this rule the reader showed
// the edition `contested` and verify exited 3 for as long as the line was held (issue #285).
func TestCutKeyCannotHoldResource(t *testing.T) {
	conformance.Covers(t, "C-id-30")
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			root, a, b, reader := newIDHome(t, alg), newIDHome(t, alg), newIDHome(t, alg), newIDHome(t, alg)
			ident := string(root.ok("identity", "new").Members["identity"].(canon.String))
			a.pullFrom(root)
			gid := firstID(t, a.ok("publish", "--draft", a.file("g.json", `{"kind":"genesis","body":{"type":"collection","name":"readings","controllers":[{"identity":"`+ident+`"}],"rule":{"any_one":true}}}`)))
			b0 := firstID(t, b.ok("publish", "--kind", "authored", "--content", b.file("b0", "b's first line"), "--licence", "CC0-1.0"))
			root.pullFrom(a)
			root.pullFrom(b)
			perms := `[{"kind":"edition","targets":{"resources":["` + gid + `"]}}]`
			grant := func(h *idHome, inception string) string {
				return string(root.ok("identity", "grant", "--identity", ident, "--delegate", h.signer, "--delegate-inception", inception, "--permissions", perms).Members["grant"].(canon.String))
			}
			ga, gb := grant(a, gid), grant(b, b0)

			// edition publishes an approval of a new edition on pred and returns the approval, the edition id and the output
			n := 0
			edition := func(h *idHome, g, pred string) (string, string, *canon.Object) {
				t.Helper()
				n++
				o := h.ok("publish", "--draft", h.file("e.json", `{"kind":"edition","body":{"resource":"`+gid+`","predecessors":["`+pred+`"],"contents":{"members":[],"note":"edition `+string(rune('0'+n))+`"}}}`), "--as", ident, "--grant", g)
				sid := firstID(t, o)
				for _, e := range member(jsonOf(t, h.read("show", gid)), "resource_view", "editions").(canon.Array) {
					for _, ap := range e.(*canon.Object).Members["approvals"].(canon.Array) {
						if ap.(*canon.Object).Members["statement"] == canon.String(sid) {
							return sid, string(e.(*canon.Object).Members["edition"].(canon.String)), o
						}
					}
				}
				t.Fatalf("no edition holds approval %s", sid)
				return "", "", nil
			}
			view := func(h *idHome) (*canon.Object, int) {
				t.Helper()
				r := h.read("verify", gid)
				return member(jsonOf(t, r), "resource_view").(*canon.Object), r.code
			}

			a.pullFrom(root)
			a1, e1, _ := edition(a, ga, gid)
			// a second copy of A's key file, on a machine whose store holds everything up to here and never the cut
			thief := &idHome{t: t, store: drillStore(t), key: a.file("copy.key", ""), signer: a.signer}
			kb, _ := os.ReadFile(a.key)
			os.WriteFile(thief.key, kb, 0o600)
			os.Chmod(thief.key, 0o600)
			thief.pullFrom(root)
			thief.pullFrom(a)

			root.pullFrom(a)
			cut := firstID(t, root.ok("identity", "cut", "--identity", ident, "--grant", ga, "--last-good", a1, "--reason", "key_compromise"))
			b.pullFrom(root)
			b.pullFrom(a)
			_, e2, o2 := edition(b, gb, e1)
			if _, warned := o2.Members["warnings"]; warned {
				t.Fatalf("an edition on the current edition warns: %s", canon.Encode(o2))
			}
			for _, h := range []*idHome{root, a, b} {
				reader.pullFrom(h)
			}
			if rv, code := view(reader); code != ExitOK || rv.Members["current"] != canon.String(e2) || rv.Members["cut_excluded"] != nil {
				t.Fatalf("after the cut and B's edition: exit %d %s", code, canon.Encode(rv))
			}

			// the holder of the cut key signs one more edition, and the reader receives it
			_, et, _ := edition(thief, ga, e1)
			// a store that gets the edition first and the cut afterwards: A's and the copy's stores never held the cut
			late := newIDHome(t, alg)
			for _, h := range []*idHome{a, thief} {
				late.pullFrom(h)
			}
			if rv, code := view(late); code != ExitOK || rv.Members["current"] != canon.String(et) {
				t.Fatalf("before the cut arrives the edition is current: exit %d %s", code, canon.Encode(rv))
			}
			reader.pullFrom(thief)
			rv, code := view(reader)
			if code != ExitOK || rv.Members["current"] != canon.String(e2) || rv.Members["contested"] != nil {
				t.Fatalf("the cut key moved the resource: exit %d %s", code, canon.Encode(rv))
			}
			ce, _ := rv.Members["cut_excluded"].(canon.Array)
			if len(ce) != 1 {
				t.Fatalf("cut_excluded: %s", canon.Encode(rv))
			}
			row := ce[0].(*canon.Object)
			if row.Members["edition"] != canon.String(et) || row.Members["state"] != canon.String("unauthorized") || row.Members["grant"] != canon.String(ga) ||
				string(canon.Encode(row.Members["cuts"])) != `["`+cut+`"]` {
				t.Fatalf("cut_excluded row: %s", canon.Encode(row))
			}
			if h := runIn(reader.store, nil, "verify", gid); h.code != ExitOK || !strings.Contains(h.stdout, "cut excluded:") {
				t.Fatalf("human verify: %d %s", h.code, h.stdout)
			}
			// a pinned edition that a cut leaves out still does not pass
			if r := reader.read("verify", et); r.code == ExitOK {
				t.Fatalf("the excluded edition, pinned, passes: %s", r.stdout)
			}

			// pull labels the cut when it arrives after the edition it leaves out: this reader's current edition moves
			// back from the cut key's edition to E1, and the exit stays 0
			r := late.read("pull", root.store)
			if r.code != ExitOK {
				t.Fatalf("pull of the cut: %d %s", r.code, r.stdout)
			}
			var labelled bool
			for _, x := range jsonOf(t, r).Members["objects"].(canon.Array) {
				o := x.(*canon.Object)
				if o.Members["id"] != canon.String(cut) {
					continue
				}
				row := string(canon.Encode(o))
				labelled = strings.Contains(row, `"cut: editions not counted"`) && strings.Contains(row, "1 edition(s) not counted") && strings.Contains(row, et[:12]) && strings.Contains(row, "current "+e1[:12])
				if !labelled {
					t.Fatalf("cut row: %s", canon.Encode(o))
				}
			}
			if !labelled {
				t.Fatalf("the cut's row carries no label: %s", r.stdout)
			}
			// pulled again, the cut is already held: no label, nothing changed for this reader
			if r := late.read("pull", root.store); strings.Contains(r.stdout, "cut: editions not counted") {
				t.Fatalf("a held cut is labelled again: %s", r.stdout)
			}

			// the writer warns when an edition names a predecessor that is not an authorized edition
			b.pullFrom(thief)
			_, _, ow := edition(b, gb, et)
			if w := string(canon.Encode(ow.Members["warnings"])); !strings.Contains(w, "is not an authorized edition") || !strings.Contains(w, et) || !strings.Contains(w, "unauthorized") || !strings.Contains(w, e2) {
				t.Fatalf("no warning for an edition on an unauthorized predecessor: %s", canon.Encode(ow))
			}
		})
	}
}
