package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/run"
)

// TestProvenancePartialWriteAndRead: wire §5 lists `provenance_partial` (workflow R, inputs R, unpinned R,
// supplied O, environment O; `unpinned` non-empty and duplicate-free, `supplied` keys among its names) on
// `authored`, so the one validation core checks it. A draft with a wrong shape is
// refused by `publish --draft` before signing (intrinsic, malformed statement, naming the member; the store is
// byte-identical afterwards), and the same body, signed by a key that skipped the writer, is refused by `pull` and
// by `hub check` with the same class, reason and member. The well-formed control passes all three, so each refusal
// is the field's.
func TestProvenancePartialWriteAndRead(t *testing.T) {
	good := `{"workflow":"` + dig("wf") + `","inputs":["` + dig("in") + `"],"unpinned":["tag:latest"]}`
	with := func(member, v string) string { // replace one member of the good object
		m, _ := canon.Parse([]byte(good))
		o := m.(*canon.Object)
		if v == "" {
			delete(o.Members, member)
			for i, k := range o.Keys {
				if k == member {
					o.Keys = append(o.Keys[:i], o.Keys[i+1:]...)
					break
				}
			}
			return string(canon.Encode(o))
		}
		pv, err := canon.Parse([]byte(v))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := o.Members[member]; !ok {
			o.Keys = append(o.Keys, member)
		}
		o.Members[member] = pv
		return string(canon.Encode(o))
	}
	cases := []struct {
		name, value, detail string // detail "" = accepted
	}{
		{"control", good, ""},
		{"control: supplied", with("supplied", `{"tag:latest":"`+dig("bytes")+`"}`), ""},
		{"not an object", `5`, "body.provenance_partial is not an object"},
		{"workflow missing", with("workflow", ""), "body.provenance_partial.workflow is missing"},
		{"bad digest in inputs", with("inputs", `["`+dig("in")+`","sha256:zz"]`), "body.provenance_partial.inputs[1] is not a content digest"},
		{"non-string in unpinned", with("unpinned", `["a",3]`), "body.provenance_partial.unpinned[1] is not a string"},
		{"non-digest in supplied", with("supplied", `{"tag:latest":"bytes"}`), "body.provenance_partial.supplied.tag:latest is not a content digest"},
		{"nothing unpinned", with("unpinned", `[]`), "body.provenance_partial.unpinned is empty"},
		{"unpinned name repeated", with("unpinned", `["a","b","a"]`), "body.provenance_partial.unpinned[2] repeats"},
		{"supplied key not unpinned", with("supplied", `{"other":"`+dig("bytes")+`"}`), "body.provenance_partial.supplied.other is not among unpinned"},
		{"control: unsorted unpinned", with("unpinned", `["b","a"]`), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := "rows"
			content := `{"digest":"` + run.Digest([]byte(data)) + `","size":4}`
			draft := `{"kind":"authored","body":{"content":` + content + `,"type":"dataset","provenance_partial":` + c.value + `}}`

			// write gate: publish --draft
			p := newPubWorld(t)
			// the draft names bytes the store must hold (storage note §3.2): install them with a plain publish first
			if r := p.publish("--kind", "authored", "--content", p.file("rows", data), "--no-holds"); r.code != ExitOK {
				t.Fatalf("setup: %d %s", r.code, r.stdout)
			}
			before := snapshot(t, p.root)
			r := p.publish("--draft", p.file("d.json", draft), "--no-holds")
			if c.detail == "" {
				if r.code != ExitOK {
					t.Fatalf("publish refused a well-formed provenance_partial: %d %s", r.code, r.stdout)
				}
			} else {
				o := outObj(t, r)
				if r.code != ExitDidNotStart || o.Members["class"] != canon.String("intrinsic") || o.Members["committed"] != canon.Bool(false) ||
					!strings.Contains(r.stdout, "malformed statement") || !strings.Contains(r.stdout, c.detail) {
					t.Fatalf("publish: exit %d, want a refusal naming %q:\n%s", r.code, c.detail, r.stdout)
				}
				if snapshot(t, p.root) != before {
					t.Fatal("a refused draft changed the store")
				}
			}

			// read gates: the same body signed past the writer, delivered as a package and as a hub change
			src := newWorld(t)
			src.blob("x", []byte(data))
			b, err := canon.Parse([]byte(draft))
			if err != nil {
				t.Fatal(err)
			}
			body := b.(*canon.Object).Members["body"].(*canon.Object)
			line := src.signLine("A", "K2", "authored", "2026-10-16T02:00:00Z", body)
			id := src.ids["A"]
			rel := stmtPath(src.signer("K2"), id)

			pkg := t.TempDir()
			copyData(t, src.root, pkg)
			os.MkdirAll(filepath.Dir(filepath.Join(pkg, rel)), 0o755)
			os.WriteFile(filepath.Join(pkg, rel), line, 0o644)
			pr := newWorld(t).run("pull", pkg, "--json")

			hub := newWorld(t)
			hub.gitHub()
			gitIn(t, hub.root, "checkout", "-q", "-b", "change")
			os.MkdirAll(filepath.Dir(filepath.Join(hub.root, rel)), 0o755)
			os.WriteFile(filepath.Join(hub.root, rel), line, 0o644)
			gitIn(t, hub.root, "add", "-A")
			gitIn(t, hub.root, "commit", "-q", "-m", "a statement")
			hr := hub.run("hub", "check", "--base", "main", "--json")

			if c.detail == "" {
				if pr.code != ExitOK || hr.code != ExitOK {
					t.Fatalf("a well-formed provenance_partial is refused: pull %d, hub check %d\n%s\n%s", pr.code, hr.code, pr.stdout, hr.stdout)
				}
				return
			}
			for _, g := range []struct {
				name string
				res  result
				row  *canon.Object
			}{{"pull", pr, refusedRow(t, pr)}, {"hub check", hr, objectRow(t, jsonOf(t, hr), rel)}} {
				if g.row == nil {
					t.Fatalf("%s: no row for %s:\n%s", g.name, rel, g.res.stdout)
				}
				detail, _ := g.row.Members["detail"].(canon.String)
				if g.res.code != 1 || g.row.Members["class"] != canon.String("intrinsic") || g.row.Members["reason"] != canon.String("malformed statement") ||
					!strings.Contains(string(detail), c.detail) {
					t.Fatalf("%s: exit %d: %s", g.name, g.res.code, canon.Encode(g.row))
				}
			}
		})
	}
}
