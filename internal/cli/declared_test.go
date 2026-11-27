package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// TestDeclaredFieldsSurfaces: C-core-149. The six signed `authored` fields no disclosure covers (type, description,
// attribution, comparator, supersedes, extends) are printed on show, list, verify and explain as a block of their own
// beside the disclosures: the default value with its signer, a rival's value listed with its signer, and the
// attribution beside the licence line of `show`. The disclosure set of C-core-66 is unchanged.
func TestDeclaredFieldsSurfaces(t *testing.T) {
	conformance.Covers(t, "C-core-149")
	w := newWorld(t)
	w.blob("pub", []byte("pub"))
	w.blob("old", []byte("old"))
	w.authored("A:pub", "K1", "pub", "licence", "CC-BY-4.0", "description", "a plain description",
		"attribution", "Jane Doe, 2026", "supersedes", dig("old"), "extends", dig("old"), "comparator", dig("cmp"))
	w.authored("A:pub2", "K2", "pub", "description", "a rival description")
	d := w.blobs["pub"]
	names := []string{"type", "description", "attribution", "comparator", "supersedes", "extends"}

	for _, cmd := range []string{"show", "verify", "explain"} {
		j := jsonOf(t, w.run(cmd, d, "--json"))
		df, ok := j.Members["declared_fields"].(*canon.Object)
		if !ok {
			t.Fatalf("%s --json: no declared_fields: %s", cmd, canon.Encode(j))
		}
		for _, n := range names {
			if _, ok := df.Members[n]; !ok {
				t.Errorf("%s --json: declared_fields lacks %s", cmd, n)
			}
		}
		if _, ok := j.Members["disclosures"].(*canon.Object); !ok {
			t.Errorf("%s --json: disclosures member lost", cmd)
		}
	}
	// list --json: the same block on the blob's row
	lj := jsonOf(t, w.run("list", "--json"))
	found := false
	for _, e := range lj.Members["blobs"].(canon.Array) {
		o := e.(*canon.Object)
		if string(o.Members["digest"].(canon.String)) == d {
			found = true
			if _, ok := o.Members["declared_fields"].(*canon.Object); !ok {
				t.Errorf("list --json: no declared_fields on the row")
			}
		}
	}
	if !found {
		t.Fatalf("list --json: blob not listed")
	}

	// the human surface of every command prints the block too
	for _, args := range [][]string{{"list"}, {"verify", d}, {"explain", d}} {
		txt := w.run(args...).stdout
		if !strings.Contains(txt, "declared fields:") || !strings.Contains(txt, "a rival description") {
			t.Errorf("%s text lacks the declared fields block:\n%s", args[0], txt)
		}
	}
	// contested authorship: no default, so every signed value is listed under `values`, as a disclosure lists them
	cj := jsonOf(t, w.run("show", d, "--json")).Members["declared_fields"].(*canon.Object).Members["description"].(*canon.Object)
	if vs, ok := cj.Members["values"].(canon.Array); !ok || len(vs) != 2 || cj.Members["rivals"] != nil || cj.Members["value"] != nil {
		t.Errorf("contested description: %s", canon.Encode(cj))
	}
	out := w.run("show", d).stdout
	for _, want := range []string{"a plain description", "Jane Doe, 2026", "a rival description"} {
		if !strings.Contains(out, want) {
			t.Errorf("show text lacks %q:\n%s", want, out)
		}
	}
	// the attribution is on the licence's own lines: after "licence:" and before the next disclosure
	di := strings.Index(out, "disclosures:")
	li := strings.Index(out[di:], "\n  licence:")
	pi := strings.Index(out[di+li:], "\n  pre registration:")
	if di < 0 || li < 0 || pi < 0 || !strings.Contains(out[di+li:di+li+pi], "attribution:") {
		t.Errorf("show text: attribution is not beside the licence line:\n%s", out)
	}
	// a sole author: the default value, its signer, and no rivals
	w.blob("solo", []byte("solo"))
	w.authored("A:solo", "K3", "solo", "licence", "CC-BY-4.0", "attribution", "Ann Lee")
	so := w.run("show", w.blobs["solo"]).stdout
	if !strings.Contains(so, "Ann Lee") {
		t.Errorf("sole author attribution missing:\n%s", so)
	}
	sj := jsonOf(t, w.run("show", w.blobs["solo"], "--json"))
	df := sj.Members["declared_fields"].(*canon.Object)
	at := df.Members["attribution"].(*canon.Object)
	if string(at.Members["state"].(canon.String)) != "default" || at.Members["signers"] == nil || at.Members["rivals"] != nil {
		t.Errorf("sole author attribution: %s", canon.Encode(at))
	}
	if _, ok := df.Members["comparator"]; ok {
		t.Errorf("a field nobody set is listed: %s", canon.Encode(df))
	}
}
