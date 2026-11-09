package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

// TestListResources: list prints one line per held resource beside the blobs (additive: the blobs array and its
// count are unchanged), each with the resource id, its current edition (the genesis while none is authorized) or
// FORK with its tips, and the controllers count of the current authority; the line agrees with show's resource
// view, and the human surface prints one line per resource.
func TestListResources(t *testing.T) {
	w := newWorld(t)
	w.blob("x", []byte("x"))
	w.authored("A:x", "A", "x")
	before := jsonOf(t, w.run("list", "--json"))
	if rs, ok := before.Members["resources"].(canon.Array); !ok || len(rs) != 0 {
		t.Fatalf("resources with none held: %s", canon.Encode(before))
	}
	g := w.genesisOf("G", "A", 0, "A", "B")
	g2 := w.genesisOf("G2", "A", 2, "A", "B", "C")
	_, e1 := w.approve("E1", "A", editionBody(g, []string{g}, []string{"a"}))
	g3 := w.genesisOf("G3", "A", 0, "A", "B")
	_, l := w.approve("L", "A", editionBody(g3, []string{g3}, []string{"l"}))
	_, r := w.approve("R", "B", editionBody(g3, []string{g3}, []string{"r"}))

	o := jsonOf(t, w.run("list", "--json"))
	if string(canon.Encode(o.Members["blobs"])) != string(canon.Encode(before.Members["blobs"])) || o.Members["count"] != before.Members["count"] {
		t.Fatalf("resources changed the blobs listing:\n%s\nvs\n%s", canon.Encode(o.Members["blobs"]), canon.Encode(before.Members["blobs"]))
	}
	rows := map[string]*canon.Object{}
	var order []string
	for _, x := range o.Members["resources"].(canon.Array) {
		ro := x.(*canon.Object)
		id := string(ro.Members["resource"].(canon.String))
		rows[id], order = ro, append(order, id)
	}
	if !slices.IsSorted(order) || len(order) != 3 {
		t.Fatalf("resource lines %v, want the three geneses sorted", order)
	}
	if ro := rows[g]; ro.Members["current"] != canon.String(e1) || ro.Members["controllers"] != canon.Int(2) {
		t.Fatalf("linear resource: %s", canon.Encode(ro))
	}
	if ro := rows[g2]; ro.Members["current"] != canon.String(g2) || ro.Members["controllers"] != canon.Int(3) || ro.Members["current_is"] == nil {
		t.Fatalf("resource with no edition: %s", canon.Encode(ro))
	}
	tips := []string{l, r}
	slices.Sort(tips)
	if ro := rows[g3]; ro.Members["state"] != canon.String("FORK") || !slices.Equal(strs(ro.Members["tips"]), tips) || ro.Members["current"] != nil {
		t.Fatalf("forked resource: %s", canon.Encode(ro))
	}
	// each line agrees with show's resource view
	for id, ro := range rows {
		rv := members(t, jsonOf(t, w.run("show", id, "--json")), "resource_view")
		for _, k := range []string{"current", "state", "tips"} {
			if string(canon.Encode(nilOr(ro.Members[k]))) != string(canon.Encode(nilOr(rv.Members[k]))) {
				t.Fatalf("list and show disagree on %s for %s: %s vs %s", k, id, canon.Encode(nilOr(ro.Members[k])), canon.Encode(nilOr(rv.Members[k])))
			}
		}
		if n := len(rv.Members["controllers"].(canon.Array)); ro.Members["state"] == nil && ro.Members["controllers"] != canon.Int(n) {
			t.Fatalf("controllers count %v, show lists %d", ro.Members["controllers"], n)
		}
	}
	// the human surface: one line per resource, under a resources heading, with FORK on the forked one
	h := w.run("list")
	if h.code != ExitOK {
		t.Fatalf("list exit %d", h.code)
	}
	var lines []string
	for _, ln := range strings.Split(h.stdout, "\n") {
		if strings.HasPrefix(ln, "  - resource: ") {
			lines = append(lines, ln)
		}
	}
	if len(lines) != 3 || !strings.Contains(h.stdout, "\nresources:\n") {
		t.Fatalf("human resource lines %q\n%s", lines, h.stdout)
	}
	for _, ln := range lines {
		if strings.Contains(ln, g3) != strings.Contains(ln, "state: FORK") {
			t.Fatalf("FORK on the wrong line: %q", ln)
		}
	}
}

func nilOr(v canon.Value) canon.Value {
	if v == nil {
		return canon.Null{}
	}
	return v
}
