package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/resolve"
)

// TestProvenanceDepthRefusal: C-core-131 through the commands. A provenance graph deeper than the traversal bound
// (resolve.DefaultProvenanceDepth, printed by `status --limits`): show, verify and explain name the limit, its
// value and the scope it cut as an operational refusal, mark the result incomplete, grade it `unchecked`, and
// verify exits 3 (a limit of this reader is could-not-check, never ok); a chain inside the bound is T0, exit 0.
// The archive half (a nested archive beyond the scan limits) is store.TestScanLimitHitMidRun.
func TestProvenanceDepthBound(t *testing.T) {
	conformance.Covers(t, "C-core-131")
	build := func(n int) *world {
		w := newWorld(t)
		w.workflow("K1", "wf", "bytes", "")
		w.authored("L", "K3", "leaf")
		prev := "leaf"
		for i := 0; i < n; i++ {
			x := fmt.Sprintf("c%d", i)
			w.authored("A"+x, "K1", x, "prov", []string{"wf", prev})
			w.authored("B"+x, "K2", x, "prov", []string{"wf", prev})
			prev = x
		}
		return w
	}
	deep := build(resolve.DefaultProvenanceDepth + 2)
	top := dig(fmt.Sprintf("c%d", resolve.DefaultProvenanceDepth+1))
	for _, cmd := range []string{"show", "verify", "explain"} {
		r := deep.run(cmd, top, "--json")
		o := jsonOf(t, r)
		inc, ok := o.Members["incomplete"].(canon.Array)
		if !ok || len(inc) == 0 {
			t.Fatalf("%s: no incomplete member: %s", cmd, canon.Encode(o))
		}
		f := inc[0].(*canon.Object)
		d := string(f.Members["detail"].(canon.String))
		if f.Members["class"] != canon.String("operational") || f.Members["reason"] != canon.String("depth limit") ||
			!strings.Contains(d, fmt.Sprintf("provenance_depth=%d", resolve.DefaultProvenanceDepth)) || !strings.Contains(d, "scope: ") {
			t.Fatalf("%s: refusal %s", cmd, canon.Encode(f))
		}
		if o.Members["grade"] != canon.String("unchecked") {
			t.Fatalf("%s: grade %s past the bound, want unchecked", cmd, canon.Encode(o.Members["grade"]))
		}
		if cmd == "verify" && (r.code != ExitCouldNot || !strings.Contains(string(canon.Encode(o.Members["causes"])), `"unchecked"`)) {
			t.Fatalf("verify exit %d: %s", r.code, canon.Encode(o.Members["causes"]))
		}
		if h := deep.run(cmd, top); h.code != r.code || !strings.Contains(h.stdout, "provenance_depth=") || !strings.Contains(h.stdout, "unchecked") {
			t.Fatalf("%s human: exit %d\n%s", cmd, h.code, h.stdout)
		}
	}
	// the limit's value is visible
	found := false
	for _, row := range jsonOf(t, deep.run("status", "--limits", "--json")).Members["limits"].(canon.Array) {
		if o := row.(*canon.Object); o.Members["name"] == canon.String(resolve.ProvenanceDepthLimit) {
			found = o.Members["value"] == canon.Int(resolve.DefaultProvenanceDepth)
		}
	}
	if !found {
		t.Fatal("status --limits does not print provenance_depth with its value")
	}
	// inside the bound: T0, complete, exit 0
	ok := build(5)
	r := ok.run("verify", dig("c4"), "--json")
	o := jsonOf(t, r)
	if r.code != ExitOK || o.Members["grade"] != canon.String("T0") || o.Members["incomplete"] != nil {
		t.Fatalf("a chain inside the bound: exit %d %s", r.code, canon.Encode(o))
	}
}
