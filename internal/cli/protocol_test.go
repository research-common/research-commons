package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// TestProtocolNoComparator: C-core-18a, end to end. Two keys author different output bytes with one provenance
// under a `protocol` workflow whose authored statement names no comparator. Every run's grade and the group are
// `unchecked`; no default comparison is applied (no T0, T1 or `diverged`, although the bytes differ); `verify`
// exits 3 on both outputs with the derivation cause `unchecked`; the display (show, explain, human verify) says
// the workflow declares no comparator. Control: the same world whose workflow names a comparator reaches the
// comparator question (the runs are no longer `unchecked` for want of a declaration), so the outcome above is
// the missing declaration's.
func TestProtocolNoComparator(t *testing.T) {
	conformance.Covers(t, "C-core-18a")
	build := func(comparator string) *world {
		w := newWorld(t)
		w.workflow("K1", "wf", "protocol", comparator)
		w.authored("A:out1", "K1", "out1", "prov", []string{"wf", "in"})
		w.authored("A:out2", "K2", "out2", "prov", []string{"wf", "in"})
		return w
	}
	w := build("")
	const says = "the workflow declares protocol replication and no comparator; no default comparison is made"
	for _, out := range []string{"out1", "out2"} {
		d := dig(out)
		r := w.run("verify", d, "--json")
		v := jsonOf(t, r)
		s := string(canon.Encode(v))
		if r.code != ExitCouldNot || !strings.Contains(s, `"about":"derivation","state":"unchecked"`) {
			t.Fatalf("verify %s: exit %d\n%s", out, r.code, s)
		}
		for _, bad := range []string{`"T0"`, `"T1"`, `"diverged"`, `"comparator":`} {
			if strings.Contains(s, bad) {
				t.Fatalf("verify %s: a default comparison or comparator appeared (%s)\n%s", out, bad, s)
			}
		}
		sh := string(canon.Encode(jsonOf(t, w.run("show", d, "--json"))))
		if strings.Count(sh, `"grade":"unchecked"`) != 3 || !strings.Contains(sh, `"replication":"protocol"`) {
			t.Fatalf("show %s: not every run unchecked under protocol\n%s", out, sh)
		}
		ex := w.run("explain", d)
		if ex.code != ExitOK || !strings.Contains(ex.stdout, says) {
			t.Fatalf("explain %s does not say the workflow declares no comparator:\n%s", out, ex.stdout)
		}
		if h := w.run("show", d); h.code != ExitOK || !strings.Contains(h.stdout, says) {
			t.Fatalf("human show %s does not say it:\n%s", out, h.stdout)
		}
		if h := w.run("verify", d); h.code != ExitCouldNot || !strings.Contains(h.stdout, "unchecked") {
			t.Fatalf("human verify %s: exit %d\n%s", out, h.code, h.stdout)
		}
	}
	// control: with a comparator declared, the group is no longer unchecked for want of one
	c := build("cmp")
	ex := c.run("explain", dig("out1"))
	if strings.Contains(ex.stdout, says) {
		t.Fatalf("control: a declared comparator still reads as no comparator:\n%s", ex.stdout)
	}
	if !strings.Contains(string(canon.Encode(jsonOf(t, c.run("show", dig("out1"), "--json")))), `"comparator":"`+dig("cmp")+`"`) {
		t.Fatal("control: the declared comparator is not shown")
	}
}
