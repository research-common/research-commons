package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/resolve"
)

// viewCommands are the commands whose output is a view resolved from the statements held: each prints one
// status_scope footer (claims-model note §6 (1), I4; finding PROPS-F5).
var viewCommands = map[string]bool{"show": true, "verify": true, "explain": true, "list": true}

// countMember counts the members named k anywhere in v.
func countMember(v canon.Value, k string) int {
	n := 0
	switch x := v.(type) {
	case *canon.Object:
		for _, kk := range x.Keys {
			if kk == k {
				n++
			}
			n += countMember(x.Members[kk], k)
		}
	case canon.Array:
		for _, e := range x {
			n += countMember(e, k)
		}
	}
	return n
}

// TestStatusScopeFooter: PROPS-F5. Authorship (`sole author`), a statement's counted state and a verify exit
// are printed bare, so the view prints its scope once, as a footer: the last human line and one top-level JSON
// member, never inside a token. Every view command over every fixture ref carries it; a command that resolves
// no status (status, fsck, gc, init) does not.
func TestStatusScopeFooter(t *testing.T) {
	conformance.Partial(t, "P-12", "the CLI half: every view command (show, verify, explain, list) over every fixture ref prints one status_scope footer, `within statements you hold`, beside authorship, counted state and the verify exit, and publish prints it beside a pre-pin state and a task edition's readiness; show, verify and explain of a resource, an edition or an approval print it too (TestResourceSurfaceSweep)")
	w := fixture(t)
	const footer = "status scope: " + resolve.ScopeHeld + "\n"
	for _, a := range sweepArgs(w) {
		h, j := w.run(a...), w.run(append(a, "--json")...)
		o := jsonOf(t, j)
		n := countMember(o, "status_scope")
		if !viewCommands[a[0]] {
			if n != 0 || strings.Contains(h.stdout, "status scope:") {
				t.Errorf("%v resolves no status and prints a scope", a)
			}
			continue
		}
		if n != 1 || o.Members["status_scope"] != canon.String(resolve.ScopeHeld) {
			t.Errorf("%v: status_scope %d time(s), top-level %v\n%s", a, n, o.Members["status_scope"], j.stdout)
		}
		if !strings.HasSuffix(h.stdout, footer) || strings.Count(h.stdout, "status scope:") != 1 {
			t.Errorf("%v: the human surface does not end with one scope footer\n%s", a, h.stdout)
		}
	}
	// the statuses the finding named, each with the footer beside it
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"show", dig("sole")}, "authorship: sole author\n"},
		{[]string{"verify", dig("sole")}, "exit: 0\n"},
		{[]string{"verify", w.ids["A:sole"]}, "counted: counted\n"},
		{[]string{"list"}, "authorship: contested"},
	} {
		r := w.run(c.args...)
		if !strings.Contains(r.stdout, c.want) || !strings.HasSuffix(r.stdout, footer) {
			t.Errorf("%v: want %q with the scope footer\n%s", c.args, c.want, r.stdout)
		}
	}
	for _, a := range [][]string{{"status"}, {"fsck"}, {"gc"}} {
		if r := w.run(append(a, "--json")...); strings.Contains(r.stdout, "status_scope") {
			t.Errorf("%v prints a scope: %s", a, r.stdout)
		}
	}
}
