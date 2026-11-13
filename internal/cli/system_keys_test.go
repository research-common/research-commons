package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// TestVerifyEmptySystemKeyValue: C-core-32b, empty-value variant, through the command. A method edition declares
// system_keys model and routing_era. An observation pinning routing_era as "" is admitted (it is held and shown)
// and `verify` exits 3 naming referent.system.routing_era, the same answer as for a missing member; the same
// observation with a real value exits 0.
func TestVerifyEmptySystemKeyValue(t *testing.T) {
	conformance.Covers(t, "C-core-32b")
	w := newWorld(t)
	g := w.genesisOf("G", "MC", 0, "MC")
	_, m := w.approve("M", "MC", editionBody(g, []string{g}, nil, "system_keys", []string{"model", "routing_era"}))
	observe := func(name string, system *canon.Object) string {
		ref := obj("method_edition", m,
			"environment", obj("image_digest", dig("img"), "platform", "linux/amd64", "harness_commit", strings.Repeat("c", 40)),
			"system", system, "inputs", []string{dig("seeds")}, "window", obj("from", "2026-10-01T00:00:00Z", "to", "2026-10-02T00:00:00Z"))
		return w.sign(name, "O", "observed", obj("content", content(name), "class", "method", "referent", canon.Value(ref),
			"capture", obj("at", "2026-10-02T00:00:00Z", "evidence", "self-asserted")))
	}
	empty := observe("empty", obj("model", "m", "routing_era", ""))
	missing := observe("missing", obj("model", "m"))
	set := observe("set", obj("model", "m", "routing_era", "q3"))

	for _, id := range []string{empty, missing} {
		r := w.run("verify", id)
		if r.code != ExitCouldNot || !strings.Contains(r.stdout, "referent.system.routing_era") {
			t.Fatalf("verify %s: exit %d, want %d naming the key:\n%s%s", id[:8], r.code, ExitCouldNot, r.stdout, r.stderr)
		}
	}
	// held and shown as written, not refused
	if r := w.run("show", empty); r.code != ExitOK || !strings.Contains(r.stdout, `"routing_era":""`) || !strings.Contains(r.stdout, "status: unpinned") {
		t.Fatalf("show: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if r := w.run("verify", set); r.code != ExitOK {
		t.Fatalf("control verify: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
}
