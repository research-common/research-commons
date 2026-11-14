package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

// TestPublishHoldsRule: the one rule for the writer's own `holds` (holdsFor; the same rule run --publish applies,
// internal/clirun.TestRunPublishHoldsRule). An `authored` with its bytes gets a holds; an `observed` with its bytes
// gets one too (the only statement of the signer that pins a capture's bytes as served); --no-holds withholds
// either; an `observed` whose bytes this store does not keep gets none (nothing to serve); a `reproduced` never
// gets one; --no-holds on a kind without one is exit 2.
func TestPublishHoldsRule(t *testing.T) {
	p := newPubWorld(t)
	kinds := func(r result) string {
		t.Helper()
		if r.code != ExitOK {
			t.Fatalf("exit %d %s", r.code, r.stdout)
		}
		var ks []string
		for _, s := range statementsOf(outObj(t, r)) {
			ks = append(ks, string(s.Members["kind"].(canon.String)))
		}
		return strings.Join(ks, ",")
	}
	observed := func(data string) string {
		d := dig(data)
		return p.file("obs-"+data, `{"kind":"observed","body":{"content":{"digest":"`+d+`","size":`+itoa(len(data))+`},"class":"source",`+
			`"referent":{"endpoint":"https://api.example/x","parameters":{},"response_digest":"`+d+`"},"capture":{"at":"2026-01-02T00:00:00Z","evidence":"self-asserted"}}}`)
	}
	authored := p.publish("--kind", "authored", "--content", p.file("a", "authored bytes"))
	if k := kinds(authored); k != "authored,holds" {
		t.Fatalf("authored: %s", k)
	}
	if k := kinds(p.publish("--draft", observed("capture one"), "--content", p.file("o1", "capture one"))); k != "observed,holds" {
		t.Fatalf("observed with its bytes: %s", k)
	}
	if k := kinds(p.publish("--draft", observed("capture two"), "--content", p.file("o2", "capture two"), "--no-holds")); k != "observed" {
		t.Fatalf("observed --no-holds: %s", k)
	}
	if k := kinds(p.publish("--draft", observed("not kept here"))); k != "observed" {
		t.Fatalf("observed whose bytes this store does not keep: %s", k)
	}
	aid := string(statementsOf(outObj(t, authored))[0].Members["statement"].(canon.String))
	rep := p.file("rep", `{"kind":"reproduced","body":{"of":"`+aid+`","result":"match","content":{"digest":"`+dig("authored bytes")+`","size":14},`+
		`"provenance":{"workflow":"`+dig("wf")+`","inputs":[]}}}`)
	if k := kinds(p.publish("--draft", rep)); k != "reproduced" {
		t.Fatalf("reproduced: %s", k)
	}
	before := snapshot(t, p.root)
	if r := p.publish("--draft", rep, "--no-holds"); r.code != ExitDidNotStart || snapshot(t, p.root) != before {
		t.Fatalf("--no-holds on reproduced: %d %s", r.code, r.stdout)
	}
}
