package run

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// TestFirstRunAuthored: C-exec-02. No prior same-provenance `authored` by the runner: `authored` with provenance
// (workflow hash, input hashes) and the environment record, never `reproduced`.
func TestFirstRunAuthored(t *testing.T) {
	conformance.Covers(t, "C-exec-02")
	p := newPinned(t, "bytes", "")
	a := p.w.resolver().Artifact(p.output.Digest)
	st, _ := p.w.resolver().Statement(p.authored)
	if st.St.Kind != "authored" || a.Group == nil || a.Group.Provenance.Workflow != Digest(p.specBytes) || a.Group.Provenance.Inputs[0] != Digest(p.data) {
		t.Fatalf("%s", a.Render())
	}
	has(t, string(canon.Encode(st.St.Body)), `"environment":{`)
	if n := len(a.Group.Runs); n != 1 || a.Group.Runs[0].Kind != "authored" {
		t.Fatalf("%s", a.Render())
	}
}

// TestRerunEmitsReproduced: C-exec-01. A holds its own `authored` for X under (W, inputs); `run --publish` gets X
// again: a `reproduced` (match, with environment record) is appended, no second `authored` for X by A exists in
// A's log, and the group shows `derived by 1` plus the reproduction.
func TestRerunEmitsReproduced(t *testing.T) {
	conformance.Covers(t, "C-exec-01")
	p := newPinned(t, "bytes", "")
	f := newFake().step("s", catStep("in"))
	res, err := Execute(context.Background(), grantAll(), f, p.inv(p.data))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanPublish(PublishInput{Spec: p.spec, Result: res, Own: []HeldAuthored{{p.authored, p.output.Digest}}, Mode: "bytes"})
	if err != nil || len(plan) != 1 || plan[0].Kind != "reproduced" || plan[0].Token.Kind != Match {
		t.Fatalf("%v %+v", err, plan)
	}
	body := string(canon.Encode(plan[0].Body))
	has(t, body, `"of":"`+p.authored+`"`)
	has(t, body, `"result":"match"`)
	has(t, body, `"environment":{`)
	p.w.publish(ownerKey, plan)
	r := p.w.resolver()
	n := 0
	for _, l := range p.w.lines {
		st, _ := wire.Read(l)
		if st.Kind == "authored" && st.Signer == p.w.signer(ownerKey) && strings.Contains(string(canon.Encode(st.Body)), p.output.Digest) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d authored for X by A", n)
	}
	a := r.Artifact(p.output.Digest)
	has(t, a.Render(), "derived by 1: byte-identical re-derivation (T0)")
	has(t, a.Render(), "reproduced ")
	// a re-run producing different bytes Y against A's own X: reproduced diverged pointing at X; Y gets no
	// authored here (an author who wants Y as a result publishes it on its own, §5.1 row 3 / §8)
	f = newFake().step("s", writeStep("Y"))
	res, _ = Execute(context.Background(), grantAll(), f, p.inv(p.data))
	plan, err = PlanPublish(PublishInput{Spec: p.spec, Result: res, Own: []HeldAuthored{{p.authored, p.output.Digest}}, Mode: "bytes"})
	if err != nil || plan[0].Kind != "reproduced" || plan[0].Token.Kind != Diverged {
		t.Fatalf("%v %+v", err, plan)
	}
	// another key's authored for the same provenance changes nothing: B's first run is an authored
	f = newFake().step("s", catStep("in"))
	res, _ = Execute(context.Background(), grantAll(), f, p.inv(p.data))
	plan, _ = PlanPublish(PublishInput{Spec: p.spec, Result: res, Mode: "bytes"})
	if plan[0].Kind != "authored" {
		t.Fatalf("B: %s", plan[0].Kind)
	}
}

// TestUnpinnedInput: C-exec-03. A workflow whose input is a mutable tag: the run is not refused; its output
// joins no derivation group (no `provenance`, so the resolver forms none); `verify` cannot report T0: exit 4,
// nothing to re-run, the unpinned input listed.
func TestUnpinnedInput(t *testing.T) {
	conformance.Covers(t, "C-exec-03")
	data := []byte("pinned")
	specBytes := specB("s", map[string]string{"feed": "registry.example/feed:latest", "table": Digest(data)})
	s := mustSpec(t, specBytes)
	f := newFake().step("s", catStep("table"))
	blobs := blobsFor(s, "s", map[string][]byte{"t": data})
	blobs["registry.example/feed:latest"] = []byte("whatever the tag pointed at today")
	res, err := Execute(context.Background(), grantAll(), f, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobs})
	if err != nil || !res.Completed() {
		t.Fatalf("an unpinned input is disclosed, not refused: %v", err)
	}
	plan, err := PlanPublish(PublishInput{Spec: s, Result: res, Mode: "bytes"})
	if err != nil || len(plan) != 1 || plan[0].Kind != "authored" {
		t.Fatal(err)
	}
	w := newWorld(t)
	w.workflow(ownerKey, specBytes, "bytes", "")
	w.publish(ownerKey, plan)
	w.publish("B", plan) // B runs it too and gets the same bytes: still no group
	a := w.resolver().Artifact(res.Outputs[0].Digest)
	if a.Group != nil || len(a.Groups) != 0 || a.Step.Tier != "" {
		t.Fatalf("partial provenance joined a group:\n%s", a.Render())
	}
	un := Partial(plan[0].Body)
	if len(un) != 1 || !strings.Contains(un[0], "feed:latest") {
		t.Fatalf("unpinned %v", un)
	}
	code, why := VerifyPartial(un)
	if code != 4 || !strings.Contains(strings.Join(why, ";"), "unpinned input feed") {
		t.Fatalf("%d %v", code, why)
	}
}

// threeOutputs runs a spec with outputs o1, o2, o3.
func threeOutputs(t *testing.T, missing string) (*Spec, *Result) {
	specBytes := specB("s3", nil, "outputs", object("o1", canon.String("o1"), "o2", canon.String("o2"), "o3", canon.String("o3")))
	s := mustSpec(t, specBytes)
	f := newFake().step("s3", func(_ context.Context, _, out string, _ map[string]string) (int, Resources) {
		for _, n := range []string{"o1", "o2", "o3"} {
			if n != missing {
				os.WriteFile(filepath.Join(out, n), []byte("bytes of "+n), 0o644)
			}
		}
		return 0, Resources{CapMemory: 1}
	})
	res, err := Execute(context.Background(), grantAll(), f, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobsFor(s, "s3", nil)})
	if err != nil {
		t.Fatal(err)
	}
	return s, res
}

// TestPerOutputDisclosures: C-exec-04. Three outputs; a licence and availability supplied for two and nothing for
// the third: each `authored` carries exactly what was supplied, the third shows licence `unknown` in the
// resolver, nothing is inherited from a sibling or the workflow (whose own statement carries a licence), and no
// flag is needed to publish partial disclosures. Also: one missing output makes the whole run incomplete, with
// nothing published from its siblings.
func TestPerOutputDisclosures(t *testing.T) {
	conformance.Covers(t, "C-exec-04")
	s, res := threeOutputs(t, "")
	avail := object("redistribution", canon.String("permitted"), "obtainable", canon.Bool(true))
	plan, err := PlanPublish(PublishInput{Spec: s, Result: res, Mode: "bytes", Disclosures: map[string]map[string]canon.Value{
		"o1": {"licence": canon.String("CC-BY-4.0"), "availability": avail},
		"o2": {"licence": canon.String("CC0-1.0"), "availability": avail},
	}})
	if err != nil || len(plan) != 3 {
		t.Fatal(err, plan)
	}
	w := newWorld(t)
	w.workflow(ownerKey, specB("s3", nil, "outputs", object("o1", canon.String("o1"), "o2", canon.String("o2"), "o3", canon.String("o3"))), "bytes", "",
		"licence", canon.String("MIT"))
	w.publish(ownerKey, plan)
	r := w.resolver()
	want := map[string]string{"o1": `"CC-BY-4.0"`, "o2": `"CC0-1.0"`}
	for _, pl := range plan {
		o, _ := res.Output(pl.Output)
		a := r.Artifact(o.Digest)
		lic := a.Field("licence")
		if v, _ := lic.Default(); v != want[pl.Output] {
			t.Fatalf("%s licence %q (%s)", pl.Output, v, lic.State)
		}
		keys := slices.Clone(pl.Body.Keys)
		slices.Sort(keys)
		if pl.Output == "o3" {
			has(t, a.Render(), "licence: unknown")
			has(t, a.Render(), "availability: undeclared")
			if strings.Join(keys, ",") != "content,provenance,type" {
				t.Fatalf("o3 carries %v", keys)
			}
		}
	}
	_, inc := threeOutputs(t, "o2")
	if inc.Token.Kind != IncompleteOutput || len(inc.Outputs) != 0 {
		t.Fatalf("one missing output: %s, %d outputs kept", inc.Token, len(inc.Outputs))
	}
	if _, err := PlanPublish(PublishInput{Spec: s, Result: inc}); err == nil {
		t.Fatal("published siblings of a missing output")
	}
}

// TestPublishAcceptsEveryDisclosure: C-exec-05. Every disclosure `publish` accepts (the single-party fields of
// `authored` the resolver reads, minus `type`, which the tool writes) is accepted by `run --publish` and present
// in the emitted statement; the set difference is empty. The emitted statement passes the wire gate.
func TestPublishAcceptsEveryDisclosure(t *testing.T) {
	conformance.Partial(t, "C-exec-05", "the disclosure sets compared are the Go lists (resolve.SingleParty vs run.Disclosure); the CLI flag enumeration needs the CLI slice")
	var publish []string
	for _, f := range resolveSingleParty() {
		if f != "type" {
			publish = append(publish, f)
		}
	}
	if !slices.Equal(publish, Disclosure) {
		t.Fatalf("publish %v\nrun --publish %v", publish, Disclosure)
	}
	id := strings.Repeat("ab", 32)
	values := map[string]canon.Value{
		"attribution":      canon.String("A. Author"),
		"availability":     object("redistribution", canon.String("restricted"), "obtainable", canon.Bool(false)),
		"comparator":       canon.String(Digest([]byte("k"))),
		"description":      canon.String("d"),
		"extends":          canon.String(Digest([]byte("e"))),
		"fulfills":         object("resource", canon.String(id), "edition", canon.String(id)),
		"intended_for":     object("resource", canon.String(id), "edition", canon.String(id), "edition_applied", canon.String(id), "outcome", canon.String("ok")),
		"licence":          canon.String("LicenseRef-x"),
		"licence_texts":    object("LicenseRef-x", canon.String("https://example.org/terms")),
		"pre_registration": canon.String("exploratory"),
		"replication":      canon.String("bytes"),
		"sampling":         object("n", canon.Int(3), "unit", canon.String("runs")),
		"shelf_life_days":  canon.Int(30),
		"supersedes":       canon.String(Digest([]byte("old"))),
	}
	if len(values) != len(Disclosure) {
		t.Fatal("a disclosure has no test value")
	}
	s, res := threeOutputs(t, "")
	plan, err := PlanPublish(PublishInput{Spec: s, Result: res, Disclosures: map[string]map[string]canon.Value{"o1": values}})
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld(t)
	w.publish(ownerKey, plan) // through wire.Write: every body passes the validation core
	for _, k := range Disclosure {
		if _, ok := plan[0].Body.Get(k); !ok {
			t.Fatalf("%s dropped", k)
		}
	}
	for _, k := range []string{"provenance", "type", "content"} {
		_, err := PlanPublish(PublishInput{Spec: s, Result: res, Disclosures: map[string]map[string]canon.Value{"o1": {k: canon.String("x")}}})
		if err == nil {
			t.Fatalf("%s supplied on the command line", k)
		}
	}
}

// TestAcquisitionEmitsObserved: C-exec-14, the run half. A `network: required` workflow emits `observed` only
// (decided 2), with the capture record filled from the run and a multi-request capture pinned as one request log;
// it joins no derivation group. The comparison of two captures is a `network: none` workflow: it runs with no
// network, and a step that opens a connection fails inside the sandbox (`failed`, never match).
func TestAcquisitionEmitsObserved(t *testing.T) {
	conformance.Partial(t, "C-exec-14", "the corroborates emission and a real refused connection: the corroboration slice and the OCI backend (network none)")
	specBytes := specB("acq", nil, "network", object("required", strings2array([]string{"https://api.example/v1/settlements"})),
		"outputs", object("data", canon.String("data.json"), "log", canon.String("requests.jsonl")))
	s := mustSpec(t, specBytes)
	f := newFake().step("acq", func(_ context.Context, _, out string, _ map[string]string) (int, Resources) {
		os.WriteFile(filepath.Join(out, "data.json"), []byte(`{"period":"2026-09"}`), 0o644)
		os.WriteFile(filepath.Join(out, "requests.jsonl"), []byte("r1\nr2\n"), 0o644)
		return 0, Resources{CapMemory: 1}
	})
	pol := grantAll()
	if _, err := Execute(context.Background(), pol, f, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobsFor(s, "acq", nil)}); err == nil {
		t.Fatal("network without a grant must refuse")
	}
	pol.Network = []string{s.Digest}
	res, err := Execute(context.Background(), pol, f, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobsFor(s, "acq", nil)})
	if err != nil || len(f.Jobs[0].Network) != 1 {
		t.Fatal(err)
	}
	plan, err := PlanPublish(PublishInput{Spec: s, Result: res, CaptureAt: "2026-10-16T05:00:00Z", WindowFrom: "2026-10-16T04:59:00Z", WindowTo: "2026-10-16T05:00:00Z",
		RequestLog: &RequestLog{Output: "log", Format: "jsonl-v1", Count: 2}})
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld(t)
	for _, pl := range plan {
		if pl.Kind != "observed" {
			t.Fatalf("acquisition emitted %s", pl.Kind)
		}
		body := string(canon.Encode(pl.Body))
		has(t, body, `"class":"source"`)
		has(t, body, `"count":2`)
		has(t, body, `"endpoints":["https://api.example/v1/settlements"]`)
		hasNot(t, body, `"provenance"`)
		w.sign("O1", "observed", pl.Body)
	}
	d, _ := res.Output("data")
	if a := w.resolver().Artifact(d.Digest); a.Group != nil || a.Step.Why != "observation (not a tier)" {
		t.Fatalf("%s", a.Render())
	}
	// the comparison workflow: network none, so the runner gets no network; a step that tries fails
	cmpSpec := mustSpec(t, specB("cmp2", nil))
	f2 := newFake().step("cmp2", func(_ context.Context, _, _ string, _ map[string]string) (int, Resources) {
		return 1, Resources{CapMemory: 1} // connect(2) fails with no network: the step exits non-zero
	})
	r2, err := Execute(context.Background(), pol, f2, Invocation{Request: Request{Spec: cmpSpec, Signer: ownerKey}, Blobs: blobsFor(cmpSpec, "cmp2", nil)})
	if err != nil || f2.Jobs[0].Network != nil || r2.Token.Kind != FailedExit {
		t.Fatalf("%v %v %s", err, f2.Jobs[0].Network, r2.Token)
	}
	_ = keylog.Short
}
