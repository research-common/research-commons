package run

import (
	"context"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/resolve"
)

// pinned is a world in which A authored output X of a bytes workflow, with an environment record, through a real
// run on the fake: the fixture every re-run test starts from.
type pinned struct {
	w         *world
	spec      *Spec
	specBytes []byte
	data      []byte
	authored  string
	output    OutputBlob
	pin       Pin
}

func newPinned(t *testing.T, mode, comparator string, extra ...any) *pinned {
	t.Helper()
	data := []byte("input-v1")
	specBytes := specB("s", map[string]string{"in": Digest(data)})
	s := mustSpec(t, specBytes)
	w := newWorld(t)
	w.workflow(ownerKey, specBytes, mode, comparator, extra...)
	f := newFake().step("s", catStep("in"))
	res, err := Execute(context.Background(), grantAll(), f, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobsFor(s, "s", map[string][]byte{"in": data})})
	if err != nil || !res.Completed() {
		t.Fatalf("first run: %v %+v", err, res)
	}
	plan, err := PlanPublish(PublishInput{Spec: s, Result: res, Mode: mode, Comparator: comparator})
	if err != nil || len(plan) != 1 || plan[0].Kind != "authored" {
		t.Fatalf("first publish: %v %+v", err, plan)
	}
	ids := w.publish(ownerKey, plan)
	return &pinned{w: w, spec: s, specBytes: specBytes, data: data, authored: ids["result"], output: res.Outputs[0],
		pin: Pin{Mode: mode, Comparator: comparator, Env: Fields(res.Record.Object()), Digest: res.Outputs[0].Digest}}
}

func (p *pinned) inv(data []byte) Invocation {
	return Invocation{Request: Request{Spec: p.spec, Signer: ownerKey}, Blobs: blobsFor(p.spec, "s", map[string][]byte{"in": data})}
}

// statementOnly is the resolver's answer before any re-run, and the rendering the re-run must leave unchanged.
func (p *pinned) statementOnly(t *testing.T) (int, []string, string) {
	a := p.w.resolver().Artifact(p.output.Digest)
	code, why := a.VerifyExit()
	return code, why, a.Render()
}

// TestRerunEnvironmentAndDivergence: C-exec-13. (a) a re-run in an environment whose record differs from the pin
// on a field environment_match names: exit 5 with the field named, nothing compared; (b) a re-run in the pinned
// environment producing different bytes (the input mutated, so the test knows which): exit 1, `diverged`. In both,
// the earlier `authored` stays visible and unchanged (the resolver's view of the held set is byte-identical
// before and after).
func TestRerunEnvironmentAndDivergence(t *testing.T) {
	conformance.Covers(t, "C-exec-13")
	p := newPinned(t, "bytes", "")
	code0, why0, before := p.statementOnly(t)
	if code0 != 3 || !strings.Contains(strings.Join(why0, ";"), "not re-derived") {
		t.Fatalf("statement-only verify of a sole derivation: %d %v (decision A4: 3, not re-derived)", code0, why0)
	}

	// (a): the same image digest is held for another platform by this runtime
	f := newFake().step("s", catStep("in"))
	f.Images[imgDigest] = platArm
	res, d, err := Rerun(context.Background(), grantAll(), f, p.inv(p.data), p.pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Token.String() != "environment mismatch: platform" || d.Token.Exit() != 5 || f.Spawned != 1 {
		t.Fatalf("(a) %s %d", d.Token, f.Spawned)
	}
	has(t, strings.Join(d.Explain, "\n"), "not compared (environment mismatch)")
	if res.Outputs[0].Digest != p.output.Digest {
		t.Fatal("(a) the mutation must be the environment only (same bytes produced)")
	}
	if code, why := VerifyWithRerun(code0, why0, d.Token); code != 5 || !strings.Contains(why[0], "platform") {
		t.Fatalf("(a) verify %d %v", code, why)
	}

	// (b)
	f = newFake().step("s", catStep("in"))
	_, d, err = Rerun(context.Background(), grantAll(), f, p.inv([]byte("input-v1")), p.pin, nil)
	if err != nil || d.Token.Kind != Match {
		t.Fatalf("(b) control, same input: %v %s", err, d.Token)
	}
	mut := p.inv([]byte("input-v2"))
	mut.Blobs[Digest([]byte("input-v1"))] = []byte("input-v2") // the held bytes for the pinned digest are wrong
	if _, _, err := Rerun(context.Background(), grantAll(), f, mut, p.pin, nil); err == nil {
		t.Fatal("a staged input that does not hash to its pin must refuse before the step")
	}
	// mutate the step instead (a nondeterministic or environment-dependent step), environment unchanged
	f = newFake().step("s", writeStep("other bytes"))
	_, d, err = Rerun(context.Background(), grantAll(), f, p.inv(p.data), p.pin, nil)
	if err != nil || d.Token.Kind != Diverged || d.Token.Exit() != 1 {
		t.Fatalf("(b) %v %s", err, d.Token)
	}
	has(t, strings.Join(d.Explain, "\n"), "the earlier statement is unchanged")
	if code, _ := VerifyWithRerun(code0, why0, d.Token); code != 1 {
		t.Fatalf("(b) verify %d", code)
	}
	if _, _, after := p.statementOnly(t); after != before {
		t.Fatalf("the held view changed:\n%s\nvs\n%s", after, before)
	}
}

// TestRerunExit3Versus5: C-exec-13a. (a) the pinned image is not available: exit 5 naming the environment, nothing
// spawned; (b) in the pinned environment under a reader wall-time limit lower than the step needs, the spec's
// declared wall_time within that limit (an under-declaring spec): `timeout`, exit 3; (c) the same with memory:
// `failed: operational: memory`, exit 3. Each names its next step.
func TestRerunExit3Versus5(t *testing.T) {
	conformance.Covers(t, "C-exec-13a")
	p := newPinned(t, "bytes", "")
	// (a)
	f := newFake().step("s", catStep("in"))
	delete(f.Images, imgDigest)
	res, d, err := Rerun(context.Background(), grantAll(), f, p.inv(p.data), p.pin, nil)
	if err != nil || d.Token.Exit() != 5 || !strings.Contains(d.Token.String(), "image_digest") || f.Spawned != 0 || res.Record != nil {
		t.Fatalf("(a) %v %s spawned %d", err, d.Token, f.Spawned)
	}
	has(t, strings.Join(d.Explain, "\n"), "run where the pinned environment exists")

	// the spec declares wall_time 10000 and memory 1 MiB; the reader's ceilings are those values, and the step
	// needs more of each than it declared
	pol := grantAll()
	pol.Ceiling[CapWallTime], pol.Ceiling[CapMemory] = 10_000, 1<<20
	for _, c := range []struct {
		use        Resources
		want, kill string
	}{
		{Resources{CapWallTime: 50_000, CapMemory: 10}, "timeout", "killed: wall_time"},
		{Resources{CapWallTime: 10, CapMemory: 4 << 20}, "failed: operational: memory", "killed: memory"},
	} {
		f := newFake().step("s", useStep(c.use))
		res, d, err := Rerun(context.Background(), pol, f, p.inv(p.data), p.pin, nil)
		if err != nil || d.Token.String() != c.want || d.Token.Exit() != 3 {
			t.Fatalf("%s: %v %s", c.want, err, d.Token)
		}
		if res.Record == nil || res.Record.ExitStatus != c.kill {
			t.Fatalf("record exit %q", res.Record.ExitStatus)
		}
		ex := strings.Join(d.Explain, "\n")
		has(t, ex, "raise the limit")
		has(t, ex, "resources used up to the kill")
		if len(res.Outputs) != 0 {
			t.Fatal("output read back after a cap tripped")
		}
	}
}

// TestFailedStepIsNotDivergence: C-exec-15. In an environment matching the pin: (a) the step exits non-zero:
// `failed: exit n`, exit 3; (b) it exits 0 with a declared output missing: `incomplete output`, exit 3; (c)
// control: completes with different bytes: `diverged`, exit 1. In (a) and (b) nothing is compared, explain says
// the determinism claim may be weaker and the pinned bytes are not shown wrong, the earlier `authored` is
// unchanged and nothing is emitted on the author's behalf.
func TestFailedStepIsNotDivergence(t *testing.T) {
	conformance.Covers(t, "C-exec-15")
	p := newPinned(t, "bytes", "")
	code0, why0, before := p.statementOnly(t)
	cases := []struct {
		name string
		step Step
		tok  string
		exit int
	}{
		{"a", func(context.Context, string, string, map[string]string) (int, Resources) {
			return 7, Resources{CapMemory: 1}
		}, "failed: exit 7", 3},
		{"b", func(context.Context, string, string, map[string]string) (int, Resources) {
			return 0, Resources{CapMemory: 1}
		}, "incomplete output", 3},
		{"c", writeStep("different"), "diverged", 1},
	}
	for _, c := range cases {
		f := newFake().step("s", c.step)
		res, d, err := Rerun(context.Background(), grantAll(), f, p.inv(p.data), p.pin, nil)
		if err != nil || d.Token.String() != c.tok || d.Token.Exit() != c.exit {
			t.Fatalf("(%s) %v %s", c.name, err, d.Token)
		}
		if d.Mismatch.Mismatched() {
			t.Fatalf("(%s) the environment must match the pin", c.name)
		}
		ex := strings.Join(d.Explain, "\n")
		if c.exit == 3 {
			has(t, ex, "determinism claim may be weaker than declared")
			has(t, ex, "the pinned bytes are not shown wrong")
			has(t, ex, "no statement is changed or emitted on the author's behalf")
			if _, err := PlanPublish(PublishInput{Spec: p.spec, Result: res, Own: []HeldAuthored{{p.authored, p.output.Digest}}, Mode: "bytes"}); err == nil {
				t.Fatalf("(%s) a statement was planned", c.name)
			}
		}
		if code, _ := VerifyWithRerun(code0, why0, d.Token); code != c.exit {
			t.Fatalf("(%s) verify %d", c.name, code)
		}
	}
	if _, _, after := p.statementOnly(t); after != before {
		t.Fatal("the held view changed")
	}
}

// TestTimeoutCleansUp: C-exec-11 (decision layer). A step past the wall-time cap: token `timeout`, verify exit 3
// (not 5), resources used recorded, staging removed, the runner's cleanup check recorded, and no `reproduced`
// emitted. That the container and a leftover child are really gone needs a real runtime (sandbox_oci_test.go).
func TestTimeoutCleansUp(t *testing.T) {
	conformance.Partial(t, "C-exec-11", "container and leftover child killed: checked by the OCI backend test under the sandbox_oci build tag; the fake only reports it")
	p := newPinned(t, "bytes", "")
	pol := grantAll()
	pol.Ceiling[CapWallTime] = 100
	f := newFake().step("s", useStep(Resources{CapWallTime: 1_000_000, CapMemory: 1}))
	staging := t.TempDir()
	inv := p.inv(p.data)
	inv.StagingRoot = staging
	res, d, err := Rerun(context.Background(), pol, f, inv, Pin{Mode: "bytes", Env: p.pin.Env, Digest: p.pin.Digest}, nil)
	if err == nil {
		t.Fatal("the spec declares 10000 ms and the ceiling is 100: refuse without the opt-in")
	}
	inv.BelowProfile = true
	res, d, err = Rerun(context.Background(), pol, f, inv, p.pin, nil)
	if err != nil || d.Token.Kind != Timeout || d.Token.Exit() != 3 {
		t.Fatalf("%v %s", err, d.Token)
	}
	if !res.StagingRemoved || res.Record.WallTimeMs != 100 || !strings.HasPrefix(res.Record.Cleanup, "ok") {
		t.Fatalf("%+v", res.Record)
	}
	plan, err := PlanPublish(PublishInput{Spec: p.spec, Result: res, Own: []HeldAuthored{{p.authored, p.output.Digest}}, Mode: "bytes"})
	if err == nil || plan != nil {
		t.Fatal("a reproduced was planned after a timeout")
	}
}

// TestCapsDuringExecution: C-exec-10 (decision layer). pids and disk caps stop the step (`failed: operational:
// <cap>`), nothing reads as match, no partial output is published. Stopping it while running and the absence of
// the recorded PIDs afterwards are the OCI backend's (sandbox_oci_test.go).
func TestCapsDuringExecution(t *testing.T) {
	conformance.Partial(t, "C-exec-10", "kernel caps tripping during execution and recorded PIDs gone afterwards: the OCI backend test under the sandbox_oci build tag")
	p := newPinned(t, "bytes", "")
	for _, c := range []struct {
		use Resources
		cap string
	}{{Resources{CapPids: 100_000, CapMemory: 1}, CapPids}, {Resources{CapDisk: 1 << 40, CapMemory: 1}, CapDisk}} {
		f := newFake().step("s", useStep(c.use))
		res, d, err := Rerun(context.Background(), grantAll(), f, p.inv(p.data), p.pin, nil)
		if err != nil || d.Token.String() != "failed: operational: "+c.cap || len(res.Outputs) != 0 {
			t.Fatalf("%s: %v %s", c.cap, err, d.Token)
		}
		if _, err := PlanPublish(PublishInput{Spec: p.spec, Result: res}); err == nil {
			t.Fatal("published after a cap")
		}
	}
}

// TestRerunFeedsResolver: how a re-run reaches the grade path (decisions A4, A5, A13). The reader's own re-run
// replaces the statement-only `not re-derived` (exit 3) with its token; publishing it as a `reproduced` makes it a
// run in the group, graded by the reader's comparison of bytes (T0 under bytes), the runner's signed token and
// environment shown beside, never graded, with the trust line `not configured`.
func TestRerunFeedsResolver(t *testing.T) {
	p := newPinned(t, "bytes", "")
	code0, why0, _ := p.statementOnly(t)
	f := newFake().step("s", catStep("in"))
	res, d, err := Rerun(context.Background(), grantAll(), f, p.inv(p.data), p.pin, nil)
	if err != nil || d.Token.Kind != Match {
		t.Fatal(err, d.Token)
	}
	if code, why := VerifyWithRerun(code0, why0, d.Token); code != 0 || len(why) != 0 {
		t.Fatalf("verify with the reader's own re-run: %d %v", code, why)
	}
	// other causes stay: a contested field is not a derivation cause
	if code, why := VerifyWithRerun(3, []string{"field licence: contested", "derivation: not re-derived"}, d.Token); code != 3 || len(why) != 1 {
		t.Fatalf("%d %v", code, why)
	}
	plan, err := PlanPublish(PublishInput{Spec: p.spec, Result: res, Own: []HeldAuthored{{p.authored, p.output.Digest}}, Mode: "bytes"})
	if err != nil || len(plan) != 1 || plan[0].Kind != "reproduced" {
		t.Fatalf("%v %+v", err, plan)
	}
	p.w.publish(ownerKey, plan)
	a := p.w.resolver().Artifact(p.output.Digest)
	if a.Step.Tier != "T0" {
		t.Fatalf("%s", a.Render())
	}
	out := a.Render()
	has(t, out, "runner says: match")
	has(t, out, "environment (runner's record):")
	has(t, out, `"profile":"sandbox"`)
	has(t, out, "your trust in this key: not configured")
	has(t, out, "re-derived by its author only")
	if code, _ := a.VerifyExit(); code != 0 {
		t.Fatalf("verify %d", code)
	}
}

// TestComparatorRunnerFeedsResolver: a protocol workflow's comparator runs as a sandboxed workflow through the
// same Execute path, and that runner is the resolver's Comparator (resolve.WithComparator): T1 under the
// comparator; with no grant for the comparator, `unchecked` with the reason. A comparator whose `authored` does
// not declare `replication: bytes` (another mode, or no declaration held) is not run: `unchecked`, with the reason
// (execution §5.3, the comparator interface).
func TestComparatorRunnerFeedsResolver(t *testing.T) {
	cmpSpecBytes := specB("cmp", map[string]string{"a": Digest([]byte("pa")), "b": Digest([]byte("pb"))},
		"outputs", object("verdict", canon.String("verdict")))
	cmpSpec := mustSpec(t, cmpSpecBytes)
	k := cmpSpec.Digest
	data := []byte("input")
	specBytes := specB("s", map[string]string{"in": Digest(data)})
	w := newWorld(t)
	w.workflow(ownerKey, specBytes, "protocol", k)
	prov := object("workflow", canon.String(Digest(specBytes)), "inputs", strings2array([]string{Digest(data)}))
	x, y := []byte("1.000\n"), []byte("1.0001\n")
	content := func(b []byte) *canon.Object {
		return object("digest", canon.String(Digest(b)), "size", canon.Int(int64(len(b))))
	}
	w.sign(ownerKey, "authored", object("content", content(x), "type", canon.String("dataset"), "provenance", prov))
	w.sign("B", "authored", object("content", content(y), "type", canon.String("dataset"), "provenance", prov))

	f := newFake().step("cmp", func(_ context.Context, in, out string, _ map[string]string) (int, Resources) {
		return writeStep("match\n")(context.Background(), in, out, nil)
	})
	f.Steps[Digest([]byte("code:cmp"))] = func(ctx context.Context, in, out string, env map[string]string) (int, Resources) {
		// a tolerance comparator over one number per file
		a, _ := readFile(in, "a")
		b, _ := readFile(in, "b")
		v := "diverged"
		if strings.HasPrefix(a, "1.000") && strings.HasPrefix(b, "1.000") {
			v = "match"
		}
		return 0, writeOut(out, "verdict", v)
	}
	cr := &ComparatorRunner{Policy: grantAll(), Runner: f, Specs: map[string][]byte{k: cmpSpecBytes}, Signers: map[string]string{k: ownerKey},
		Blobs: map[string][]byte{cmpSpec.Code: []byte("code:cmp"), Digest(x): x, Digest(y): y}}
	for _, mode := range []string{"", "protocol", "none"} {
		cr.Replication = map[string]string{k: mode}
		a := w.resolver(resolve.WithComparator(cr)).Artifact(Digest(x))
		if a.Step.Why != resolve.UncheckedToken || f.Spawned != 0 {
			t.Fatalf("comparator declaring %q: spawned %d\n%s", mode, f.Spawned, a.Render())
		}
		has(t, a.Render(), "a comparator must declare replication: bytes")
	}
	cr.Replication = map[string]string{k: "bytes"}
	a := w.resolver(resolve.WithComparator(cr)).Artifact(Digest(x))
	if a.Step.Tier != "T1" || a.Step.Under != k {
		t.Fatalf("%s", a.Render())
	}
	if f.Spawned != 1 {
		t.Fatalf("comparator runs %d; the resolver asks each pair once", f.Spawned)
	}
	cr.Policy = &Policy{Ceiling: grantAll().Ceiling}
	a = w.resolver(resolve.WithComparator(cr)).Artifact(Digest(x))
	if a.Step.Why != resolve.UncheckedToken {
		t.Fatalf("%s", a.Render())
	}
	has(t, a.Render(), "executable admission")
	_ = keylog.Short
}
