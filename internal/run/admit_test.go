package run

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
)

// TestRuntimeUnavailable: C-exec-06. The sandbox runtime is unreachable: `run` refuses, operational class named,
// and the process audit (the runner's spawn count, and a native runner that would have been the fallback) shows
// nothing was spawned. No fallback in either direction.
func TestRuntimeUnavailable(t *testing.T) {
	conformance.Covers(t, "C-exec-06")
	s := mustSpec(t, specB("s", nil))
	sb := newFake().step("s", writeStep("x"))
	sb.Down = errors.New("cannot connect to the container runtime socket")
	native := newFake().step("s", writeStep("x"))
	native.Prof = Native
	p := grantAll()
	p.Own, p.NativeAll = []string{ownerKey}, true // even a reader allowed native gets no fallback
	_, err := Execute(context.Background(), p, sb, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobsFor(s, "s", nil)})
	r := wantRefusal(t, err, refusal.Operational, ReasonRuntime, "nothing was spawned", "cannot connect")
	if sb.Spawned != 0 || native.Spawned != 0 {
		t.Fatalf("spawned: sandbox %d native %d", sb.Spawned, native.Spawned)
	}
	// a native runner handed to a sandbox invocation is not used either: the profile is never changed
	_, err = Execute(context.Background(), p, native, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobsFor(s, "s", nil)})
	wantRefusal(t, err, refusal.Operational, ReasonRuntime)
	if native.Spawned != 0 {
		t.Fatal("a sandbox invocation ran on the native runner")
	}
	_ = r
}

// TestAdmissionIsNotTrust: C-exec-07. A workflow signed by a key at the reader's highest trust level, with no
// execution grant, is refused under `reader policy: executable admission`; the trust level is shown beside the
// missing grant and is not permission; the blob stays held (nothing is deleted or quarantined); with a grant,
// execution runs sandboxed.
func TestAdmissionIsNotTrust(t *testing.T) {
	conformance.Covers(t, "C-exec-07")
	specBytes := specB("s", nil)
	s := mustSpec(t, specBytes)
	f := newFake().step("s", writeStep("x"))
	held := map[string][]byte{s.Digest: specBytes}
	p := &Policy{Ceiling: grantAll().Ceiling}
	_, err := Execute(context.Background(), p, f, Invocation{Request: Request{Spec: s, Signer: ownerKey, TrustShown: "highest (hub-endorsed)"}, Blobs: blobsFor(s, "s", nil)})
	wantRefusal(t, err, refusal.Policy, ReasonAdmission, "trust level highest (hub-endorsed)", "trust is not permission", "signer "+ownerKey)
	if f.Spawned != 0 {
		t.Fatal("spawned without a grant")
	}
	if b := held[s.Digest]; Digest(b) != s.Digest {
		t.Fatal("the blob must remain held and verifiable")
	}
	for _, grant := range []*Policy{{ExecSigners: []string{ownerKey}}, {ExecWorkflows: []string{s.Digest}}} {
		grant.Ceiling = p.Ceiling
		res, err := Execute(context.Background(), grant, f, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobsFor(s, "s", nil)})
		if err != nil || res.Record.Profile != Sandbox || !strings.HasPrefix(res.Record.Boundary, "sandbox:") {
			t.Fatalf("granted: %v %+v", err, res)
		}
	}
	// a grant for another workflow hash or another key grants nothing
	_, err = (&Policy{ExecWorkflows: []string{Digest([]byte("other"))}, ExecSigners: []string{"B"}}).Admit(Request{Spec: s, Signer: ownerKey})
	wantRefusal(t, err, refusal.Policy, ReasonAdmission)
}

// TestNativeConditions: §2.4. native needs the profile named, the author key the reader's own, and a native
// grant; failing any one refuses under reader policy naming the condition. The default is sandbox.
func TestNativeConditions(t *testing.T) {
	s := mustSpec(t, specB("s", nil))
	base := func() *Policy { p := grantAll(); p.ExecSigners = append(p.ExecSigners, "B"); return p }
	p := base()
	p.Own = []string{"B"}
	p.NativeAll = true
	_, err := p.Admit(Request{Spec: s, Signer: ownerKey, Profile: Native})
	wantRefusal(t, err, refusal.Policy, ReasonNative, "not one of the reader's own keys")
	p = base()
	p.Own = []string{ownerKey}
	_, err = p.Admit(Request{Spec: s, Signer: ownerKey, Profile: Native})
	wantRefusal(t, err, refusal.Policy, ReasonNative, "no native grant")
	p.NativeWorkflows = []string{s.Digest}
	if a, err := p.Admit(Request{Spec: s, Signer: ownerKey, Profile: Native}); err != nil || a.Profile != Native {
		t.Fatalf("%v %+v", err, a)
	}
	if a, _ := p.Admit(Request{Spec: s, Signer: ownerKey}); a.Profile != Sandbox {
		t.Fatal("the default profile is sandbox")
	}
	_, err = p.Admit(Request{Spec: s, Signer: ownerKey, Profile: "vm"})
	wantRefusal(t, err, refusal.Policy, ReasonProfile)
}

// TestNetworkAndImages: §2.1. `required` needs a grant naming the workflow hash; an allowlist is digest-pinned
// and fails closed.
func TestNetworkAndImages(t *testing.T) {
	s := mustSpec(t, specB("s", nil, "network", object("required", strings2array([]string{"https://api.example/v1"}))))
	p := grantAll()
	_, err := p.Admit(Request{Spec: s, Signer: ownerKey})
	wantRefusal(t, err, refusal.Policy, ReasonNetwork, "https://api.example/v1")
	p.Network = []string{s.Digest}
	if a, err := p.Admit(Request{Spec: s, Signer: ownerKey}); err != nil || len(a.Network) != 1 {
		t.Fatalf("%v %+v", err, a)
	}
	s2 := mustSpec(t, specB("s", nil))
	p.Images = []string{"registry.example/step:1"}
	_, err = p.Admit(Request{Spec: s2, Signer: ownerKey})
	wantRefusal(t, err, refusal.Operational, ReasonImageList, "fails closed")
	p.Images = []string{Digest([]byte("other"))}
	_, err = p.Admit(Request{Spec: s2, Signer: ownerKey})
	wantRefusal(t, err, refusal.Policy, ReasonImageList)
	p.Images = []string{imgDigest}
	if _, err := p.Admit(Request{Spec: s2, Signer: ownerKey}); err != nil {
		t.Fatal(err)
	}
}

// TestImageDigestChecked: §1 rule 4. The digest the runtime resolves for the pinned image must be the pinned one;
// otherwise the run is refused (intrinsic: hash mismatch) before anything is staged.
func TestImageDigestChecked(t *testing.T) {
	s := mustSpec(t, specB("s", nil))
	f := &lyingImages{Fake: newFake().step("s", writeStep("x"))}
	_, err := Execute(context.Background(), grantAll(), f, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobsFor(s, "s", nil)})
	wantRefusal(t, err, refusal.Intrinsic, ReasonImageDigest, "is not the pinned")
	if f.Spawned != 0 {
		t.Fatal("staged after a digest mismatch")
	}
}

type lyingImages struct{ *Fake }

func (l *lyingImages) Image(context.Context, Image) (string, string, error) {
	return Digest([]byte("something else")), platAmd, nil
}

// TestCapsFromProfileAndCeiling: §2.2 as a pure function. Spec values at or under the ceiling are used; over the
// ceiling refuses naming both numbers; with the opt-in the ceiling is in force and the declared value recorded;
// an undeclared cap runs at the ceiling and is listed.
func TestCapsFromProfileAndCeiling(t *testing.T) {
	ceil := Resources{CapMemory: 100, CapWallTime: 1000, CapPids: 10}
	caps, decl, und, err := Caps(Resources{CapMemory: 50, CapWallTime: 1000}, ceil, false)
	if err != nil || caps[CapMemory] != 50 || caps[CapWallTime] != 1000 || caps[CapPids] != 10 || decl != nil {
		t.Fatalf("%v %v %v", caps, decl, err)
	}
	if strings.Join(und, ",") != "cpus,pids,disk" {
		t.Fatalf("undeclared %v", und)
	}
	_, _, _, err = Caps(Resources{CapMemory: 500, CapPids: 20}, ceil, false)
	wantRefusal(t, err, refusal.Policy, ReasonResources, "memory: the spec declares 500, the reader's ceiling is 100", "pids: the spec declares 20, the reader's ceiling is 10")
	caps, decl, _, err = Caps(Resources{CapMemory: 500}, ceil, true)
	if err != nil || caps[CapMemory] != 100 || decl[CapMemory] != 500 || len(decl) != 1 {
		t.Fatalf("%v %v %v", caps, decl, err)
	}
}

// TestBelowDeclaredProfile: C-exec-13b. A bytes workflow whose spec declares more memory than the reader's
// ceiling, with a pinned result. (a) without the opt-in: refused before staging (reader policy: resources), both
// values named, no run record; (b) with it, the step needs more than the ceiling: `failed: operational: memory
// (below declared profile)`, exit 3, the record shows the cap in force and the declared value, the next step
// names the declared value, nothing reads it as a workflow defect; (c) with it, the step fits: `match`, exit 0,
// the record shows the lowered cap beside the declared one.
func TestBelowDeclaredProfile(t *testing.T) {
	conformance.Covers(t, "C-exec-13b")
	data := []byte("input")
	specBytes := specB("s", map[string]string{"in": Digest(data)}, "resources", object("memory", canon.Int(8000), "wall_time", canon.Int(1000)))
	s := mustSpec(t, specBytes)
	p := grantAll()
	p.Ceiling[CapMemory] = 4000
	pinned := Digest([]byte("input"))
	pinRec := sandboxRecord()
	pin := Pin{Mode: "bytes", Env: Fields(pinRec.Object()), Digest: pinned}
	inv := func(below bool) Invocation {
		return Invocation{Request: Request{Spec: s, Signer: ownerKey, BelowProfile: below}, Blobs: blobsFor(s, "s", map[string][]byte{"in": data})}
	}

	// (a)
	f := newFake().step("s", catStep("in"))
	res, _, err := Rerun(context.Background(), p, f, inv(false), pin, nil)
	wantRefusal(t, err, refusal.Policy, ReasonResources, "8000", "4000")
	if res != nil || f.Spawned != 0 {
		t.Fatal("(a) a run record was written or the step started")
	}

	// (b)
	f = newFake().step("s", useStep(Resources{CapMemory: 6000, CapWallTime: 10}))
	res, d, err := Rerun(context.Background(), p, f, inv(true), pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.Jobs[0].Caps[CapMemory] != 4000 {
		t.Fatalf("(b) cap in force %d", f.Jobs[0].Caps[CapMemory])
	}
	if d.Token.String() != "failed: operational: memory (below declared profile)" || d.Token.Exit() != 3 {
		t.Fatalf("(b) %s", d.Token)
	}
	caps := string(canon.Encode(res.Record.Object().Members["caps"]))
	has(t, caps, `"declared":{"memory":8000}`)
	has(t, caps, `"memory":4000`)
	ex := strings.Join(d.Explain, "\n")
	has(t, ex, "run where the declared memory of 8000 is available")
	has(t, ex, "not evidence of a workflow defect")
	hasNot(t, ex, "determinism claim may be weaker")
	if _, err := PlanPublish(PublishInput{Spec: s, Result: res}); err == nil {
		t.Fatal("(b) a stopped run published")
	}

	// (c)
	f = newFake().step("s", catStep("in"))
	res, d, err = Rerun(context.Background(), p, f, inv(true), pin, nil)
	if err != nil || d.Token.Kind != Match || d.Token.Exit() != 0 {
		t.Fatalf("(c) %v %s %v", err, d.Token, d.Explain)
	}
	caps = string(canon.Encode(res.Record.Object().Members["caps"]))
	has(t, caps, `"declared":{"memory":8000}`)
	if res.Record.Result != "match" {
		t.Fatalf("(c) record result %s", res.Record.Result)
	}
}
