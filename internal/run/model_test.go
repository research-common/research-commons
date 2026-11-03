package run

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// TestTokenTableIsTheNote: the token vocabulary and its exits are one table, checked row by row against the
// execution note §5.2 (C-core-133: "the documented table is generated from the same source as the code").
func TestTokenTableIsTheNote(t *testing.T) {
	conformance.Partial(t, "C-core-133", "run-token exits match the note's table; the statement-only fixtures (contested, unknown) and a CLI exit are the resolver's and the CLI slice's")
	root, err := conformance.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join(root, "docs", "DESIGN-notes-execution.md"))
	if err != nil {
		t.Fatal(err)
	}
	sec := string(doc)
	sec = sec[strings.Index(sec, "### 5.2 Result tokens"):]
	sec = sec[:strings.Index(sec, "Exit 1 is reserved")]
	row := regexp.MustCompile("(?m)^\\| `([^`]+)` \\| [^|]+ \\| ([0-9]) \\|$")
	var doc2 [][2]string
	for _, m := range row.FindAllStringSubmatch(sec, -1) {
		doc2 = append(doc2, [2]string{m[1], m[2]})
	}
	// the note's "… (below declared profile)" row is a suffix on two rows, not a kind of its own
	var code [][2]string
	for _, r := range TableRows() {
		if r[0] != string(NothingToRerun) {
			code = append(code, r)
		}
	}
	want := slices.DeleteFunc(doc2, func(r [2]string) bool { return strings.HasPrefix(r[0], "…") })
	if !slices.Equal(code, want) {
		t.Fatalf("code table %v\nnote table %v", code, want)
	}
	if NothingToRerun.Exit() != 4 {
		t.Fatal("nothing to re-run is exit 4 (claims §13)")
	}
}

func TestTokenStrings(t *testing.T) {
	for _, c := range []struct {
		tok  Token
		s    string
		exit int
	}{
		{Token{Kind: Match}, "match", 0},
		{Token{Kind: Match, Identical: true}, "match (identical bytes)", 0},
		{Token{Kind: Diverged}, "diverged", 1},
		{Token{Kind: FailedExit, ExitStatus: 7}, "failed: exit 7", 3},
		{Token{Kind: FailedCap, Cap: "memory"}, "failed: operational: memory", 3},
		{Token{Kind: FailedCap, Cap: "memory", Below: true}, "failed: operational: memory (below declared profile)", 3},
		{Token{Kind: Timeout, Below: true}, "timeout (below declared profile)", 3},
		{Token{Kind: IncompleteOutput}, "incomplete output", 3},
		{Token{Kind: EnvMismatch, Fields: []string{"platform"}}, "environment mismatch: platform", 5},
	} {
		if c.tok.String() != c.s || c.tok.Exit() != c.exit {
			t.Fatalf("%#v: %q exit %d, want %q exit %d", c.tok, c.tok.String(), c.tok.Exit(), c.s, c.exit)
		}
	}
	// only a completed comparison maps to a reproduced result; exit 1 only for diverged
	for _, k := range []Kind{Unchecked, IncompleteOutput, FailedExit, FailedCap, Timeout, EnvMismatch} {
		if (Token{Kind: k}).WireResult() != "" {
			t.Fatalf("%s maps to a reproduced result", k)
		}
		if (Token{Kind: k}).Exit() == 1 {
			t.Fatalf("%s exits 1; 1 is reserved for a completed comparison that disagreed", k)
		}
	}
}

// --- the spec (§1) -------------------------------------------------------------------------------------------

func TestSpecRefusesIncompletePins(t *testing.T) {
	for _, field := range []string{"code", "interpreter", "outputs"} {
		_, err := ParseSpec(specB("s", nil, field, nil))
		r := wantRefusal(t, err, refusal.Intrinsic, "malformed workflow", field)
		if !strings.Contains(r.Detail, "missing") {
			t.Fatalf("%s: %s", field, r.Detail)
		}
	}
	if _, err := ParseSpec(specB("s", nil, "image", object("reference", canon.String("x:latest")))); err == nil {
		t.Fatal("an image without a digest must be malformed (an image is pinned by reference and digest)")
	}
	if _, err := ParseSpec(specB("s", nil, "network", canon.String("some"))); err == nil {
		t.Fatal("network must be none or {required: [...]}")
	}
	// no image is admitted by the parser: sandbox refuses it at admission (reader policy: no image)
	s := mustSpec(t, specB("s", nil, "image", nil))
	_, err := grantAll().Admit(Request{Spec: s, Signer: ownerKey})
	wantRefusal(t, err, refusal.Policy, ReasonNoImage)
}

func TestSpecDisclosesUnpinnedAndIgnoresStatementFields(t *testing.T) {
	s := mustSpec(t, specB("s", map[string]string{"data": "registry.example/feed:latest", "table": Digest([]byte("t"))},
		"replication", canon.String("bytes"), "comparator", canon.String(Digest([]byte("k")))))
	if got := s.Unpinned(); len(got) != 1 || !strings.Contains(got[0], "data") || !strings.Contains(got[0], "feed:latest") {
		t.Fatalf("unpinned %v", got)
	}
	if got := s.InputDigests(); len(got) != 1 || got[0] != Digest([]byte("t")) {
		t.Fatalf("inputs %v", got)
	}
	d := strings.Join(s.IgnoredDisplay(), "; ")
	has(t, d, "replication: declared in spec body, ignored")
	has(t, d, "comparator: declared in spec body, ignored")
	if s.Acquisition() {
		t.Fatal("no network declared: not an acquisition")
	}
	if !mustSpec(t, specB("s", nil, "network", object("required", strings2array([]string{"https://api.example/v1"})))).Acquisition() {
		t.Fatal("network required: an acquisition")
	}
}

// --- the environment record (§4) -----------------------------------------------------------------------------

func sandboxRecord() *Record {
	rss := int64(4096)
	return &Record{Profile: Sandbox, ImageReference: imgRef, ImageDigest: imgDigest, Platform: platAmd,
		HarnessCommit: strings.Repeat("ab", 20), Runtime: "oci-runtime 1", Interpreter: "sh 5",
		Caps: Resources{CapMemory: 1 << 20}, Grants: []string{}, PeakRSS: &rss, WallTimeMs: 12, ExitStatus: "0",
		Result: "match", StagingCheck: "ok", Boundary: "sandbox: oci, image " + imgDigest}
}

// TestNetworkEnforcedDisclosure: execution §6. A granted network carries `enforced`: `all` when it was opened as
// a whole (the OCI runner, or a runner that does not say), `per-endpoint` when egress was limited to the declared
// endpoints; the display says which. `network: none` carries no `enforced`, and a record claiming one, or an
// unknown value, is refused by Validate.
func TestNetworkEnforcedDisclosure(t *testing.T) {
	r := sandboxRecord()
	if got := string(canon.Encode(r.Object().Members["network"])); got != `"none"` || r.NetworkLine() != "network none" {
		t.Fatalf("no network: %s / %s", got, r.NetworkLine())
	}
	r.Network, r.NetworkEnforced = []string{"https://api.example/v1"}, EnforcedAll
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := string(canon.Encode(r.Object().Members["network"])); got != `{"enforced":"all","granted":["https://api.example/v1"]}` {
		t.Fatalf("granted: %s", got)
	}
	has(t, r.NetworkLine(), "network granted (not limited to the declared endpoints)")
	r.NetworkEnforced = EnforcedPerEndpoint
	has(t, r.NetworkLine(), "network granted (limited to the declared endpoints)")
	for _, bad := range []struct {
		net []string
		enf string
	}{{nil, EnforcedAll}, {[]string{"https://x.example"}, ""}, {[]string{"https://x.example"}, "some"}} {
		b := sandboxRecord()
		b.Network, b.NetworkEnforced = bad.net, bad.enf
		if b.Validate() == nil {
			t.Fatalf("record accepted network %v enforced %q", bad.net, bad.enf)
		}
	}
	// through Execute: the fake runner does not say how it confined the network, so the record says `all`
	spec := mustSpec(t, specB("net", nil, "network", object("required", strings2array([]string{"https://api.example/v1"}))))
	f := newFake().step("net", writeStep("ok"))
	p := grantAll()
	p.Network = []string{spec.Digest}
	res, err := Execute(context.Background(), p, f, Invocation{Request: Request{Spec: spec, Signer: ownerKey}, Blobs: blobsFor(spec, "net", nil)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Record.NetworkEnforced != EnforcedAll || !strings.Contains(string(canon.Encode(res.Record.Object())), `"enforced":"all"`) {
		t.Fatalf("executed record: %s", canon.Encode(res.Record.Object()))
	}
	// and a run with no network records none, with no enforced member
	spec0 := mustSpec(t, specB("net0", nil))
	res0, err := Execute(context.Background(), p, newFake().step("net0", writeStep("ok")), Invocation{Request: Request{Spec: spec0, Signer: ownerKey}, Blobs: blobsFor(spec0, "net0", nil)})
	if err != nil || res0.Record.NetworkEnforced != "" || strings.Contains(string(canon.Encode(res0.Record.Object())), "enforced") {
		t.Fatalf("no-network record: %v %s", err, canon.Encode(res0.Record.Object()))
	}
}

// TestRecordRidesTheWireSchema: the record's object passes the one validation core as an `authored`
// provenance.environment and as a `reproduced` provenance.environment (wire §5), and its three wire members keep
// their standard forms; a malformed image_digest is refused by the wire gate itself.
func TestRecordRidesTheWireSchema(t *testing.T) {
	w := newWorld(t)
	env := sandboxRecord().Object()
	prov := object("workflow", canon.String(Digest([]byte("wf"))), "inputs", strings2array([]string{Digest([]byte("i"))}), "environment", env)
	content := object("digest", canon.String(Digest([]byte("X"))), "size", canon.Int(1))
	a := w.sign("A", "authored", object("content", content, "type", canon.String("dataset"), "provenance", prov))
	w.sign("A", "reproduced", object("of", canon.String(a), "result", canon.String("match"), "content", content, "provenance", prov))
	if err := sandboxRecord().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := sandboxRecord()
	bad.ImageDigest = "sha256:ABC"
	if err := bad.Validate(); err == nil {
		t.Fatal("record accepted a malformed image digest")
	}
	bo := bad.Object()
	badProv := object("workflow", canon.String(Digest([]byte("wf"))), "inputs", strings2array(nil), "environment", bo)
	line, _ := wire.Sign(wire.Draft{Kind: "authored", Seq: 0, TS: "2026-10-16T00:00:00Z",
		Body: object("content", content, "type", canon.String("dataset"), "provenance", badProv)}, w.key("Z"))
	if _, err := wire.Read(line); err == nil || !strings.Contains(err.Error(), "image_digest") {
		t.Fatalf("wire gate: %v", err)
	}
	for _, p := range []string{"linux/amd64", "linux/arm64/v8"} {
		r := sandboxRecord()
		r.Platform = p
		if r.Validate() != nil {
			t.Fatal(p)
		}
	}
	r := sandboxRecord()
	r.HarnessCommit = "abc1234"
	if r.Validate() == nil {
		t.Fatal("an abbreviated harness commit must be refused")
	}
}

// TestPeakRSS: C-exec-16. A sandbox run whose runner cannot read peak RSS is a conformance failure of the
// sandbox profile (no record is written with `unmeasured`); a native run's record carries `unmeasured`, never
// zero or the spec's number.
func TestPeakRSS(t *testing.T) {
	conformance.Covers(t, "C-exec-16")
	data := []byte("in")
	specBytes := specB("s", map[string]string{"in": Digest(data)})
	s := mustSpec(t, specBytes)
	f := newFake().step("s", writeStep("out"))
	f.NoRSS = true
	_, err := Execute(t.Context(), grantAll(), f, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobsFor(s, "s", map[string][]byte{"in": data})})
	if err != ErrSandboxUnmeasured {
		t.Fatalf("sandbox without peak RSS: %v", err)
	}
	if f.Spawned != 1 {
		t.Fatal("the mutation must reach the record (the step ran, the counter was unreadable)")
	}

	nf := newFake().step("s", writeStep("out"))
	nf.Prof, nf.NoRSS = Native, true
	p := grantAll()
	p.Own, p.NativeAll = []string{ownerKey}, true
	res, err := Execute(t.Context(), p, nf, Invocation{Request: Request{Spec: s, Signer: ownerKey, Profile: Native}, Blobs: blobsFor(s, "s", map[string][]byte{"in": data})})
	if err != nil {
		t.Fatal(err)
	}
	o := res.Record.Object()
	if got := string(canon.Encode(o.Members["peak_rss_bytes"])); got != `"unmeasured"` {
		t.Fatalf("native peak_rss_bytes %s", got)
	}
	if got := string(canon.Encode(o.Members["caps"])); !strings.Contains(got, `"advisory":true`) {
		t.Fatalf("native caps not advisory: %s", got)
	}
	// a sandbox record with unmeasured never validates
	r := sandboxRecord()
	r.PeakRSS = nil
	if r.Validate() != ErrSandboxUnmeasured {
		t.Fatal("sandbox record with unmeasured peak RSS validated")
	}
}

// TestEnvironmentMatch: the comparison of §4 and §8. Default for bytes is image digest + platform; a narrowed
// environment_match compares on bytes across platforms (no third token); unnamed fields are side by side; a
// native pin under sandbox exits 5 unless the reader accepts native records.
func TestEnvironmentMatch(t *testing.T) {
	pin := Fields(sandboxRecord().Object())
	arm := sandboxRecord()
	arm.Platform, arm.ImageDigest, arm.Runtime = platArm, Digest([]byte("image manifest arm64")), "oci-runtime 2"
	re := Fields(arm.Object())

	m := Compare(pin, re, DefaultMatch("bytes"), false)
	if !m.Mismatched() || m.Token().String() != "environment mismatch: image_digest, platform" || m.Token().Exit() != 5 {
		t.Fatalf("%+v", m)
	}
	if !slices.Contains(m.Side, "runtime") || slices.Contains(m.Side, "wall_time_ms") {
		t.Fatalf("side %v", m.Side)
	}
	if m := Compare(pin, re, []string{}, false); m.Mismatched() {
		t.Fatalf("narrowed environment_match: %+v", m)
	}
	if DefaultMatch("protocol") != nil || DefaultMatch("") != nil {
		t.Fatal("protocol and undeclared default to no fields")
	}
	// a pin with only the wire's three members compares on those
	slim := map[string]string{"image_digest": `"` + imgDigest + `"`, "platform": `"linux/amd64"`}
	if m := Compare(slim, pin, DefaultMatch("bytes"), false); m.Mismatched() {
		t.Fatalf("slim pin: %+v", m)
	}
	// a field the re-run lacks is a difference when named
	if m := Compare(pin, map[string]string{"platform": `"linux/amd64"`}, DefaultMatch("bytes"), false); !m.Mismatched() || m.Fields[0] != "image_digest" {
		t.Fatalf("%+v", m)
	}
	nat := sandboxRecord()
	nat.Profile, nat.ImageDigest, nat.ImageReference, nat.Advisory = Native, "", "", true
	np := Fields(nat.Object())
	m = Compare(np, pin, []string{"platform"}, false)
	if !m.Mismatched() || m.Token().String() != "environment mismatch: profile native ≠ sandbox" {
		t.Fatalf("%+v %s", m, m.Token())
	}
	m = Compare(np, pin, []string{"platform"}, true)
	if m.Mismatched() || m.Profile == "" {
		t.Fatalf("accepted native: %+v", m)
	}
}
