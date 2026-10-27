package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/wire"
)

// readerPolicyDoc is a reader-policy-v1 document trusting keys for admission over any content.
func readerPolicyDoc(keys ...string) string {
	if len(keys) == 0 {
		return `{"version":"reader-policy-v1","selections":[],"trust":[]}`
	}
	var es []string
	for _, k := range keys {
		es = append(es, `{"principal":{"key":"`+k+`"},"purposes":["admission"],"targets":{"any_content":true}}`)
	}
	return `{"version":"reader-policy-v1","selections":[],"trust":[` + strings.Join(es, ",") + `]}`
}

// TestReaderPolicy: one hub-policy parser (gate.ParseHubPolicy) and the reader policy (--policy, else
// $COMMONS_POLICY) checked before any work; explain prints both digests; hub check takes no reader policy.
func TestReaderPolicy(t *testing.T) {
	w := fixture(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "p.json")
	os.WriteFile(good, []byte(readerPolicyDoc()), 0o644)
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"version":"reader-policy-v1","selections":[],"trust":[],"extra":1}`), 0o644)

	// unconfigured: explain says so, no reader digest
	e := jsonOf(t, w.run("explain", dig("sole"), "--json")).Members["policy"].(*canon.Object)
	rp := e.Members["reader_policy"].(*canon.Object)
	if _, ok := rp.Members["digest"]; ok {
		t.Fatalf("reader policy digest without a policy: %s", canon.Encode(e))
	}
	hubDigest := e.Members["digest"]
	// --policy and the environment: both digests printed, the hub digest unchanged
	for _, r := range []result{w.run("explain", dig("sole"), "--policy", good, "--json"),
		runIn(w.root, map[string]string{PolicyEnv: good}, "explain", dig("sole"), "--json")} {
		e := jsonOf(t, r).Members["policy"].(*canon.Object)
		rp := e.Members["reader_policy"].(*canon.Object)
		if d, _ := rp.Members["digest"].(canon.String); !isDigest(string(d)) {
			t.Fatalf("reader digest: %s", canon.Encode(e))
		}
		if e.Members["digest"] != hubDigest {
			t.Fatal("the reader policy changed the hub policy digest")
		}
	}
	// a bad, missing or oversized reader policy is exit 2 before any work, on every command that takes it
	big := filepath.Join(dir, "big.json")
	os.WriteFile(big, []byte(strings.Repeat(" ", 1<<21)), 0o644)
	before := snapshot(t, w.root)
	for _, c := range Commands() {
		if !c.ReaderPolicy {
			continue
		}
		args := strings.Fields(c.Name)
		if len(c.Args) > 0 && !c.Args[0].Optional {
			args = append(args, sweepArg(w, c))
		}
		for _, p := range []string{bad, filepath.Join(dir, "absent.json"), big} {
			r := w.run(append(args, "--policy", p, "--json")...)
			if r.code != 2 || !strings.Contains(r.stdout, `"class":"reader policy"`) {
				t.Fatalf("%v --policy %s: exit %d %s", args, p, r.code, r.stdout)
			}
			r = runIn(w.root, map[string]string{PolicyEnv: p}, append(args, "--json")...)
			if r.code != 2 {
				t.Fatalf("%v %s=%s: exit %d", args, PolicyEnv, p, r.code)
			}
		}
	}
	if snapshot(t, w.root) != before {
		t.Fatal("a refused reader policy changed the store")
	}
	// commands that take no reader policy reject the option (hub check: signer trust is not an input, H-13)
	for _, c := range Commands() {
		if c.ReaderPolicy {
			continue
		}
		if r := w.run(append(strings.Fields(c.Name), "--policy", good, "--json")...); r.code != 2 {
			t.Fatalf("%s accepted --policy: exit %d", c.Name, r.code)
		}
	}
	// the hub policy's limit names come from gate's documented list (one parser)
	os.WriteFile(filepath.Join(w.root, PolicyFile), []byte(`{"policy":"rc-hub-policy/1","limits":{"made_up":1}}`), 0o644)
	if r := w.run("list", "--json"); r.code != 2 {
		t.Fatalf("undocumented limit name accepted: %d", r.code)
	}
	os.WriteFile(filepath.Join(w.root, PolicyFile), []byte(`{"policy":"rc-hub-policy/1","limits":{"blob_bytes":5}}`), 0o644)
	if r := w.run("list", "--json"); r.code != 0 {
		t.Fatalf("documented limit refused: %d %s", r.code, r.stdout)
	}
	os.Remove(filepath.Join(w.root, PolicyFile))
}

// sweepArg is a valid first positional argument for a command over the fixture.
func sweepArg(w *world, c *Command) string {
	switch c.Args[0].Shape {
	case ShapeText:
		return w.root
	}
	return dig("sole")
}

// sortedKeys sorts trust principals as reader-policy-v1 requires (entries in canonical order).
func sortedKeys(ks ...string) []string {
	slices.SortFunc(ks, func(a, b string) int {
		return strings.Compare(`{"principal":{"key":"`+a, `{"principal":{"key":"`+b)
	})
	return ks
}

// pullWorld is a source store with statements by a trusted key (K1), an untrusted one (Z) and a third key (Y)
// whose statement is tampered in the package (bad signature), and a fresh receiving store.
func pullWorld(t *testing.T) (src, dst *world, pkg, zPath, badPath string) {
	src = newWorld(t)
	src.blob("k1", []byte("k1"))
	src.authored("A:k1", "K1", "k1", "licence", "CC0-1.0")
	src.blob("z", []byte("z"))
	zID := src.authored("A:z", "Z", "z")
	yID := src.authored("A:y", "Y", "y")
	pkg = t.TempDir()
	copyData(t, src.root, pkg)
	zPath = "statements/" + strings.ReplaceAll(src.signer("Z"), ":", "-") + "/" + zID
	badPath = "statements/" + strings.ReplaceAll(src.signer("Y"), ":", "-") + "/" + yID
	b := mustRead(t, filepath.Join(pkg, badPath))
	i := strings.LastIndex(string(b), `"sig":"`) + 12
	if b[i] == 'a' {
		b[i] = 'b'
	} else {
		b[i] = 'a'
	}
	os.WriteFile(filepath.Join(pkg, badPath), b, 0o644)
	return src, newWorld(t), pkg, zPath, badPath
}

func objectRow(t *testing.T, rep *canon.Object, path string) *canon.Object {
	t.Helper()
	for _, x := range rep.Members["objects"].(canon.Array) {
		o := x.(*canon.Object)
		if o.Members["path"] == canon.String(path) {
			return o
		}
	}
	return nil
}

// TestPullTrustFloor: C-core-111, C-core-113, C-core-121a, C-core-137 through the command. The reader policy's
// admission trust is the trust floor: Z's valid statement is refused (class reader policy, reason trust floor,
// scope Z's objects) with --below-floor refuse, or admitted and labelled by default; the tampered statement is
// refused intrinsic under every setting, and the admitted rest is committed as one operation. A typed override
// naming Z's object admits it and is recorded by name; it cannot admit the intrinsic refusal; no message offers
// a force. --dry-run states its side effects and changes nothing.
func TestPullTrustFloor(t *testing.T) {
	conformance.Covers(t, "C-core-111")
	conformance.Covers(t, "C-core-113")
	conformance.Partial(t, "C-core-137", "pull --dry-run states its side effects and a before/after snapshot proves nothing changed; fetch --dry-run (fetch, cache, quarantine) has no command yet")
	src, dst, pkg, zPath, badPath := pullWorld(t)
	pf := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(pf, []byte(readerPolicyDoc(sortedKeys(src.signer("K1"), src.signer("Y"))...)), 0o644)

	// dry run: the full report, nothing changed
	before := snapshot(t, dst.root)
	r := dst.run("pull", pkg, "--policy", pf, "--below-floor", "refuse", "--dry-run", "--json")
	if r.code != 1 || snapshot(t, dst.root) != before {
		t.Fatalf("dry run: exit %d, changed %v\n%s", r.code, snapshot(t, dst.root) != before, r.stdout)
	}
	if rep := jsonOf(t, r); rep.Members["side_effects"] != canon.String(pullSideEffects) {
		t.Fatalf("dry run side effects: %s", rep.Members["side_effects"])
	}

	// refuse: Z refused under reader policy, the tampered line refused intrinsic, K1 committed
	r = dst.run("pull", pkg, "--policy", pf, "--below-floor", "refuse", "--json")
	if r.code != 1 {
		t.Fatalf("pull: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	rep := jsonOf(t, r)
	z := objectRow(t, rep, zPath)
	if z == nil || z.Members["verdict"] != canon.String("refused") || z.Members["class"] != canon.String("reader policy") ||
		z.Members["reason"] != canon.String("trust floor") || !strings.Contains(string(z.Members["detail"].(canon.String)), src.signer("Z")) {
		t.Fatalf("Z: %s", canon.Encode(z))
	}
	bad := objectRow(t, rep, badPath)
	if bad == nil || bad.Members["class"] != canon.String("intrinsic") || bad.Members["next"] == z.Members["next"] {
		t.Fatalf("tampered: %s", canon.Encode(bad))
	}
	if _, ok := rep.Members["operation"]; !ok {
		t.Fatalf("the admitted rest was not committed: %s", r.stdout)
	}
	if _, err := os.Stat(filepath.Join(dst.root, zPath)); err == nil {
		t.Fatal("a refused statement was written")
	}
	if _, err := os.Stat(filepath.Join(dst.root, badPath)); err == nil {
		t.Fatal("the tampered statement was written")
	}
	if strings.Contains(strings.ToLower(r.stdout+dst.run("pull", pkg, "--policy", pf, "--below-floor", "refuse").stdout), "force") {
		t.Fatal("a message offers a force")
	}
	if l := dst.run("list", "--json"); !strings.Contains(l.stdout, dig("k1")) || strings.Contains(l.stdout, dig("z")) {
		t.Fatalf("receiver after pull: %s", l.stdout)
	}

	// C-core-113: relax the floor (the policy now trusts Z) and retry: Z admitted, the tampered line still intrinsic
	relaxed := filepath.Join(t.TempDir(), "relaxed.json")
	os.WriteFile(relaxed, []byte(readerPolicyDoc(sortedKeys(src.signer("K1"), src.signer("Y"), src.signer("Z"))...)), 0o644)
	r = dst.run("pull", pkg, "--policy", relaxed, "--below-floor", "refuse", "--json")
	rep = jsonOf(t, r)
	if objectRow(t, rep, zPath) != nil || objectRow(t, rep, badPath).Members["class"] != canon.String("intrinsic") || r.code != 1 {
		t.Fatalf("relaxed retry: exit %d\n%s", r.code, r.stdout)
	}
	if _, err := os.Stat(filepath.Join(dst.root, zPath)); err != nil {
		t.Fatal("the relaxed retry did not install Z's statement")
	}

	// default --below-floor label: Z admitted and labelled; the tampered line still refused
	_, dst2, _, _, _ := pullWorld(t)
	r = dst2.run("pull", pkg, "--policy", pf, "--json")
	rep = jsonOf(t, r)
	z = objectRow(t, rep, zPath)
	if r.code != 1 || z.Members["verdict"] != canon.String("admitted and labelled") || !strings.Contains(string(canon.Encode(z)), `"below trust floor"`) {
		t.Fatalf("label: exit %d %s", r.code, canon.Encode(z))
	}
	if objectRow(t, rep, badPath).Members["class"] != canon.String("intrinsic") {
		t.Fatal("labelling changed the intrinsic refusal")
	}

	// a typed override naming Z (and, uselessly, the tampered line): Z admitted by name, the line stays refused
	_, dst3, _, _, _ := pullWorld(t)
	r = dst3.run("pull", pkg, "--policy", pf, "--below-floor", "refuse", "--override", "zok="+zPath+","+badPath, "--json")
	rep = jsonOf(t, r)
	z = objectRow(t, rep, zPath)
	if r.code != 1 || !strings.Contains(string(canon.Encode(z)), `"admitted by override"`) || z.Members["override"] != canon.String("zok") {
		t.Fatalf("override: exit %d %s", r.code, canon.Encode(z))
	}
	if objectRow(t, rep, badPath).Members["verdict"] != canon.String("refused") {
		t.Fatal("an override admitted an intrinsic refusal")
	}
	if !strings.Contains(string(rep.Members["journal_kind"].(canon.String)), "override zok") {
		t.Fatalf("journal kind does not name the override: %s", rep.Members["journal_kind"])
	}

	// no reader policy: every signer admitted unlabelled (policy D-1 undecided: the round-1 behaviour)
	_, dst4, _, _, _ := pullWorld(t)
	rep = jsonOf(t, dst4.run("pull", pkg, "--json"))
	if z := objectRow(t, rep, zPath); z != nil {
		t.Fatalf("no reader policy, Z reported: %s", canon.Encode(z))
	}

	// pulling the same package again installs nothing new
	r = dst.run("pull", pkg, "--policy", pf, "--below-floor", "refuse", "--json")
	if _, ok := jsonOf(t, r).Members["operation"]; ok {
		t.Fatalf("a repeat pull committed an operation: %s", r.stdout)
	}

	// a checkout's .git is refused, never read; the data beside it is judged on its own
	os.MkdirAll(filepath.Join(pkg, ".git", "hooks"), 0o755)
	os.WriteFile(filepath.Join(pkg, ".git", "hooks", "post-checkout"), []byte("#!/bin/sh\ntouch /tmp/rc-pwned\n"), 0o755)
	rep = jsonOf(t, dst4.run("pull", pkg, "--json"))
	if g := objectRow(t, rep, ".git"); g == nil || g.Members["class"] != canon.String("intrinsic") {
		t.Fatalf(".git: %s", canon.Encode(g))
	}
}

// TestHubCheckCommand: hub template H-10 to H-14, H-50 to H-52 through the command. A full check of the
// fixture hub exits 0 with the policy revision and digest, the tool version, counts per verdict and the side
// effects line; a refused object in a change exits 1 with path, id, verdict, class and reason on one line; no
// hub root, an unknown marker and a base that is not a commit exit 2 with problem details; nothing is written.
func TestHubCheckCommand(t *testing.T) {
	w := fixture(t)
	if _, err := os.Stat(filepath.Join(w.root, ".git")); err != nil {
		t.Skip("git not installed")
	}
	before := snapshot(t, w.root)
	r := w.run("hub", "check")
	j := jsonOf(t, w.run("hub", "check", "--json"))
	if r.code != 0 {
		t.Fatalf("full check: %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	for _, want := range []string{"revision: ", "digest: sha256:", "tool: test", "commit: 0000000", "not applied: ", "refused: 0", "side effects: no registry change; no fetch; no cache"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("human output lacks %q:\n%s", want, r.stdout)
		}
	}
	if j.Members["side_effects"] != canon.String("no registry change; no fetch; no cache") {
		t.Fatal(canon.Encode(j))
	}
	if snapshot(t, w.root) != before {
		t.Fatal("hub check wrote to the hub")
	}
	// a change adding a tampered statement and a hook: exit 1, one line each
	gitIn(t, w.root, "checkout", "-q", "-b", "pr")
	id := w.ids["A:sole"]
	signer := strings.ReplaceAll(w.signer("K1"), ":", "-")
	line := mustRead(t, filepath.Join(w.root, "statements", signer, id))
	os.MkdirAll(filepath.Join(w.root, "hooks"), 0o755)
	os.WriteFile(filepath.Join(w.root, "hooks", "post-merge"), []byte("#!/bin/sh\n"), 0o755)
	fake := strings.Repeat("0", 64)
	os.WriteFile(filepath.Join(w.root, "statements", signer, fake), line, 0o644)
	gitIn(t, w.root, "add", "-A")
	gitIn(t, w.root, "commit", "-q", "-m", "change")
	r = w.run("hub", "check", "--base", "main")
	if r.code != 1 {
		t.Fatalf("change: exit %d\n%s", r.code, r.stdout)
	}
	for _, p := range []string{`"hooks/post-merge"`, `"statements/` + signer + `/` + fake + `"`} {
		found := false
		for _, l := range strings.Split(r.stdout, "\n") {
			if strings.Contains(l, p) && strings.Contains(l, "verdict: refused") && strings.Contains(l, "class: intrinsic") && strings.Contains(l, "reason: ") {
				found = true
			}
		}
		if !found {
			t.Fatalf("no refusal line for %s:\n%s", p, r.stdout)
		}
	}
	jr := jsonOf(t, w.run("hub", "check", "--base", "main", "--json"))
	if jr.Members["base"] == nil || objectRow(t, jr, "hooks/post-merge").Members["verdict"] != canon.String("refused") {
		t.Fatal(canon.Encode(jr))
	}
	// did not start
	for _, c := range []struct {
		wd   string
		args []string
	}{{t.TempDir(), nil}, {w.root, []string{"--base", "nope"}}} {
		r := runIn(c.wd, nil, append([]string{"hub", "check", "--json"}, c.args...)...)
		p := jsonOf(t, r)
		if r.code != 2 || p.Members["committed"] != canon.Bool(false) || p.Members["next"] == nil {
			t.Fatalf("%v: %d %s", c.args, r.code, r.stdout)
		}
	}
	// an unknown marker at the policy revision (read from git, never the working tree)
	os.WriteFile(filepath.Join(w.root, "rc-store"), []byte(`{"layout":"rc-store/9"}`), 0o644)
	gitIn(t, w.root, "commit", "-q", "-am", "marker")
	if r := w.run("hub", "check", "--json"); r.code != 2 {
		t.Fatalf("unknown marker: %d", r.code)
	}
	// the environment configures nothing (H-13): a reader policy in the environment is not read
	if r := runIn(w.root, map[string]string{PolicyEnv: "/nonexistent"}, "hub", "check", "--base", "main", "--json"); r.code == 2 && strings.Contains(r.stdout, "reader policy") {
		t.Fatal("hub check read COMMONS_POLICY")
	}
}

// releaseWorld: a store whose operator key (OPR) serves blob B under its own holds, and a key file for OPR.
func releaseWorld(t *testing.T) (w *world, b, keyFile string) {
	w = newWorld(t)
	b = w.blob("B", []byte("B"))
	w.authored("A:B", "K1", "B")
	w.sign("H:B", "OPR", "holds", obj("content", canon.Value(content("B")), "locations", []string{"https://mirror.example/b"}))
	seed := sha256.Sum256([]byte("research-commons go test cli key OPR"))
	keyFile = filepath.Join(t.TempDir(), "opr.key")
	os.WriteFile(keyFile, keyFileBytes(wire.AlgEd25519, seed[:]), 0o600)
	return w, b, keyFile
}

// TestGCRelease: C-core-145 (a), (b), (d) and C-core-146 (c) through the command. gc is a dry run by default
// and states its side effects; a blob the operator's serving holds pins is kept with the reason named; gc
// --release signs the withdrawal and deletes the blob in one operation, after which show says the bytes are not
// held here and the holds statements (serving and withdrawn) are both in the log; with no usable key nothing
// is committed or deleted. --grace for one run is printed in the plan.
func TestGCRelease(t *testing.T) {
	conformance.Partial(t, "C-core-145", "through the command: (a) gc keeps B and names the serving holds, (b) gc --release commits the withdrawal and deletes B, show then says not held here and both holds are listed, (d) no usable key: nothing committed or deleted; (c) crash and (e) are the store's and the wire schema's (internal/store)")
	conformance.Partial(t, "C-core-146", "through the command: (c) gc --grace for one run is used and printed in the plan; the policy-window floor, (a), (b) and (d) are the store's (internal/store) or need history and publish")
	w, b, keyFile := releaseWorld(t)
	blobPath := filepath.Join(w.root, "blobs", "sha256", strings.TrimPrefix(b, "sha256:"))

	before := snapshot(t, w.root)
	r := w.run("gc", "--json")
	if r.code != 0 || snapshot(t, w.root) != before {
		t.Fatalf("dry run: %d %s", r.code, r.stdout)
	}
	if !strings.Contains(w.run("show", b, "--json").stdout, `"holders":["`+w.signer("OPR")+`"]`) {
		t.Fatal("the operator is not a holder before the release")
	}
	p := jsonOf(t, r)
	if p.Members["side_effects"] != canon.String("no deletion; no registry change") || !strings.Contains(string(canon.Encode(p.Members["kept"])), "served under holds "+w.ids["H:B"]) {
		t.Fatalf("plan: %s", r.stdout)
	}
	if r := w.run("gc", "--apply", "--grace", "0s", "--json"); r.code != 0 || !strings.Contains(r.stdout, `"grace_source":"this run (--grace)"`) {
		t.Fatalf("apply: %d %s", r.code, r.stdout)
	} else if _, err := os.Stat(blobPath); err != nil {
		t.Fatal("gc --apply deleted a blob the operator serves")
	}

	// (d) no usable key: exit 2, nothing changed; a group-readable key file is refused, and never printed
	os.Chmod(keyFile, 0o644)
	before = snapshot(t, w.root)
	for _, args := range [][]string{{"--key", keyFile}, {}} {
		r := w.run(append([]string{"gc", "--release", b, "--json"}, args...)...)
		if r.code != 2 || snapshot(t, w.root) != before || strings.Contains(r.stdout, "seed") && strings.Contains(r.stdout, `"seed":"`) {
			t.Fatalf("unusable key %v: %d %s", args, r.code, r.stdout)
		}
	}
	os.Chmod(keyFile, 0o600)

	// (b) one operation
	r = runIn(w.root, map[string]string{KeyEnv: keyFile}, "gc", "--release", b, "--json")
	if r.code != 0 {
		t.Fatalf("release: %d %s%s", r.code, r.stdout, r.stderr)
	}
	rel := jsonOf(t, r)
	if rel.Members["blob_removed"] != canon.Bool(true) || rel.Members["withdrawal"] == nil {
		t.Fatalf("release: %s", r.stdout)
	}
	if _, err := os.Stat(blobPath); err == nil {
		t.Fatal("the blob is still there")
	}
	// B is not held here and has no current holder; both holds (serving, then withdrawn) stay in the log
	show := w.run("show", b, "--json")
	if !strings.Contains(show.stdout, `"bytes":"not held here"`) || !strings.Contains(show.stdout, `"holders":[]`) {
		t.Fatalf("show after release: %s", show.stdout)
	}
	for _, id := range []string{w.ids["H:B"], string(rel.Members["withdrawal"].(canon.String))} {
		if r := w.run("show", id, "--json"); r.code != 0 || !strings.Contains(r.stdout, `"line":"chained"`) {
			t.Fatalf("holds %s after release: %d %s", id, r.code, r.stdout)
		}
	}
	if !strings.Contains(w.run("show", string(rel.Members["withdrawal"].(canon.String)), "--json").stdout, `"withdrawn":true`) {
		t.Fatal("the withdrawal does not show withdrawn")
	}
	if strings.Contains(r.stdout+show.stdout, hex.EncodeToString([]byte{})+`"seed"`) {
		t.Fatal("key material printed")
	}
}

// TestFsckAndLimits: fsck is read-only, reports what it scanned and exits 1 on a fatal finding (a corrupt blob)
// and 0 otherwise; status --limits prints one table, every row with a name, value, source and what it bounds,
// and a hub policy limit shows as the policy's.
func TestFsckAndLimits(t *testing.T) {
	w := fixture(t)
	before := snapshot(t, w.root)
	r := w.run("fsck", "--json")
	if r.code != 0 || snapshot(t, w.root) != before {
		t.Fatalf("fsck: %d %s", r.code, r.stdout)
	}
	if s := jsonOf(t, r).Members["scanned"].(*canon.Object); s.Members["statements"] == canon.Int(0) {
		t.Fatal("fsck scanned nothing")
	}
	bp := filepath.Join(w.root, "blobs", "sha256", strings.TrimPrefix(dig("sole"), "sha256:"))
	os.Chmod(bp, 0o644)
	if err := os.WriteFile(bp, []byte("not sole"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := w.run("fsck", "--json"); r.code != 1 || !strings.Contains(r.stdout, `"finding":"corrupt blob"`) {
		t.Fatalf("corrupt blob: %d %s", r.code, r.stdout)
	}
	os.WriteFile(filepath.Join(w.root, PolicyFile), []byte(`{"policy":"rc-hub-policy/1","limits":{"blob_bytes":5}}`), 0o644)
	l := jsonOf(t, w.run("status", "--limits", "--json")).Members["limits"].(canon.Array)
	seen := map[string]bool{}
	for _, x := range l {
		o := x.(*canon.Object)
		for _, k := range []string{"name", "value", "unit", "source", "bounds"} {
			if _, ok := o.Members[k]; !ok {
				t.Fatalf("limit row lacks %s: %s", k, canon.Encode(o))
			}
		}
		n := string(o.Members["name"].(canon.String))
		if seen[n] {
			t.Fatalf("limit %s twice", n)
		}
		seen[n] = true
		if n == "blob_bytes" && (o.Members["value"] != canon.Int(5) || o.Members["source"] != canon.String(PolicyFile)) {
			t.Fatalf("hub policy limit: %s", canon.Encode(o))
		}
	}
	for _, n := range []string{"blob_bytes", "statement_bytes", "scan.member_bytes", "fetch_bytes", "gc_grace", "wire.line_bytes"} {
		if !seen[n] {
			t.Fatalf("limits table lacks %s", n)
		}
	}
	if _, ok := jsonOf(t, w.run("status", "--json")).Members["limits"]; ok {
		t.Fatal("status prints limits without --limits")
	}
}
