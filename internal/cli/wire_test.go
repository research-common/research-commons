package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
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
