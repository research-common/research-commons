package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
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
		args := []string{c.Name}
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
		if r := w.run(c.Name, "--policy", good, "--json"); r.code != 2 {
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
