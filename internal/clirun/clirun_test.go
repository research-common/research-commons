package clirun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/cli"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/run"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

var imgDigest = run.Digest([]byte("image manifest amd64"))

func object(kv ...any) *canon.Object {
	o := &canon.Object{Members: map[string]canon.Value{}}
	for i := 0; i < len(kv); i += 2 {
		o.Keys = append(o.Keys, kv[i].(string))
		o.Members[kv[i].(string)] = kv[i+1].(canon.Value)
	}
	slices.SortFunc(o.Keys, canon.CompareKeys)
	return o
}

func catStep(_ context.Context, in, out string, _ map[string]string) (int, run.Resources) {
	b, err := os.ReadFile(filepath.Join(in, "in"))
	if err != nil {
		return 2, run.Resources{}
	}
	os.WriteFile(filepath.Join(out, "result.txt"), b, 0o644)
	return 0, run.Resources{run.CapMemory: 1000, run.CapWallTime: 5, run.CapPids: 1}
}

// pinned is a store in which one key authored a workflow and the output of one real run of it (on the fake),
// with the run's environment record as its pin: the fixture every re-run case starts from.
type pinned struct {
	root, policy, signer string
	output               string
	spec                 *run.Spec
}

func newPinned(t *testing.T) *pinned {
	t.Helper()
	k := wire.Ed25519Key{Seed: func() []byte { h := sha256.Sum256([]byte("clirun test key")); return h[:] }()}
	data := []byte("input-v1")
	code := []byte("code:s")
	specBytes := canon.Encode(object(
		"code", canon.String(run.Digest(code)), "interpreter", canon.String("sh >=1"),
		"image", object("reference", canon.String("registry.example/step:1"), "digest", canon.String(imgDigest)),
		"inputs", object("in", canon.String(run.Digest(data))),
		"outputs", object("result", canon.String("result.txt")),
		"resources", object("memory", canon.Int(1<<20), "wall_time", canon.Int(10_000))))
	spec, err := run.ParseSpec(specBytes)
	if err != nil {
		t.Fatal(err)
	}
	pol := &run.Policy{ExecSigners: []string{k.Signer()}, Ceiling: run.Resources{run.CapMemory: 1 << 30, run.CapWallTime: 60_000, run.CapPids: 256, run.CapDisk: 1 << 30}}
	res, err := run.Execute(context.Background(), pol, fake(catStep), run.Invocation{Request: run.Request{Spec: spec, Signer: k.Signer()},
		Blobs: map[string][]byte{spec.Code: code, run.Digest(data): data}})
	if err != nil || !res.Completed() {
		t.Fatalf("first run: %v", err)
	}
	plan, err := run.PlanPublish(run.PublishInput{Spec: spec, Result: res, Mode: "bytes"})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	s, err := store.Open(root, store.Options{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{specBytes, code, data, res.Outputs[0].Bytes} {
		if _, _, err := s.InstallBlob(bytes.NewReader(b), ""); err != nil {
			t.Fatal(err)
		}
	}
	wf := object("type", canon.String("workflow"), "replication", canon.String("bytes"),
		"content", object("digest", canon.String(spec.Digest), "size", canon.Int(int64(len(specBytes)))))
	prev := ""
	for i, body := range []*canon.Object{wf, plan[0].Body} {
		kind := "authored"
		line, id := wire.Sign(wire.Draft{Kind: kind, Seq: int64(i), Prev: prev, TS: fmt.Sprintf("2026-10-16T00:00:0%dZ", i), Body: body}, k)
		if _, err := s.Commit("publish", [][]byte{line}, nil); err != nil {
			t.Fatal(err)
		}
		prev = id
	}
	p := &pinned{root: root, signer: k.Signer(), output: res.Outputs[0].Digest, spec: spec}
	p.policy = p.writePolicy(t, `{"format":"`+cli.ExecPolicyFormat+`","exec_signers":["`+k.Signer()+`"],"ceiling":{"memory":1073741824,"wall_time":60000,"pids":256,"disk":1073741824}}`)
	return p
}

func (p *pinned) writePolicy(t *testing.T, body string) string {
	f := filepath.Join(t.TempDir(), "exec-policy.json")
	os.WriteFile(f, []byte(body), 0o644)
	return f
}

func fake(step run.Step) *run.Fake {
	return &run.Fake{Images: map[string]string{imgDigest: "linux/amd64"}, Steps: map[string]run.Step{run.Digest([]byte("code:s")): step}}
}

type result struct {
	code   int
	stdout string
}

func (p *pinned) verify(rr cli.Rerunner, args ...string) result {
	var o, e bytes.Buffer
	env := &cli.Env{Stdout: &o, Stderr: &e, Getenv: func(string) string { return "" }, Getwd: func() (string, error) { return p.root, nil },
		Build: cli.Build{Version: "test", Commit: "0000000"}, Rerun: rr}
	code := cli.Main(append([]string{"verify", "--json"}, args...), env)
	return result{code, o.String() + e.String()}
}

// TestRerunExits: C-core-133, the re-run fixtures through the CLI. In the pinned environment the re-run matches
// (exit 0) or diverges (1); a reader limit stops it (timeout, 3); the step fails in an environment matching the
// pin (failed, 3); the pinned environment is not this one (environment mismatch, 5). Nothing to re-run (4) and
// the statement-only fixtures are in the CLI package's TestVerifyExits; together they cover the case.
func TestRerunExits(t *testing.T) {
	conformance.Covers(t, "C-core-133")
	p := newPinned(t)
	if r := p.verify(nil, p.output); r.code != 3 || !strings.Contains(r.stdout, "not re-derived") {
		t.Fatalf("statement-only: %d %s", r.code, r.stdout)
	}
	write := func(s string) run.Step {
		return func(_ context.Context, _, out string, _ map[string]string) (int, run.Resources) {
			os.WriteFile(filepath.Join(out, "result.txt"), []byte(s), 0o644)
			return 0, run.Resources{run.CapMemory: 1000, run.CapWallTime: 5}
		}
	}
	other := fake(catStep)
	other.Images[imgDigest] = "linux/arm64/v8"
	for _, c := range []struct {
		name         string
		f            *run.Fake
		exit         int
		token, cause string
	}{
		{"match", fake(catStep), 0, "match", ""},
		{"diverged", fake(write("other bytes")), 1, "diverged", ""},
		{"timeout", fake(func(context.Context, string, string, map[string]string) (int, run.Resources) {
			return 0, run.Resources{run.CapWallTime: 50_000}
		}), 3, "timeout", ""},
		{"failed step", fake(func(context.Context, string, string, map[string]string) (int, run.Resources) {
			return 2, run.Resources{run.CapWallTime: 5}
		}), 3, "failed", "failed: exit 2"},
		{"environment mismatch", other, 5, "environment mismatch", "environment mismatch: platform"},
	} {
		r := p.verify(&Bridge{Runner: c.f}, p.output, "--rerun", "--exec-policy", p.policy)
		if r.code != c.exit {
			t.Fatalf("%s: exit %d, want %d\n%s", c.name, r.code, c.exit, r.stdout)
		}
		if !strings.Contains(r.stdout, `"state":"`+c.token+`"`) || (c.cause != "" && !strings.Contains(r.stdout, c.cause)) {
			t.Fatalf("%s: token missing: %s", c.name, r.stdout)
		}
		causes, _, _ := strings.Cut(r.stdout[strings.Index(r.stdout, `"causes"`):], "]")
		if strings.Contains(causes, "not re-derived") {
			t.Fatalf("%s: the statement-only derivation cause was not replaced: %s", c.name, r.stdout)
		}
		if c.f.Spawned != 1 {
			t.Fatalf("%s: spawned %d", c.name, c.f.Spawned)
		}
	}
	// the exit is run.VerifyWithRerun's
	for _, k := range []run.Token{{Kind: run.Match}, {Kind: run.Diverged}, {Kind: run.Timeout}, {Kind: run.FailedExit, ExitStatus: 2}, {Kind: run.EnvMismatch, Fields: []string{"platform"}}} {
		if code, _ := run.VerifyWithRerun(3, []string{"derivation: not re-derived"}, k); code != k.Exit() && !(k.Exit() == 0 && code == 0) {
			t.Fatalf("%s: VerifyWithRerun %d", k, code)
		}
	}
}

// TestRerunNeverByDefault: verify runs nothing unless asked (--rerun) and given a policy; a refusal before
// staging spawns nothing; a build without a Rerunner says so. The CLI options are checked before any work.
func TestRerunNeverByDefault(t *testing.T) {
	p := newPinned(t)
	f := fake(catStep)
	b := &Bridge{Runner: f}
	if r := p.verify(b, p.output); r.code != 3 || f.Spawned != 0 || strings.Contains(r.stdout, `"rerun"`) || !strings.Contains(r.stdout, "not re-derived") {
		t.Fatalf("no --rerun: %d spawned %d", r.code, f.Spawned)
	}
	if r := p.verify(b, p.output, "--rerun"); r.code != 3 || !strings.Contains(r.stdout, "no execution policy") || f.Spawned != 0 {
		t.Fatalf("no policy: %d %s", r.code, r.stdout)
	}
	if r := p.verify(nil, p.output, "--rerun", "--exec-policy", p.policy); r.code != 3 || !strings.Contains(r.stdout, "re-run not available in this build") {
		t.Fatalf("no bridge: %d %s", r.code, r.stdout)
	}
	// the policy admits neither the signer nor the workflow: refused before staging, nothing spawned, no pass
	deny := p.writePolicy(t, `{"format":"`+cli.ExecPolicyFormat+`","exec_signers":[]}`)
	if r := p.verify(b, p.output, "--rerun", "--exec-policy", deny); r.code != 3 || !strings.Contains(r.stdout, "refused before staging") || f.Spawned != 0 {
		t.Fatalf("not admitted: %d %s spawned %d", r.code, r.stdout, f.Spawned)
	}
	for _, args := range [][]string{
		{p.output, "--exec-policy", p.policy},
		{p.output, "--rerun", "--exec-policy", filepath.Join(t.TempDir(), "missing")},
		{p.output, "--rerun", "--exec-policy", p.writePolicy(t, `{"format":"`+cli.ExecPolicyFormat+`","grants":{}}`)},
		{p.output, "--rerun", "--exec-policy", p.writePolicy(t, `{"format":"rc-exec-policy/9"}`)},
		{p.output, "--rerun", "--exec-policy", p.writePolicy(t, `{"format":"`+cli.ExecPolicyFormat+`","ceiling":{"gpu":1}}`)},
		{strings.Repeat("ab", 32), "--rerun", "--exec-policy", p.policy},
	} {
		if r := p.verify(b, args...); r.code != 2 || f.Spawned != 0 {
			t.Fatalf("%v: %d %s", args, r.code, r.stdout)
		}
	}
}

// TestWordsInVocabulary: every run token's word is a CLI vocabulary token.
func TestWordsInVocabulary(t *testing.T) {
	for _, k := range []run.Token{{Kind: run.Match}, {Kind: run.Match, Identical: true}, {Kind: run.Diverged}, {Kind: run.Unchecked},
		{Kind: run.NotComparable}, {Kind: run.IncompleteOutput}, {Kind: run.FailedExit, ExitStatus: 1}, {Kind: run.FailedCap, Cap: "memory"},
		{Kind: run.Timeout}, {Kind: run.EnvMismatch, Fields: []string{"platform"}}} {
		if !cli.IsToken(Word(k)) {
			t.Errorf("%s: word %q is not in the CLI vocabulary", k, Word(k))
		}
	}
}

// TestEmptyImageAllowlistAdmitsNothing: a present but empty images list is an allowlist that admits no image (the
// allowlist fails closed, execution note §2.1); only an absent member means no allowlist.
func TestEmptyImageAllowlistAdmitsNothing(t *testing.T) {
	p := newPinned(t)
	body, err := os.ReadFile(p.policy)
	if err != nil {
		t.Fatal(err)
	}
	empty := p.writePolicy(t, strings.Replace(string(body), `"format":`, `"images":[],"format":`, 1))
	f := fake(catStep)
	r := p.verify(&Bridge{Runner: f}, p.output, "--rerun", "--exec-policy", empty)
	if r.code == 0 || f.Spawned != 0 || !strings.Contains(r.stdout, "allowlist") {
		t.Fatalf("empty allowlist: exit %d, spawned %d\n%s", r.code, f.Spawned, r.stdout)
	}
	// control: the same policy without the member runs
	f = fake(catStep)
	if r := p.verify(&Bridge{Runner: f}, p.output, "--rerun", "--exec-policy", p.policy); r.code != 0 || f.Spawned != 1 {
		t.Fatalf("absent allowlist: exit %d, spawned %d\n%s", r.code, f.Spawned, r.stdout)
	}
}
