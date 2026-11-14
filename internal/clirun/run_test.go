package clirun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/cli"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/reqlog"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/run"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// runWorld is a store holding one workflow spec, its code and inputs, and the workflow's authored statement (by
// the author key, replication bytes); the runner signs with its own key file.
type runWorld struct {
	t                    *testing.T
	root, policy, key    string
	runner, author, spec string
	code                 []byte
}

func seedKey(name string) wire.Ed25519Key {
	h := sha256.Sum256([]byte(name))
	return wire.Ed25519Key{Seed: h[:]}
}

// newRunWorld: spec is built from kv (code, image and resources filled in); held are the input bytes to install.
func newRunWorld(t *testing.T, policyExtra string, held [][]byte, kv ...any) *runWorld {
	t.Helper()
	w := &runWorld{t: t, code: []byte("code:s")}
	m := []any{"code", canon.String(run.Digest(w.code)), "interpreter", canon.String("sh >=1"),
		"image", object("reference", canon.String("registry.example/step:1"), "digest", canon.String(imgDigest)),
		"resources", object("memory", canon.Int(1<<20), "wall_time", canon.Int(10_000))}
	specBytes := canon.Encode(object(append(m, kv...)...))
	if _, err := run.ParseSpec(specBytes); err != nil {
		t.Fatal(err)
	}
	w.spec = run.Digest(specBytes)
	w.root = t.TempDir()
	s, err := store.Open(w.root, store.Options{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range append([][]byte{specBytes, w.code}, held...) {
		if _, _, err := s.InstallBlob(bytes.NewReader(b), ""); err != nil {
			t.Fatal(err)
		}
	}
	author := seedKey("workflow author")
	w.author = author.Signer()
	wf := object("type", canon.String("workflow"), "replication", canon.String("bytes"),
		"content", object("digest", canon.String(w.spec), "size", canon.Int(int64(len(specBytes)))))
	line, _ := wire.Sign(wire.Draft{Kind: "authored", TS: "2026-10-16T00:00:00Z", Body: wf}, author)
	if _, err := s.Commit("publish", [][]byte{line}, nil); err != nil {
		t.Fatal(err)
	}
	rk := seedKey("runner")
	w.runner = rk.Signer()
	kf := object("alg", canon.String(wire.AlgEd25519), "format", canon.String(cli.KeyFormat), "seed", canon.String(hex.EncodeToString(rk.Seed)))
	w.key = filepath.Join(t.TempDir(), "runner.key")
	if err := os.WriteFile(w.key, append(canon.Encode(kf), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	w.policy = filepath.Join(t.TempDir(), "exec-policy.json")
	os.WriteFile(w.policy, []byte(`{"format":"`+cli.ExecPolicyFormat+`","exec_signers":["`+w.author+`"],"ceiling":{"memory":1073741824,"wall_time":60000,"pids":256,"disk":1073741824}`+policyExtra+`}`), 0o644)
	return w
}

// oneOutput is the plain fixture: input "in" pinned, output "result".
func oneOutput(t *testing.T) *runWorld {
	data := []byte("input-v1")
	return newRunWorld(t, "", [][]byte{data}, "inputs", object("in", canon.String(run.Digest(data))), "outputs", object("result", canon.String("result.txt")))
}

func (w *runWorld) fake(step run.Step) *run.Fake {
	return &run.Fake{Images: map[string]string{imgDigest: "linux/amd64"}, Steps: map[string]run.Step{run.Digest(w.code): step}}
}

// writes is a step that writes each named file with the given bytes.
func writes(files ...string) run.Step {
	return func(_ context.Context, _, out string, _ map[string]string) (int, run.Resources) {
		for i := 0; i < len(files); i += 2 {
			os.WriteFile(filepath.Join(out, files[i]), []byte(files[i+1]), 0o644)
		}
		return 0, run.Resources{run.CapMemory: 1000, run.CapWallTime: 5, run.CapPids: 1}
	}
}

// run runs `commons run --json <spec> --exec-policy <policy> args...` through the bridge over f (nil = no bridge).
func (w *runWorld) run(f *run.Fake, args ...string) result {
	var o, e bytes.Buffer
	env := &cli.Env{Stdout: &o, Stderr: &e, Getenv: func(string) string { return "" }, Getwd: func() (string, error) { return w.root, nil },
		Build: cli.Build{Version: "test", Commit: "0000000"}}
	if f != nil {
		env.Exec = &Bridge{Runner: f}
	}
	code := cli.Main(append([]string{"run", "--json", w.spec, "--exec-policy", w.policy}, args...), env)
	return result{code, o.String() + e.String()}
}

func (w *runWorld) publish(f *run.Fake, args ...string) result {
	return w.run(f, append([]string{"--publish", "--key", w.key}, args...)...)
}

// statements returns the runner's statements of kind, in seq order.
func (w *runWorld) statements(kind string) []*wire.Statement {
	w.t.Helper()
	s, err := store.Open(w.root, store.Options{NoSync: true})
	if err != nil {
		w.t.Fatal(err)
	}
	all, err := s.Statements()
	if err != nil {
		w.t.Fatal(err)
	}
	var out []*wire.Statement
	for _, b := range all {
		st, err := wire.ReadStored(b)
		if err == nil && st.Signer == w.runner && st.Kind == kind {
			out = append(out, st)
		}
	}
	slices.SortFunc(out, func(a, b *wire.Statement) int { return int(a.Seq - b.Seq) })
	return out
}

func member(b *canon.Object, path ...string) canon.Value {
	var v canon.Value = b
	for _, k := range path {
		o, ok := v.(*canon.Object)
		if !ok {
			return nil
		}
		v = o.Members[k]
	}
	return v
}

func want(t *testing.T, name string, r result, code int, subs ...string) {
	t.Helper()
	if r.code != code {
		t.Fatalf("%s: exit %d, want %d\n%s", name, r.code, code, r.stdout)
	}
	for _, s := range subs {
		if !strings.Contains(r.stdout, s) {
			t.Fatalf("%s: %q missing\n%s", name, s, r.stdout)
		}
	}
}

// tree is every path, mode and content hash under root: "byte-identical" for a store.
func tree(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, p)
		fi, _ := d.Info()
		line := rel + " " + fi.Mode().String()
		if !d.IsDir() {
			b, _ := os.ReadFile(p)
			h := sha256.Sum256(b)
			line += " " + hex.EncodeToString(h[:8])
		}
		lines = append(lines, line)
		return nil
	})
	return strings.Join(lines, "\n")
}

// TestRunNeedsPolicy: run executes nothing without an execution policy, in a build without the bridge, or for a
// workflow the policy does not admit; without --publish it prints the run and appends nothing.
func TestRunNeedsPolicy(t *testing.T) {
	w := oneOutput(t)
	f := w.fake(writes("result.txt", "out-1"))
	before := tree(t, w.root)
	var o, e bytes.Buffer
	env := &cli.Env{Stdout: &o, Stderr: &e, Getenv: func(string) string { return "" }, Getwd: func() (string, error) { return w.root, nil },
		Build: cli.Build{Version: "test", Commit: "0000000"}, Exec: &Bridge{Runner: f}}
	if code := cli.Main([]string{"run", "--json", w.spec}, env); code != 2 || f.Spawned != 0 || !strings.Contains(o.String()+e.String(), "exec-policy") {
		t.Fatalf("no policy: %d %s", code, o.String()+e.String())
	}
	want(t, "no bridge", w.run(nil), 3, "run is not available in this build")
	want(t, "publish-only option without --publish", w.run(f, "--licence", "result=CC0-1.0"), 2, "applies only with --publish")
	want(t, "undeclared output", w.publish(f, "--licence", "nope=CC0-1.0"), 2, "the spec declares result")
	want(t, "request log on a derivation", w.publish(f, "--request-log", "result"), 2, "applies to an acquisition")
	if f.Spawned != 0 {
		t.Fatalf("an option error spawned %d", f.Spawned)
	}
	deny := filepath.Join(t.TempDir(), "deny.json")
	os.WriteFile(deny, []byte(`{"format":"`+cli.ExecPolicyFormat+`","exec_signers":[]}`), 0o644)
	w2 := *w
	w2.policy = deny
	want(t, "not admitted", w2.publish(f), 3, "refused before staging", `"published":false`)
	if f.Spawned != 0 {
		t.Fatalf("not admitted: spawned %d", f.Spawned)
	}
	r := w.run(f)
	want(t, "print only", r, 0, `"state":"unchecked"`, `"published":false`, `"output":"result"`, run.Digest([]byte("out-1")))
	if f.Spawned != 1 {
		t.Fatalf("print only: spawned %d", f.Spawned)
	}
	if after := tree(t, w.root); after != before {
		t.Fatalf("a run without --publish changed the store:\n%s\n---\n%s", before, after)
	}
}

// TestRunPublishFirstThenReproduced: C-exec-02 (a first run emits authored with provenance and the environment
// record), C-exec-01 (the same bytes again emit reproduced: match over that authored, never a second authored)
// and different bytes then emit reproduced: diverged over it.
func TestRunPublishFirstThenReproduced(t *testing.T) {
	conformance.Covers(t, "C-exec-02")
	conformance.Partial(t, "C-exec-01", "the group display (derived by 1 plus the reproduction) is the resolver's test in internal/resolve; this test checks the statements the command emits")
	w := oneOutput(t)
	out1 := run.Digest([]byte("out-1"))
	want(t, "first", w.publish(w.fake(writes("result.txt", "out-1"))), 0, `"committed":true`, `"kind":"authored"`)
	au := w.statements("authored")
	if len(au) != 1 || len(w.statements("reproduced")) != 0 {
		t.Fatalf("first run: %d authored", len(au))
	}
	b := au[0].Body
	if member(b, "content", "digest") != canon.String(out1) || member(b, "provenance", "workflow") != canon.String(w.spec) ||
		member(b, "provenance", "environment") == nil || member(b, "type") != canon.String("dataset") {
		t.Fatalf("first authored: %s", canon.Encode(b))
	}
	if h := w.statements("holds"); len(h) != 1 || member(h[0].Body, "content", "digest") != canon.String(out1) {
		t.Fatal("the runner does not hold its output")
	}

	want(t, "same bytes", w.publish(w.fake(writes("result.txt", "out-1"))), 0, `"kind":"reproduced"`, `"state":"match"`)
	rp := w.statements("reproduced")
	if len(w.statements("authored")) != 1 || len(rp) != 1 {
		t.Fatalf("same bytes: %d authored, %d reproduced", len(w.statements("authored")), len(rp))
	}
	if member(rp[0].Body, "of") != canon.String(au[0].ID) || member(rp[0].Body, "result") != canon.String("match") ||
		member(rp[0].Body, "provenance", "environment") == nil {
		t.Fatalf("reproduced: %s", canon.Encode(rp[0].Body))
	}

	want(t, "different bytes", w.publish(w.fake(writes("result.txt", "out-2"))), 0, `"kind":"reproduced"`, `"state":"diverged"`)
	rp = w.statements("reproduced")
	if len(w.statements("authored")) != 1 || len(rp) != 2 || member(rp[1].Body, "result") != canon.String("diverged") ||
		member(rp[1].Body, "of") != canon.String(au[0].ID) || member(rp[1].Body, "content", "digest") != canon.String(run.Digest([]byte("out-2"))) {
		t.Fatalf("diverged: %d authored, %d reproduced", len(w.statements("authored")), len(rp))
	}
}

// TestRunPublishPartialDisclosures: C-exec-04. Three outputs; a licence and availability for two, nothing for the
// third: each authored carries exactly what was supplied for it, nothing is inherited (not from the workflow's
// replication, not from a sibling), and no flag is needed to publish without disclosures.
func TestRunPublishPartialDisclosures(t *testing.T) {
	conformance.Covers(t, "C-exec-04")
	data := []byte("input-v1")
	w := newRunWorld(t, "", [][]byte{data}, "inputs", object("in", canon.String(run.Digest(data))),
		"outputs", object("a", canon.String("a.txt"), "b", canon.String("b.txt"), "c", canon.String("c.txt")))
	f := w.fake(writes("a.txt", "A", "b.txt", "B", "c.txt", "C"))
	avail := `{"obtainable":true,"redistribution":"permitted"}`
	want(t, "three outputs", w.publish(f, "--licence", "a=CC-BY-4.0", "--availability", "a="+avail, "--licence", "b=CC0-1.0", "--availability", "b="+avail), 0, `"committed":true`)
	au := w.statements("authored")
	if len(au) != 3 {
		t.Fatalf("%d authored", len(au))
	}
	written := []string{"content", "provenance", "type"}
	for _, st := range au {
		var name string
		for o, d := range map[string]string{"a": "A", "b": "B", "c": "C"} {
			if member(st.Body, "content", "digest") == canon.String(run.Digest([]byte(d))) {
				name = o
			}
		}
		keys := slices.Clone(st.Body.Keys)
		slices.Sort(keys)
		wantKeys := slices.Clone(written)
		switch name {
		case "a":
			wantKeys = append(wantKeys, "availability", "licence")
			if member(st.Body, "licence") != canon.String("CC-BY-4.0") {
				t.Fatalf("a: %s", canon.Encode(st.Body))
			}
		case "b":
			wantKeys = append(wantKeys, "availability", "licence")
			if member(st.Body, "licence") != canon.String("CC0-1.0") {
				t.Fatalf("b: %s", canon.Encode(st.Body))
			}
		case "c":
		default:
			t.Fatalf("an authored for no output: %s", canon.Encode(st.Body))
		}
		slices.Sort(wantKeys)
		if !slices.Equal(keys, wantKeys) {
			t.Fatalf("output %s carries %v, want exactly %v", name, keys, wantKeys)
		}
	}
}

// TestRunPublishDisclosureFlags: C-exec-05. run accepts, per output, exactly the disclosure options publish
// accepts (the set difference is empty both ways), and each one passed to run --publish lands in the statement.
func TestRunPublishDisclosureFlags(t *testing.T) {
	conformance.Covers(t, "C-exec-05")
	flagsOf := func(name string) map[string]cli.Flag {
		for _, c := range cli.Commands() {
			if c.Name == name {
				m := map[string]cli.Flag{}
				for _, f := range c.Flags {
					m[f.Name] = f
				}
				return m
			}
		}
		t.Fatalf("no command %s", name)
		return nil
	}
	pub, rn := flagsOf("publish"), flagsOf("run")
	var disclosures []string
	for _, d := range run.Disclosure {
		disclosures = append(disclosures, strings.ReplaceAll(d, "_", "-"))
	}
	var runPer []string
	for n, f := range rn {
		if strings.HasPrefix(f.Value, "output=") && n != "of" && n != "media-type" {
			runPer = append(runPer, n)
		}
	}
	slices.Sort(runPer)
	if !slices.Equal(runPer, disclosures) {
		t.Fatalf("run's per-output disclosure options %v != the disclosure set %v", runPer, disclosures)
	}
	for _, d := range disclosures {
		pf, ok := pub[d]
		if !ok {
			t.Fatalf("publish lacks --%s", d)
		}
		if rf := rn[d]; !rf.Repeat || rf.Value != "output="+pf.Value {
			t.Fatalf("--%s: run takes %q (repeat %v), publish %q", d, rf.Value, rf.Repeat, pf.Value)
		}
	}

	w := oneOutput(t)
	g, e := w.collection(t)
	dig := func(s string) string { return run.Digest([]byte(s)) }
	vals := map[string]string{"attribution": "A. N. Other", "availability": `{"obtainable":true,"redistribution":"permitted"}`,
		"comparator": dig("cmp"), "description": "d", "extends": dig("ext"), "fulfills": `{"edition":"` + strings.Repeat("ef", 32) + `","resource":"` + strings.Repeat("ab", 32) + `"}`,
		"intended_for": g + "/" + e, "licence": "CC0-1.0", "licence_texts": `{"CC0-1.0":"` + dig("lt") + `"}`, "pre_registration": "exploratory", "replication": "bytes",
		"sampling": `{"n":10,"unit":"rows"}`, "shelf_life_days": "30", "supersedes": dig("old")}
	var args []string
	for _, d := range run.Disclosure {
		v, ok := vals[d]
		if !ok {
			t.Fatalf("no test value for disclosure %s", d)
		}
		args = append(args, "--"+strings.ReplaceAll(d, "_", "-"), "result="+v)
	}
	want(t, "every disclosure", w.publish(w.fake(writes("result.txt", "out-1")), args...), 0, `"committed":true`)
	au := w.statements("authored")
	if len(au) != 1 {
		t.Fatalf("%d authored", len(au))
	}
	for _, d := range run.Disclosure {
		if _, ok := au[0].Body.Members[d]; !ok {
			t.Errorf("disclosure %s missing from the statement: %s", d, canon.Encode(au[0].Body))
		}
	}
}

// collection signs a collection whose one edition has no rules (the pre-pin check is then ok), by a third key.
func (w *runWorld) collection(t *testing.T) (string, string) {
	s, err := store.Open(w.root, store.Options{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	k := seedKey("collection controller")
	gb := object("type", canon.String("collection"), "name", canon.String("c"), "controllers", canon.Array{canon.String(k.Signer())}, "rule", object("any_one", canon.Bool(true)))
	gl, g := wire.Sign(wire.Draft{Kind: "genesis", TS: "2026-10-16T00:00:00Z", Body: gb}, k)
	eb := object("resource", canon.String(g), "predecessors", canon.Array{canon.String(g)}, "contents", object("rules", canon.Array{}))
	el, _ := wire.Sign(wire.Draft{Kind: "edition", Seq: 1, Prev: g, TS: "2026-10-16T00:00:01Z", Body: eb}, k)
	for _, l := range [][]byte{gl, el} {
		if _, err := s.Commit("publish", [][]byte{l}, nil); err != nil {
			t.Fatal(err)
		}
	}
	return g, resolve.EditionID(eb)
}

// TestRunPublishUnpinnedInput: C-exec-03 through the command. A spec whose input is a mutable tag cannot be
// staged from a store (it holds content by hash only, and the command fetches nothing): the run is refused
// before staging, naming the input, and nothing is appended.
func TestRunPublishUnpinnedInput(t *testing.T) {
	conformance.Partial(t, "C-exec-03", "a run of an unpinned input through the command needs a way to supply the tag's bytes (none exists: the store holds content by hash and run fetches nothing); the emitted provenance_partial, no group and verify's exit 4 are the planner's and resolver's tests in internal/run")
	data := []byte("pinned")
	w := newRunWorld(t, "", [][]byte{data}, "inputs", object("feed", canon.String("registry.example/feed:latest"), "table", canon.String(run.Digest(data))),
		"outputs", object("result", canon.String("result.txt")))
	before := tree(t, w.root)
	f := w.fake(writes("result.txt", "x"))
	want(t, "unpinned", w.publish(f), 3, `"ran":false`, "registry.example/feed:latest", `"published":false`)
	if f.Spawned != 0 || tree(t, w.root) != before {
		t.Fatalf("spawned %d, store changed %v", f.Spawned, tree(t, w.root) != before)
	}
}

// TestRunPublishAcquisition: a network-requiring workflow emits observed (never authored or reproduced), and with
// --request-log the batch referent is read from the rc-request-log/1 output (format, count, shared endpoint).
func TestRunPublishAcquisition(t *testing.T) {
	ep := "https://api.example/v1/settlements"
	lg := reqlog.Encode([]reqlog.Entry{
		{Endpoint: ep, Parameters: object("period", canon.String("2026-08")), Status: 200, Time: "2026-10-16T04:59:30Z", ResponseDigest: run.Digest([]byte("a"))},
		{Endpoint: ep, Parameters: object("period", canon.String("2026-09")), Status: 200, Time: "2026-10-16T04:59:40Z", ResponseDigest: run.Digest([]byte("b"))},
	})
	spec := []any{"network", object("required", canon.Array{canon.String(ep)}), "inputs", object(),
		"outputs", object("data", canon.String("data.json"), "log", canon.String("requests.jsonl"))}
	w := newRunWorld(t, "", nil, spec...)
	f := w.fake(writes("data.json", `{"period":"2026-09"}`, "requests.jsonl", string(lg)))
	want(t, "no network grant", w.publish(f, "--request-log", "log"), 3, "refused before staging")
	if f.Spawned != 0 {
		t.Fatal("ran without a grant")
	}
	w = newRunWorld(t, `,"network":["SPEC"]`, nil, spec...)
	pol, _ := os.ReadFile(w.policy)
	os.WriteFile(w.policy, bytes.ReplaceAll(pol, []byte("SPEC"), []byte(w.spec)), 0o644)
	want(t, "observed", w.publish(f, "--request-log", "log", "--licence", "data=CC0-1.0"), 0, `"committed":true`, `"kind":"observed"`)
	obs := w.statements("observed")
	if len(obs) != 2 || len(w.statements("authored")) != 0 || len(w.statements("reproduced")) != 0 {
		t.Fatalf("%d observed", len(obs))
	}
	var data *wire.Statement
	for _, st := range obs {
		if member(st.Body, "content", "digest") == canon.String(run.Digest([]byte(`{"period":"2026-09"}`))) {
			data = st
		}
	}
	if data == nil {
		t.Fatal("no observed for the data output")
	}
	req := canon.Encode(data.Body)
	for _, s := range []string{`"format":"rc-request-log/1"`, `"count":2`, `"endpoint":"` + ep + `"`, `"digest":"` + run.Digest(lg) + `"`, `"licence":"CC0-1.0"`} {
		if !bytes.Contains(req, []byte(s)) {
			t.Fatalf("observed lacks %s: %s", s, req)
		}
	}
	// a log in another layout publishes nothing and says why
	w2 := newRunWorld(t, `,"network":["SPEC"]`, nil, spec...)
	pol, _ = os.ReadFile(w2.policy)
	os.WriteFile(w2.policy, bytes.ReplaceAll(pol, []byte("SPEC"), []byte(w2.spec)), 0o644)
	before := tree(t, w2.root)
	want(t, "bad log", w2.publish(w2.fake(writes("data.json", "{}", "requests.jsonl", "r1\nr2\n")), "--request-log", "log"), 3, `"published":false`, "rc-request-log/1")
	if tree(t, w2.root) != before {
		t.Fatal("a refused plan changed the store")
	}
}

// TestRunPublishAbortLeavesStore: the statements and the output blobs are one commit unit. A failure at the
// commit point (here: the journal cannot be written) leaves the store byte-identical: the output blobs this
// attempt installed are removed again.
func TestRunPublishAbortLeavesStore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	w := oneOutput(t)
	before := tree(t, w.root)
	pending := filepath.Join(w.root, "journal", "pending")
	if err := os.Chmod(pending, 0o555); err != nil {
		t.Fatal(err)
	}
	r := w.publish(w.fake(writes("result.txt", "out-1")))
	os.Chmod(pending, 0o755)
	if r.code == 0 || strings.Contains(r.stdout, `"committed":true`) {
		t.Fatalf("the commit did not fail: %d %s", r.code, r.stdout)
	}
	if after := tree(t, w.root); after != before {
		t.Fatalf("an aborted run --publish changed the store:\n%s\n---\n%s", before, after)
	}
	// the same run then commits
	want(t, "retry", w.publish(w.fake(writes("result.txt", "out-1"))), 0, `"committed":true`)
	if len(w.statements("authored")) != 1 {
		t.Fatal("retry did not land")
	}
}
