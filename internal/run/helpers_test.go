package run

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// --- specs ---------------------------------------------------------------------------------------------------

const (
	imgRef   = "registry.example/step:1"
	platAmd  = "linux/amd64"
	platArm  = "linux/arm64/v8"
	ownerKey = "A"
)

var imgDigest = Digest([]byte("image manifest amd64"))

// specB builds spec bytes. code names the step (its code bytes are "code:"+code). kv overrides or adds
// top-level members; a nil value removes one.
func specB(code string, inputs map[string]string, kv ...any) []byte {
	in := &canon.Object{Members: map[string]canon.Value{}}
	for k, v := range inputs {
		in.Keys = append(in.Keys, k)
		in.Members[k] = canon.String(v)
	}
	slices.SortFunc(in.Keys, canon.CompareKeys)
	m := map[string]canon.Value{
		"code":        canon.String(Digest([]byte("code:" + code))),
		"interpreter": canon.String("sh >=1"),
		"image":       object("reference", canon.String(imgRef), "digest", canon.String(imgDigest)),
		"inputs":      in,
		"outputs":     object("result", canon.String("result.txt")),
		"resources":   object("memory", canon.Int(1<<20), "wall_time", canon.Int(10_000)),
	}
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(m, kv[i].(string))
			continue
		}
		m[kv[i].(string)] = kv[i+1].(canon.Value)
	}
	o := &canon.Object{Members: m}
	for k := range m {
		o.Keys = append(o.Keys, k)
	}
	slices.SortFunc(o.Keys, canon.CompareKeys)
	return canon.Encode(o)
}

func mustSpec(t testing.TB, b []byte) *Spec {
	t.Helper()
	s, err := ParseSpec(b)
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	return s
}

// blobsFor supplies the code and every pinned input whose bytes are "input:"+name... resolved through data.
func blobsFor(s *Spec, code string, data map[string][]byte) map[string][]byte {
	b := map[string][]byte{s.Code: []byte("code:" + code)}
	for _, v := range data {
		b[Digest(v)] = v
	}
	return b
}

// --- fake steps ----------------------------------------------------------------------------------------------

// writeStep writes content to out/result.txt, using few resources.
func writeStep(content string) Step {
	return func(_ context.Context, _, out string, _ map[string]string) (int, Resources) {
		_ = os.WriteFile(filepath.Join(out, "result.txt"), []byte(content), 0o644)
		return 0, Resources{CapMemory: 1000, CapWallTime: 5, CapPids: 1, CapDisk: int64(len(content))}
	}
}

// catStep concatenates the named input files into result.txt.
func catStep(names ...string) Step {
	return func(_ context.Context, in, out string, _ map[string]string) (int, Resources) {
		var b []byte
		for _, n := range names {
			x, err := os.ReadFile(filepath.Join(in, n))
			if err != nil {
				return 2, Resources{}
			}
			b = append(b, x...)
		}
		_ = os.WriteFile(filepath.Join(out, "result.txt"), b, 0o644)
		return 0, Resources{CapMemory: 1000, CapWallTime: 5, CapPids: 1}
	}
}

func useStep(r Resources) Step {
	return func(_ context.Context, _, out string, _ map[string]string) (int, Resources) {
		_ = os.WriteFile(filepath.Join(out, "result.txt"), []byte("partial"), 0o644)
		return 0, r
	}
}

func newFake() *Fake {
	return &Fake{Images: map[string]string{imgDigest: platAmd}, Steps: map[string]Step{}}
}

func (f *Fake) step(code string, s Step) *Fake {
	f.Steps[Digest([]byte("code:"+code))] = s
	return f
}

func grantAll() *Policy {
	return &Policy{ExecSigners: []string{ownerKey}, Ceiling: Resources{CapMemory: 1 << 30, CapWallTime: 60_000, CapPids: 256, CapDisk: 1 << 30}}
}

func wantRefusal(t testing.TB, err error, class refusal.Class, reason string, detail ...string) *refusal.Refusal {
	t.Helper()
	var r *refusal.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("want refusal %s: %s, got %v", class, reason, err)
	}
	if r.Class != class || r.Reason != reason {
		t.Fatalf("want refusal %s: %s, got %s: %s (%s)", class, reason, r.Class, r.Reason, r.Detail)
	}
	for _, d := range detail {
		if !strings.Contains(r.Detail, d) {
			t.Fatalf("refusal detail %q lacks %q", r.Detail, d)
		}
	}
	return r
}

func has(t testing.TB, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("missing %q in\n%s", sub, s)
	}
}

func hasNot(t testing.TB, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Fatalf("unexpected %q in\n%s", sub, s)
	}
}

// --- a signing world for the resolver ------------------------------------------------------------------------

type world struct {
	t     testing.TB
	keys  map[string]wire.Key
	head  map[string]string
	seq   map[string]int64
	lines [][]byte
}

func newWorld(t testing.TB) *world {
	return &world{t: t, keys: map[string]wire.Key{}, head: map[string]string{}, seq: map[string]int64{}}
}

func (w *world) key(n string) wire.Key {
	k, ok := w.keys[n]
	if !ok {
		h := sha256.Sum256([]byte("research-commons go test run key " + n))
		k = wire.Ed25519Key{Seed: h[:]}
		w.keys[n] = k
	}
	return k
}

func (w *world) signer(n string) string { return w.key(n).Signer() }

// sign writes through wire.Write, so every body passes the one validation core.
func (w *world) sign(n, kind string, body *canon.Object) string {
	w.t.Helper()
	s := w.seq[n]
	st, err := wire.Write(wire.Draft{Kind: kind, Seq: s, Prev: w.head[n], TS: fmt.Sprintf("2026-10-16T03:%02d:%02dZ", s/60%60, s%60), Body: body},
		w.key(n), time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC))
	if err != nil {
		w.t.Fatalf("sign %s by %s: %v", kind, n, err)
	}
	w.head[n], w.seq[n] = st.ID, s+1
	w.lines = append(w.lines, st.Line())
	return st.ID
}

// workflow publishes the workflow spec's `authored` with replication, comparator and optional extra fields.
func (w *world) workflow(n string, spec []byte, mode, comparator string, extra ...any) string {
	b := &builder{o: &canon.Object{Members: map[string]canon.Value{}}}
	b.set("content", object("digest", canon.String(Digest(spec)), "size", canon.Int(int64(len(spec)))))
	b.set("type", canon.String("workflow"))
	if mode != "" {
		b.set("replication", canon.String(mode))
	}
	if comparator != "" {
		b.set("comparator", canon.String(comparator))
	}
	for i := 0; i < len(extra); i += 2 {
		b.set(extra[i].(string), extra[i+1].(canon.Value))
	}
	return w.sign(n, "authored", b.done())
}

func (w *world) resolver(opts ...resolve.Option) *resolve.Resolver {
	w.t.Helper()
	s := keylog.NewStore()
	for _, l := range w.lines {
		st, err := wire.Read(l)
		if err != nil {
			w.t.Fatal(err)
		}
		if kept, err := s.Log(st.Signer).Add(l); err != nil && kept == nil {
			w.t.Fatal(err)
		}
	}
	return resolve.New(s, opts...)
}

// publish signs every planned statement by key n and returns their ids by output.
func (w *world) publish(n string, plan []Planned) map[string]string {
	ids := map[string]string{}
	for _, p := range plan {
		ids[p.Output] = w.sign(n, p.Kind, p.Body)
	}
	return ids
}

func readFile(dir, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	return string(b), err
}

func writeOut(dir, name, content string) Resources {
	_ = os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
	return Resources{CapMemory: 100, CapWallTime: 1, CapPids: 1, CapDisk: int64(len(content))}
}

func resolveSingleParty() []string { return resolve.SingleParty }
