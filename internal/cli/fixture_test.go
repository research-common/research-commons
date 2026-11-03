package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// --- keys and statements -----------------------------------------------------------------------------------

// testKey mints a throwaway key from a name; nothing is read from or written to any key location.
func testKey(name string) wire.Key {
	h := sha256.Sum256([]byte("research-commons go test cli key " + name))
	if len(name)%2 == 0 {
		return wire.EIP191Key{Scalar: h[:]}
	}
	return wire.Ed25519Key{Seed: h[:]}
}

func dig(name string) string {
	h := sha256.Sum256([]byte(name))
	return "sha256:" + hex.EncodeToString(h[:])
}

func obj(kv ...any) *canon.Object {
	o := &canon.Object{Members: map[string]canon.Value{}}
	for i := 0; i < len(kv); i += 2 {
		k := kv[i].(string)
		var v canon.Value
		switch x := kv[i+1].(type) {
		case canon.Value:
			v = x
		case string:
			v = canon.String(x)
		case int:
			v = canon.Int(x)
		case bool:
			v = canon.Bool(x)
		case []string:
			a := canon.Array{}
			for _, s := range x {
				a = append(a, canon.String(s))
			}
			v = a
		default:
			panic(fmt.Sprintf("obj: %T", x))
		}
		o.Keys = append(o.Keys, k)
		o.Members[k] = v
	}
	return o
}

// world signs statements into per-key logs and commits them into a real store, one operation per statement.
type world struct {
	t     testing.TB
	root  string
	s     *store.Store
	keys  map[string]wire.Key
	head  map[string]string
	seq   map[string]int64
	ids   map[string]string
	blobs map[string]string // name -> digest, for blobs installed in the store
}

func newWorld(t testing.TB) *world {
	t.Helper()
	root := t.TempDir()
	s, err := store.Open(root, store.Options{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	return &world{t: t, root: root, s: s, keys: map[string]wire.Key{}, head: map[string]string{}, seq: map[string]int64{},
		ids: map[string]string{}, blobs: map[string]string{}}
}

func (w *world) key(n string) wire.Key {
	if k, ok := w.keys[n]; ok {
		return k
	}
	k := testKey(n)
	w.keys[n] = k
	return k
}

func (w *world) signer(n string) string { return w.key(n).Signer() }

// blob installs bytes into the store.
func (w *world) blob(name string, b []byte) string {
	w.t.Helper()
	d, _, err := w.s.InstallBlob(bytes.NewReader(b), "")
	if err != nil {
		w.t.Fatal(err)
	}
	w.blobs[name] = string(d)
	return string(d)
}

func (w *world) sign(name, n, kind string, body *canon.Object) string {
	w.t.Helper()
	s := w.seq[n]
	line, id := wire.Sign(wire.Draft{Kind: kind, Seq: s, Prev: w.head[n], TS: fmt.Sprintf("2026-10-16T02:%02d:%02dZ", s/60%60, s%60), Body: body}, w.key(n))
	if _, err := w.s.Commit("publish", [][]byte{line}, nil); err != nil {
		w.t.Fatalf("%s: %v", name, err)
	}
	w.head[n], w.seq[n] = id, s+1
	w.ids[name] = id
	return id
}

func content(x string) *canon.Object { return obj("digest", dig(x), "size", len(x)) }

// authored signs an `authored` by key n for blob x; "prov" takes [workflow, inputs...] blob names.
func (w *world) authored(name, n, x string, kv ...any) string {
	b := []any{"content", canon.Value(content(x))}
	if !slices.Contains(kv, any("type")) {
		b = append(b, "type", "dataset")
	}
	for i := 0; i < len(kv); i += 2 {
		if kv[i] == "prov" {
			p := kv[i+1].([]string)
			in := []string{}
			for _, y := range p[1:] {
				in = append(in, dig(y))
			}
			b = append(b, "provenance", canon.Value(obj("workflow", dig(p[0]), "inputs", in)))
			continue
		}
		b = append(b, kv[i], kv[i+1])
	}
	return w.sign(name, n, "authored", obj(b...))
}

// workflow publishes workflow blob wf with a replication mode and comparator.
func (w *world) workflow(n, wf, mode, comparator string) {
	kv := []any{"type", "workflow", "replication", mode}
	if comparator != "" {
		kv = append(kv, "comparator", dig(comparator))
	}
	w.authored("wf:"+wf, n, wf, kv...)
}

// anchor signs an anchors statement by n over its head with a proof whose one Bitcoin attestation names
// height: the proof parses, and with no chain backend it is backend-unconfigured.
func (w *world) anchor(name, n string, height uint64) string {
	cov, _ := hex.DecodeString(w.head[n])
	att := append([]byte{0x00}, btctime.TagBitcoin[:]...)
	payload := uvar(height)
	att = append(att, append(uvar(uint64(len(payload))), payload...)...)
	proof := append(append(append([]byte{}, btctime.HeaderMagic...), 0x01, 0x08), cov...)
	proof = append(proof, att...)
	d := w.blob("proof:"+name, proof)
	return w.sign(name, n, "anchors", obj("covered", w.head[n], "proof", d, "proof_format", btctime.ProofFormat))
}

func uvar(n uint64) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			out = append(out, b|0x80)
			continue
		}
		return append(out, b)
	}
}

// Hostile is peer text with terminal escapes (OSC title set, CSI colour, a C1 CSI, BEL), a bidirectional
// override, HTML and shell metacharacters (C-core-122).
const Hostile = "\x1b]0;owned\x07\x1b[31mred\u009b2J\u202eevil<script>alert(1)</script>$(touch /tmp/rc-pwned)`id`;|&>x"

// fixture builds the full fixture set every sweep runs over. Names of blobs:
//
//	sole       one author, no provenance, licence declared, bytes held          verify 0
//	contested  two keys claim it, no verified bound (anchors, no backend)         verify 3 contested
//	nobody     no statement names it                                            verify 3 no authorship claim
//	t0         two keys derive it byte-identically under a bytes workflow        verify 0 (T0)
//	div1       two keys derive different bytes under a bytes workflow           verify 1 diverged
//	prot1      two keys derive different bytes under a protocol workflow,
//	           no comparator runner configured                                  verify 3 unchecked
//	solo       one key derives it, nobody re-derived                            verify 3 not re-derived
//	partial    authored with partial provenance (an unpinned input)             verify 4 unpinned
//	retracted  its author retracts it                                           label retracted
//	hostile    described with Hostile text in note, tags and an unknown kind
func fixture(t testing.TB) *world {
	w := newWorld(t)
	w.blob("sole", []byte("sole"))
	w.authored("A:sole", "K1", "sole", "licence", "CC-BY-4.0", "description", Hostile)
	w.authored("A:contested:1", "K1", "contested")
	w.anchor("anc1", "K1", 800000)
	w.authored("A:contested:2", "K2", "contested")
	w.anchor("anc2", "K2", 800001)

	w.workflow("K1", "wfB", "bytes", "")
	w.authored("A:t0:1", "K1", "t0", "prov", []string{"wfB", "in1"})
	w.authored("A:t0:2", "K2", "t0", "prov", []string{"wfB", "in1"})
	w.authored("A:div1", "K1", "div1", "prov", []string{"wfB", "in2"})
	w.authored("A:div2", "K2", "div2", "prov", []string{"wfB", "in2"})
	w.workflow("K1", "wfP", "protocol", "cmp")
	w.authored("A:prot1", "K1", "prot1", "prov", []string{"wfP", "in3"})
	w.authored("A:prot2", "K2", "prot2", "prov", []string{"wfP", "in3"})
	w.authored("A:solo", "K3", "solo", "prov", []string{"wfB", "in4"})
	w.authored("A:partial", "K3", "partial", "provenance_partial",
		canon.Value(obj("workflow", dig("wfB"), "inputs", []string{}, "unpinned", []string{"feed:latest"})))
	w.authored("A:retracted", "K3", "retracted")
	w.sign("R:retracted", "K3", "retracts", obj("of", w.ids["A:retracted"], "reason", Hostile))
	w.sign("D:hostile", "K4", "describes", obj("about", canon.Value(obj("content", dig("sole"))), "note", Hostile,
		"tags", []string{Hostile, "<b>"}))
	w.sign("U:hostile", "K4", "x_"+"hostile", obj("text", Hostile))
	w.gitHub() // the store is also a hub clone: hub check sweeps it (sweep_test.go)
	return w
}

// --- running the binary in-process -------------------------------------------------------------------------

type result struct {
	code           int
	stdout, stderr string
}

func (w *world) run(args ...string) result {
	return runIn(w.root, nil, args...)
}

func runIn(wd string, env map[string]string, args ...string) result {
	var o, e bytes.Buffer
	code := Main(args, &Env{Stdout: &o, Stderr: &e, Getenv: func(k string) string { return env[k] },
		Getwd: func() (string, error) { return wd, nil }, Build: Build{Version: "test", Commit: "0000000"}})
	return result{code, o.String(), e.String()}
}

// jsonOf parses a --json output with the strict reader.
func jsonOf(t testing.TB, r result) *canon.Object {
	t.Helper()
	v, err := canon.Parse(bytes.TrimSuffix([]byte(r.stdout), []byte("\n")))
	if err != nil {
		t.Fatalf("output is not strict JSON: %v\n%s", err, r.stdout)
	}
	o, ok := v.(*canon.Object)
	if !ok {
		t.Fatalf("output is not an object: %s", r.stdout)
	}
	return o
}

// collect returns every string under a token member, anywhere in v, with its JSON path.
func collect(v canon.Value, path string, out map[string]string) {
	switch x := v.(type) {
	case *canon.Object:
		for _, k := range x.Keys {
			m := x.Members[k]
			if IsTokenKey(k) {
				switch y := m.(type) {
				case canon.String:
					out[path+"."+k] = string(y)
					continue
				case canon.Array:
					all := true
					for i, e := range y {
						if s, ok := e.(canon.String); ok {
							out[fmt.Sprintf("%s.%s[%d]", path, k, i)] = string(s)
						} else {
							all = false
						}
					}
					if all {
						continue
					}
				}
			}
			collect(m, path+"."+k, out)
		}
	case canon.Array:
		for i, e := range x {
			collect(e, fmt.Sprintf("%s[%d]", path, i), out)
		}
	}
}

// snapshot is every path, mode and content under root: the "root unchanged" check of C-core-133a.
func snapshot(t testing.TB, root string) string {
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
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// refsOf is every argument the sweep passes: each fixture blob's digest, every statement id, an id and a
// digest nobody holds.
func (w *world) refsOf() []string {
	var out []string
	for _, n := range []string{"sole", "contested", "nobody", "t0", "div1", "prot1", "solo", "partial", "retracted"} {
		out = append(out, dig(n))
	}
	names := make([]string, 0, len(w.ids))
	for n := range w.ids {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, w.ids[n])
	}
	return append(out, strings.Repeat("ab", 32))
}
