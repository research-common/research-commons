package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

func obj(kv ...any) *canon.Object {
	o := &canon.Object{Members: map[string]canon.Value{}}
	for i := 0; i < len(kv); i += 2 {
		k := kv[i].(string)
		o.Keys = append(o.Keys, k)
		switch v := kv[i+1].(type) {
		case string:
			o.Members[k] = canon.String(v)
		case int:
			o.Members[k] = canon.Int(v)
		case bool:
			o.Members[k] = canon.Bool(v)
		case []string:
			a := canon.Array{}
			for _, s := range v {
				a = append(a, canon.String(s))
			}
			o.Members[k] = a
		case canon.Value:
			o.Members[k] = v
		default:
			panic(fmt.Sprintf("obj: %T", v))
		}
	}
	slices.SortFunc(o.Keys, canon.CompareKeys)
	return o
}

func testKey(name string) wire.Key {
	h := sha256.Sum256([]byte("research-commons go test gate key " + name))
	if len(name)%2 == 0 {
		return wire.EIP191Key{Scalar: h[:]}
	}
	return wire.Ed25519Key{Seed: h[:]}
}

func blobDigest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// world signs statements into per-key logs, chaining each key's lines in the order the test writes them.
type world struct {
	t     *testing.T
	keys  map[string]wire.Key
	head  map[string]string
	seq   map[string]int64
	lines map[string][]byte // id -> line
	by    map[string]string // id -> key name
}

func newWorld(t *testing.T) *world {
	return &world{t: t, keys: map[string]wire.Key{}, head: map[string]string{}, seq: map[string]int64{},
		lines: map[string][]byte{}, by: map[string]string{}}
}

func (w *world) key(n string) wire.Key {
	k, ok := w.keys[n]
	if !ok {
		k = testKey(n)
		w.keys[n] = k
	}
	return k
}

func (w *world) signer(n string) string { return w.key(n).Signer() }

func (w *world) sign(n, kind string, body *canon.Object) string {
	k := w.key(n)
	s := w.seq[n]
	line, id := wire.Sign(wire.Draft{Kind: kind, Seq: s, Prev: w.head[n], TS: fmt.Sprintf("2026-10-16T02:%02d:%02dZ", s/60%60, s%60), Body: body}, k)
	w.head[n], w.seq[n] = id, s+1
	w.lines[id], w.by[id] = line, n
	return id
}

func contentOf(b []byte) *canon.Object { return obj("digest", blobDigest(b), "size", len(b)) }

func (w *world) authored(n string, blob []byte, kv ...any) string {
	return w.sign(n, "authored", obj(append([]any{"content", canon.Value(contentOf(blob)), "type", "dataset"}, kv...)...))
}

func (w *world) observed(n string, blob []byte) string {
	return w.sign(n, "observed", obj("content", canon.Value(contentOf(blob)), "class", "none-yet", "referent", canon.Value(obj()),
		"capture", canon.Value(obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted"))))
}

// path is the data-surface path of a statement this world signed.
func (w *world) path(id string) string { return StatementPath(w.signer(w.by[id]), id) }

// obj returns the package object for a statement this world signed.
func (w *world) object(id string) Object { return Object{Path: w.path(id), Data: w.lines[id]} }

func blobObject(b []byte) Object { return Object{Path: BlobPath(blobDigest(b)), Data: b} }

func heldOf(lines map[string][]byte, blobs ...[]byte) MemHeld {
	h := MemHeld{Lines: map[string][]byte{}, Blobs: map[string]bool{}}
	for id, l := range lines {
		h.Lines[id] = l
	}
	for _, b := range blobs {
		h.Blobs[blobDigest(b)] = true
	}
	return h
}

func (w *world) held(ids ...string) MemHeld {
	m := map[string][]byte{}
	for _, id := range ids {
		m[id] = w.lines[id]
	}
	return heldOf(m)
}

func mustAdmit(t *testing.T, gate string, pkg Package, held Held, pol *Policy, opt Options) *Report {
	t.Helper()
	var f func(Package, Held, *Policy, Options) (*Report, error)
	switch gate {
	case "pull":
		f = Pull
	case "push":
		f = Push
	case "hub check":
		f = HubCheck
	case "pre-pin":
		f = PrePin
	default:
		t.Fatalf("gate %q", gate)
	}
	rep, err := f(pkg, held, pol, opt)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func get(t *testing.T, rep *Report, path string) *Result {
	t.Helper()
	r, ok := rep.Result(path)
	if !ok {
		t.Fatalf("no result for %s", path)
	}
	return r
}

func wantRefused(t *testing.T, rep *Report, path string, class refusal.Class, reason string) *Result {
	t.Helper()
	r := get(t, rep, path)
	if r.Verdict != Refused || r.Refusal.Class != class || r.Refusal.Reason != reason {
		t.Fatalf("%s: want refused %s/%s, got %s %v\n%s", path, class, reason, r.Verdict, r.Refusal, rep.Render())
	}
	if r.Scope == "" || !strings.Contains(r.Refusal.Detail, "scope") {
		t.Fatalf("%s: refusal names no scope: %v", path, r.Refusal)
	}
	if strings.Contains(strings.ToLower(r.Next), "force") {
		t.Fatalf("%s: next step proposes a force: %s", path, r.Next)
	}
	return r
}

func wantAdmitted(t *testing.T, rep *Report, path string) *Result {
	t.Helper()
	r := get(t, rep, path)
	if r.Verdict != Admitted {
		t.Fatalf("%s: want admitted, got %s %v\n%s", path, r.Verdict, r.Refusal, rep.Render())
	}
	return r
}

// signature is a result reduced to what must agree across gates: verdict, class, reason, label tokens.
func signature(r Result) string {
	s := string(r.Verdict)
	if r.Refusal != nil {
		s += "|" + string(r.Refusal.Class) + "|" + r.Refusal.Reason
	}
	var ls []string
	for _, l := range r.Labels {
		ls = append(ls, l.Token)
	}
	return s + "|" + strings.Join(ls, ",")
}
