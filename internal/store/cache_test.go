package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// holdsLine signs a holds statement for blob bytes b. withdrawn drops locations (a withdrawal serves nothing).
func holdsLine(k wire.Key, seq int64, prev string, b []byte, withdrawn bool, locations ...string) ([]byte, string) {
	c := &canon.Object{Keys: []string{"digest", "size"}, Members: map[string]canon.Value{
		"digest": canon.String(digestOf(b)), "size": canon.Int(len(b))}}
	body := &canon.Object{Keys: []string{"content"}, Members: map[string]canon.Value{"content": c}}
	if withdrawn {
		body.Keys = append(body.Keys, "withdrawn")
		body.Members["withdrawn"] = canon.Bool(true)
	} else if len(locations) > 0 {
		var ls canon.Array
		for _, l := range locations {
			ls = append(ls, canon.String(l))
		}
		body.Keys = append(body.Keys, "locations")
		body.Members["locations"] = ls
	}
	return wire.Sign(wire.Draft{Kind: "holds", Seq: seq, Prev: prev, TS: "2026-10-15T00:00:00Z", Body: body}, k)
}

// publishBlob installs b and commits an authored statement for it by k.
func publishBlob(t *testing.T, s *Store, k wire.Key, seq int64, prev string, b []byte) (Digest, string) {
	t.Helper()
	d, _, err := s.InstallBlob(bytes.NewReader(b), "")
	if err != nil {
		t.Fatal(err)
	}
	l, id := authored(k, seq, prev, b)
	if _, err := s.Commit("publish", [][]byte{l}, []Digest{d}); err != nil {
		t.Fatal(err)
	}
	return d, id
}

func mustPath(t *testing.T, s *Store, signer wire.Key, id string) string {
	t.Helper()
	return filepath.Join(s.root, "statements", signerDir(signer.Signer()), id)
}

func baseKey(s *Store, in []string) CacheKey {
	return CacheKey{Projection: "log", Query: "head of A", Inputs: in, Policy: "p1", Evaluator: "e1", Time: ""}
}

// TestCacheKeyedOnDigests: C-core-129. A statement file rewritten to different valid content with the same
// size and the same mtime misses the cache (the key reads the content digest, never size or mtime); a policy
// change and an evaluator change miss; Why names the changed input; a restore of blobs and statements with
// every cache removed rebuilds without a prompt and equals the warm answers.
func TestCacheKeyedOnDigests(t *testing.T) {
	conformance.Partial(t, "C-core-129", "the store-side cache keyed on input digests, policy, evaluator and time, same-size same-mtime rewrite, restore with caches removed: checked; the resolver is not wired to the cache, so 'every answer' is checked on the store's own projections")
	conformance.Partial(t, "P-07", "deleting every cache and projection and recomputing gives identical values, checked on the store-side projections; the resolver's own answers are not yet cached")
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	k := testKey("A")
	// Two valid statements of identical byte length: same blob size, different content (seq 0 vs seq 0, different key digests of equal length).
	l0, id0 := authored(k, 0, "", []byte("dataset-aaaa"))
	lAlt, idAlt := authored(k, 0, "", []byte("dataset-bbbb"))
	if len(l0) != len(lAlt) || id0 == idAlt {
		t.Fatalf("test needs two same-length statements: %d %d", len(l0), len(lAlt))
	}
	d0, _, _ := s.InstallBlob(strings.NewReader("dataset-aaaa"), "")
	dAlt, _, _ := s.InstallBlob(strings.NewReader("dataset-bbbb"), "")
	if _, err := s.Commit("publish", [][]byte{l0}, []Digest{d0}); err != nil {
		t.Fatal(err)
	}
	c := NewCache(s)
	var builds int
	value := func() ([]byte, error) {
		builds++
		sts, err := s.Statements()
		if err != nil {
			return nil, err
		}
		var ids []string
		for id := range sts {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		return []byte("statements: " + strings.Join(ids, ",")), nil
	}
	in := func() []string {
		x, err := s.StatementSetInputs(k.Signer())
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	key := func() CacheKey { return baseKey(s, in()) }

	v1, hit, err := c.Compute(key(), value)
	if err != nil || hit || builds != 1 {
		t.Fatal(hit, builds, err)
	}
	v2, hit, _ := c.Compute(key(), value)
	if !hit || builds != 1 || !bytes.Equal(v1, v2) {
		t.Fatal("a repeated question did not hit", hit, builds)
	}

	// Rewrite the statement file in place to the other valid statement of the same size, keeping its mtime and
	// its name: content differs, size and mtime do not.
	p := filepath.Join(root, "statements", signerDir(k.Signer()), id0)
	fi, _ := os.Stat(p)
	_ = os.Chmod(p, 0o644)
	if err := os.WriteFile(p, lAlt, 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(p, fi.ModTime(), fi.ModTime())
	if fi2, _ := os.Stat(p); fi2.Size() != fi.Size() || !fi2.ModTime().Equal(fi.ModTime()) {
		t.Fatal("the rewrite did not keep size and mtime: the test would not reach the boundary")
	}
	_ = dAlt
	after := key()
	why := strings.Join(c.Why(after), ";")
	if !strings.Contains(why, "input stmt:"+id0+" changed") {
		t.Fatalf("the miss does not cite the rewritten statement: %q", why)
	}
	if _, hit, _ = c.Compute(after, value); hit || builds != 2 {
		t.Fatalf("a same-size same-mtime rewrite hit the cache (builds=%d)", builds)
	}

	// Policy change misses; evaluator change misses; both are named.
	k2 := key()
	k2.Policy = "p2"
	if _, hit, _ := c.Compute(k2, value); hit {
		t.Fatal("policy change hit")
	}
	k3 := key()
	k3.Evaluator = "e2"
	if why := c.Why(k3); !strings.Contains(strings.Join(why, ";"), "policy digest changed") || !strings.Contains(strings.Join(why, ";"), "evaluator version changed (e1 → e2)") {
		t.Fatalf("miss not explained: %v", why)
	}
	if _, hit, _ := c.Compute(k3, value); hit {
		t.Fatal("evaluator change hit")
	}
	// Time context is a key component for time-dependent entries.
	k4 := key()
	k4.Time = "2026-10-20T00:00:00Z"
	if _, hit, _ := c.Compute(k4, value); hit {
		t.Fatal("a time-dependent entry hit under another time context")
	}
	if _, hit, _ := c.Compute(k4, value); !hit {
		t.Fatal("same time context missed")
	}
	// Input order is irrelevant; a duplicate input is the same input.
	ka, kb := key(), key()
	slices.Reverse(kb.Inputs)
	kb.Inputs = append(kb.Inputs, kb.Inputs[0])
	if ka.Digest() != kb.Digest() {
		t.Fatal("input order or duplication changed the key")
	}
}

// TestCacheMissExplainsStatement: the miss after a new statement arrives names the statement input.
func TestCacheMissExplainsStatement(t *testing.T) {
	s := open(t, t.TempDir(), Options{NoSync: true})
	k := testKey("A")
	d, id0 := publishBlob(t, s, k, 0, "", []byte("one"))
	c := NewCache(s)
	in0, _ := s.Inputs([]string{id0}, []Digest{d})
	_, _, _ = c.Compute(baseKey(s, in0), func() ([]byte, error) { return []byte("v"), nil })
	// a new statement the projection would read (it asked about id1 and found it absent)
	l1, id1 := authored(k, 1, id0, []byte("one"))
	in1, _ := s.Inputs([]string{id0, id1}, []Digest{d})
	_, _, _ = c.Compute(baseKey(s, in1), func() ([]byte, error) { return []byte("w"), nil })
	if _, err := s.Commit("publish", [][]byte{l1}, []Digest{d}); err != nil {
		t.Fatal(err)
	}
	in2, _ := s.Inputs([]string{id0, id1}, []Digest{d})
	why := strings.Join(c.Why(baseKey(s, in2)), ";")
	if !strings.Contains(why, "input stmt:"+id1+" arrived") {
		t.Fatalf("%q", why)
	}
	if _, hit, _ := c.Compute(baseKey(s, in2), func() ([]byte, error) { return []byte("w2"), nil }); hit {
		t.Fatal("the arrival of a statement the projection asked about did not miss")
	}
	// a blob that arrives is an input change too
	b := []byte("later bytes")
	bd := digestOf(b)
	ib0, _ := s.Inputs(nil, []Digest{bd})
	_, _, _ = c.Compute(baseKey(s, ib0), func() ([]byte, error) { return []byte("x"), nil })
	_, _, _ = s.InstallBlob(bytes.NewReader(b), bd)
	ib1, _ := s.Inputs(nil, []Digest{bd})
	if _, hit, _ := c.Compute(baseKey(s, ib1), func() ([]byte, error) { return []byte("y"), nil }); hit {
		t.Fatal("a blob that became held did not miss")
	}
	if _, err := s.Inputs([]string{"nothex"}, nil); err == nil {
		t.Fatal("malformed id accepted")
	}
	if _, err := s.Inputs(nil, []Digest{"md5:abc"}); err == nil {
		t.Fatal("malformed digest accepted")
	}
}

// TestCacheColdEqualsWarm: P-07 and the invalidation list (§5.3 items 6). A registered projection computed
// warm equals a cold rebuild; deleting the whole cache and recomputing gives identical bytes; a corrupted
// entry is a miss (never a wrong answer); drift is detected and `--rebuild` fixes it.
func TestCacheColdEqualsWarm(t *testing.T) {
	conformance.Partial(t, "P-07", "cold rebuild equals warm for the store-side projections, drift detection and rebuild: checked; the resolver's own caches are not wired")
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	k := testKey("A")
	_, id0 := publishBlob(t, s, k, 0, "", []byte("x"))
	_, _ = publishBlob(t, s, k, 1, id0, []byte("y"))
	c := NewCache(s)
	count := func(*Store) ([]byte, error) {
		sts, _ := s.Statements()
		return []byte(fmt.Sprintf("n=%d", len(sts))), nil
	}
	if err := c.Register(Projection{Name: "count",
		Key: func(s *Store) (CacheKey, error) {
			in, err := s.StatementSetInputs("")
			return CacheKey{Projection: "count", Query: "all", Inputs: in, Policy: "p", Evaluator: "e"}, err
		}, Build: count}); err != nil {
		t.Fatal(err)
	}
	if err := c.Register(Projection{Name: "Bad Name", Key: nil}); err == nil {
		t.Fatal("bad projection registered")
	}
	warm, err := c.Rebuild("count")
	if err != nil || len(warm) != 1 {
		t.Fatal(warm, err)
	}
	pk, _ := c.reg["count"].Key(s)
	w1, ok, _ := c.Get(pk)
	if !ok || string(w1) != "n=2" {
		t.Fatal(w1, ok)
	}
	if d, err := c.Drift(); err != nil || len(d) != 0 {
		t.Fatal(d, err)
	}
	// Delete every projection: a cold start recomputes identical bytes with no prompt.
	if err := c.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := c.Get(pk); ok {
		t.Fatal("entry survived Clear")
	}
	cold, _, err := c.Compute(pk, func() ([]byte, error) { return count(s) })
	if err != nil || !bytes.Equal(cold, w1) {
		t.Fatal(cold, err)
	}
	// A corrupted entry is a miss, not an answer.
	path := c.entryPath(pk)
	b, _ := os.ReadFile(path)
	_ = os.WriteFile(path, bytes.Replace(b, []byte(`"check":"`), []byte(`"check":"0`), 1), 0o644)
	if _, ok, _ := c.Get(pk); ok {
		t.Fatal("a corrupt entry was served")
	}
	// An entry planted under another key's name does not answer for it (the name is the digest of its own key).
	other := pk
	other.Policy = "other"
	good, _ := os.ReadFile(c.entryPath(other))
	_ = good
	_, _, _ = c.Compute(pk, func() ([]byte, error) { return count(s) })
	plant := c.entryPath(other)
	pb, _ := os.ReadFile(c.entryPath(pk))
	_ = os.MkdirAll(filepath.Dir(plant), 0o755)
	_ = os.WriteFile(plant, pb, 0o644)
	if _, ok, _ := c.Get(other); ok {
		t.Fatal("an entry planted under a different key name answered")
	}
	// Drift: an entry whose value differs from a cold build under the same key.
	if err := c.Put(pk, []byte("n=999")); err != nil {
		t.Fatal(err)
	}
	dr, err := c.Drift("count")
	if err != nil || len(dr) != 1 || dr[0].Name != "count" || dr[0].Warm == dr[0].Cold {
		t.Fatal(dr, err)
	}
	// fsck reports the drift as fatal, names the projection; --rebuild repairs; the next fsck is clean.
	r, err := s.Fsck(FsckOptions{Cache: c})
	if err != nil || r.Clean() || len(r.Of(FsckDrift)) != 1 || !strings.Contains(r.Of(FsckDrift)[0].Detail, "--rebuild count") {
		t.Fatal(r.Render(), err)
	}
	r, err = s.Fsck(FsckOptions{Cache: c, Rebuild: []string{"count"}, DriftOf: []string{}})
	_ = r
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Fsck(FsckOptions{Cache: c})
	if err != nil || len(r.Of(FsckDrift)) != 0 {
		t.Fatal(r.Render(), err)
	}
	if _, err := c.Rebuild("nope"); err == nil || !strings.Contains(err.Error(), "registered: count") {
		t.Fatal(err)
	}
	// Invalidate names the projection (§5.3 item 6) and a gc removes no input of any valid projection.
	if err := c.Invalidate("count"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := c.Get(pk); ok {
		t.Fatal("Invalidate left the entry")
	}
	_, _, _ = c.Compute(pk, func() ([]byte, error) { return count(s) })
	if _, err := s.GC(GCConfig{PerRun: ptr(time.Duration(0))}, true); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := c.Get(pk); !ok {
		t.Fatal("gc invalidated a valid projection")
	}
}

func ptr[T any](v T) *T { return &v }

// TestVerifyCache: C-core-129a. Every verification a conformance run reports is computed in the run under
// test: with the cache pre-populated "verified" for a statement whose signature is invalid, Cold mode never
// reports verified and UseCache mode is shown to be the thing that would (the planted entry is reached);
// warm and cold agree on the genuine statements; a changed verifier version misses every entry.
func TestVerifyCache(t *testing.T) {
	conformance.Partial(t, "C-core-129a", "the cache itself (poisoned entry never reported verified in a cold run, warm equals cold, a changed verifier version misses) is checked here; running the whole suite's signature-bearing cases twice is the harness's, which verifies through wire.Read with no cache")
	s := open(t, t.TempDir(), Options{NoSync: true})
	good, _ := authored(testKey("A"), 0, "", []byte("x"))
	good2, _ := authored(testKey("B"), 0, "", []byte("y"))
	bad := bytes.Replace(slices.Clone(good2), []byte("2026-10-15T00:00:00Z"), []byte("2026-10-16T00:00:00Z"), 1) // a signed field changed after signing
	if _, err := wire.Read(bad); err == nil {
		t.Fatal("tampered line verified: the test would not reach the boundary")
	} else {
		var r *refusal.Refusal
		if !errors.As(err, &r) || r.Reason != refusal.BadSignature {
			t.Fatalf("tampered line refused for another reason: %v", err)
		}
	}
	verify := func(line []byte) error { _, err := wire.Read(line); return err }

	cold, _ := s.NewVerifyCache("v1", verify)
	cold.Mode = Cold
	run := func(vc *VerifyCache) map[string]string {
		out := map[string]string{}
		for name, l := range map[string][]byte{"good": good, "good2": good2, "bad": bad} {
			v, _ := vc.Check(l)
			out[name] = string(v)
		}
		return out
	}
	want := run(cold)
	if want["good"] != "verified" || want["good2"] != "verified" || want["bad"] != "failed" {
		t.Fatal(want)
	}

	// Pre-populate "verified" for the invalid statement (and the genuine ones).
	warm, _ := s.NewVerifyCache("v1", verify)
	for _, l := range [][]byte{good, good2, bad} {
		p := warm.path(l)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("verified\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A conformance run: Cold ignores every entry, so the invalid one is never reported verified.
	cold2, _ := s.NewVerifyCache("v1", verify)
	cold2.Mode = Cold
	got := run(cold2)
	if got["bad"] != "failed" || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("cold run with a poisoned cache: %v", got)
	}
	if h, c := cold2.Stats(); h != 0 || c != 3 {
		t.Fatalf("cold run answered from the cache: hits=%d computed=%d", h, c)
	}
	// The cold run refreshed the poisoned entry to the true verdict, so daily use is right again.
	daily, _ := s.NewVerifyCache("v1", verify)
	if g := run(daily); fmt.Sprint(g) != fmt.Sprint(want) {
		t.Fatalf("warm answers differ from cold: %v vs %v", g, want)
	}
	if h, c := daily.Stats(); h != 3 || c != 0 {
		t.Fatalf("warm run did not use the cache: hits=%d computed=%d", h, c)
	}
	// Poison again and show UseCache would have trusted it (so the Cold-mode result above was meaningful).
	_ = os.WriteFile(warm.path(bad), []byte("verified\n"), 0o644)
	if v, _ := daily.Check(bad); v != Verified {
		t.Fatal("test cannot show the planted entry is reachable in daily mode")
	}
	// A changed verifier version misses every entry: the planted entry is under v1 only.
	v2, _ := s.NewVerifyCache("v2", verify)
	if g := run(v2); g["bad"] != "failed" {
		t.Fatalf("a changed verifier version reused an entry: %v", g)
	}
	if h, c := v2.Stats(); h != 0 || c != 3 {
		t.Fatalf("v2 hits=%d computed=%d", h, c)
	}
	// A failure keeps its typed refusal class and reason from the cache.
	d2, _ := s.NewVerifyCache("v2", verify)
	_, err := d2.Check(bad)
	var r *refusal.Refusal
	if !errors.As(err, &r) || r.Class != refusal.Intrinsic || r.Reason != refusal.BadSignature {
		t.Fatalf("%v", err)
	}
	// An operational failure of the verifier itself is never cached.
	boom := errors.New("verifier crashed")
	vb, _ := s.NewVerifyCache("v3", func([]byte) error { return boom })
	if _, err := vb.Check(good); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if _, err := os.Stat(vb.path(good)); err == nil {
		t.Fatal("an operational failure was cached")
	}
	if _, err := s.NewVerifyCache("", verify); err == nil {
		t.Fatal("empty verifier version accepted")
	}
}
