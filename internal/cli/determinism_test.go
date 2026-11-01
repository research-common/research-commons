package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// The resolved view of a store, as one value two readers can compare: the view digest CONFORMANCE.md defines
// under "How a result is recorded". No command prints one yet, so the tests compute the narrowest one the
// determinism cases need: for a fixed universe of refs (every blob digest and
// statement id the statement set names, plus one nobody holds), the exit code and the canonical --json output of
// verify and explain for each ref, and of list; the digest is sha256 over those lines in order. explain prints
// the whole show view (showArtifact, showStatement) and verify's causes, so show adds nothing; verify is kept
// for its exit. Every surface is rendered from one result tree (node.go), so the JSON surface carries every
// token the human surface prints. Two stores with equal view digests answer every read command identically
// over the universe.

// surfaces is every read surface over refs: "<command> <ref>" -> "<exit> <stdout>".
func surfaces(t testing.TB, root string, refs []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	add := func(args ...string) {
		r := runIn(root, nil, append(args, "--json")...)
		if r.code == ExitDidNotStart {
			t.Fatalf("%v did not start: %s", args, r.stdout)
		}
		out[strings.Join(args, " ")] = strconv.Itoa(r.code) + " " + r.stdout
	}
	add("list")
	for _, ref := range refs {
		for _, c := range []string{"verify", "explain"} {
			add(c, ref)
		}
	}
	return out
}

func viewDigest(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k + "\x00" + m[k] + "\x00"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// seeds is n seeds from base; RC_DETERMINISM_SEEDS=<n> widens the sweep (each seed is a few seconds of CLI runs).
func seeds(base uint64, n int) []uint64 {
	if v, err := strconv.Atoi(os.Getenv("RC_DETERMINISM_SEEDS")); err == nil && v > 0 {
		n = v
	}
	out := make([]uint64, n)
	for i := range out {
		out[i] = base + uint64(i)
	}
	return out
}

// dataObjects lists the data surface of a store root: every blob and statement path, relative, sorted.
func dataObjects(t testing.TB, root string) (blobs, stmts []string) {
	t.Helper()
	for _, top := range []string{"blobs", "statements"} {
		filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				t.Fatal(err)
			}
			if !d.IsDir() {
				rel, _ := filepath.Rel(root, p)
				if top == "blobs" {
					blobs = append(blobs, filepath.ToSlash(rel))
				} else {
					stmts = append(stmts, filepath.ToSlash(rel))
				}
			}
			return nil
		})
	}
	return blobs, stmts
}

// writePackage writes a package directory (a store tree) holding exactly the given objects of src.
func writePackage(t testing.TB, src, dst string, objs []string) {
	t.Helper()
	os.WriteFile(filepath.Join(dst, "rc-store"), mustRead(t, filepath.Join(src, "rc-store")), 0o644)
	for _, o := range objs {
		os.MkdirAll(filepath.Join(dst, filepath.Dir(o)), 0o755)
		if err := os.WriteFile(filepath.Join(dst, o), mustRead(t, filepath.Join(src, o)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// chunks permutes objs under r and cuts them into 1..maxChunks non-empty runs.
func chunks(r *rand.Rand, objs []string, maxChunks int) [][]string {
	p := slices.Clone(objs)
	r.Shuffle(len(p), func(i, j int) { p[i], p[j] = p[j], p[i] })
	n := 1 + r.IntN(min(maxChunks, len(p)))
	cuts := r.Perm(len(p) - 1)[:n-1]
	for i := range cuts {
		cuts[i]++
	}
	slices.Sort(cuts)
	var out [][]string
	prev := 0
	for _, c := range append(cuts, len(p)) {
		out = append(out, p[prev:c])
		prev = c
	}
	return out
}

// refUniverse is every blob digest and statement id of the source set, plus an id nobody holds.
func refUniverse(t testing.TB, src string) []string {
	blobs, stmts := dataObjects(t, src)
	var refs []string
	for _, b := range blobs {
		refs = append(refs, "sha256:"+filepath.Base(b))
	}
	for _, s := range stmts {
		refs = append(refs, filepath.Base(s))
	}
	// the fixture names blobs it never installs (contested, t0, …): every digest a statement names is a ref
	lines := map[string]bool{}
	for _, s := range stmts {
		for _, d := range scanDigests(mustRead(t, filepath.Join(src, s))) {
			lines[d] = true
		}
	}
	for d := range lines {
		refs = append(refs, d)
	}
	refs = append(refs, strings.Repeat("ab", 32))
	slices.Sort(refs)
	return slices.Compact(refs)
}

func scanDigests(b []byte) []string {
	var out []string
	s := string(b)
	for i := strings.Index(s, "sha256:"); i >= 0; {
		if len(s) >= i+71 && isDigest(s[i:i+71]) {
			out = append(out, s[i:i+71])
		}
		j := strings.Index(s[i+1:], "sha256:")
		if j < 0 {
			break
		}
		i += 1 + j
	}
	return out
}

// noncanonical re-encodes a statement line with whitespace: the same canonical form, other bytes.
func noncanonical(t testing.TB, line []byte) []byte {
	t.Helper()
	v, err := canon.Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	o := v.(*canon.Object)
	var b strings.Builder
	b.WriteString("{ ")
	for i, k := range o.Keys {
		if i > 0 {
			b.WriteString(" , ")
		}
		b.Write(canon.Encode(canon.String(k)))
		b.WriteString(" : ")
		b.Write(canon.Encode(o.Members[k]))
	}
	b.WriteString(" }\n")
	return []byte(b.String())
}

// TestDeliveryOrderOneView: C-core-04. One fixed statement set (the sweep fixture: sole, contested, nobody,
// T0, diverged, protocol-unchecked, not re-derived, unpinned, retracted, hostile text, anchors and an unknown
// kind) delivered to fresh readers (a) as local package trees and (b) as a hub checkout that grows commit by
// commit, each in a seeded random order cut into several pulls, every statement delivered at least twice, and
// on one order every duplicate also in a non-canonical byte form. Every delivery ends at the same view digest
// as the source store, so every verify exit and every explain output is identical (explain carries no delivery
// metadata at all). The control: a reader missing one statement has a different view digest, so the digest sees
// a difference when there is one.
func TestDeliveryOrderOneView(t *testing.T) {
	conformance.Partial(t, "C-core-04", "deliveries (a) local package trees and (b) a growing hub checkout pulled with --from-checkout, three seeded orders each, every statement duplicated: one view digest, one verify exit per ref, explain identical; (c) an archive has no ingest path: pull reads a directory only")
	src := fixture(t)
	blobs, stmts := dataObjects(t, src.root)
	refs := refUniverse(t, src.root)
	want := surfaces(t, src.root, refs)
	wantDigest := viewDigest(want)
	all := append(slices.Clone(blobs), stmts...)

	check := func(label string, root string) {
		t.Helper()
		got := surfaces(t, root, refs)
		if d := viewDigest(got); d != wantDigest {
			for k := range want {
				if got[k] != want[k] {
					t.Fatalf("%s: view digest %s, want %s; first difference at %q:\n got %s\nwant %s", label, d[:12], wantDigest[:12], k, got[k], want[k])
				}
			}
			t.Fatalf("%s: view digest differs", label)
		}
	}

	// control: a reader missing one statement (the retraction) answers differently
	{
		dst := newWorld(t)
		var less []string
		for _, o := range all {
			if !strings.HasSuffix(o, src.ids["R:retracted"]) {
				less = append(less, o)
			}
		}
		pkg := t.TempDir()
		writePackage(t, src.root, pkg, less)
		if r := dst.run("pull", pkg); r.code != 0 {
			t.Fatalf("control pull: exit %d\n%s", r.code, r.stdout)
		}
		if viewDigest(surfaces(t, dst.root, refs)) == wantDigest {
			t.Fatal("control: a reader without the retraction has the source's view digest; the digest proves nothing")
		}
	}

	for _, seed := range seeds(1, 2) {
		r := rand.New(rand.NewPCG(seed, 0xc0de04))
		t.Logf("seed %d", seed)

		// (a) local package trees: two passes, each a fresh permutation cut into pulls, so every object arrives
		// twice and lines arrive before their predecessors
		t.Run("tree/"+strconv.FormatUint(seed, 10), func(t *testing.T) {
			dst := newWorld(t)
			for pass := 0; pass < 2; pass++ {
				for i, c := range chunks(r, all, 6) {
					pkg := t.TempDir()
					writePackage(t, src.root, pkg, c)
					if seed == 1 && pass == 1 {
						// the duplicates of this order also arrive in a non-canonical byte form (whitespace): the
						// wire note stores one byte form per statement; the gate refuses these bytes (reason
						// `not canonical`), and either way the view is unchanged
						for _, o := range c {
							if strings.HasPrefix(o, "statements/") {
								os.WriteFile(filepath.Join(pkg, o), noncanonical(t, mustRead(t, filepath.Join(src.root, o))), 0o644)
							}
						}
						if x := dst.run("pull", pkg); x.code == ExitDidNotStart || x.code == ExitCouldNot {
							t.Fatalf("pass %d pull %d (non-canonical duplicates): exit %d\n%s", pass, i, x.code, x.stdout)
						}
						continue
					}
					if x := dst.run("pull", pkg); x.code != 0 {
						t.Fatalf("pass %d pull %d: exit %d\n%s", pass, i, x.code, x.stdout)
					}
				}
			}
			check("tree seed "+strconv.FormatUint(seed, 10), dst.root)
		})

		// (b) a hub: a git repository whose commits add the objects in a random order; the reader pulls its
		// checkout (--from-checkout) after every commit, so everything already committed is re-delivered by
		// each later pull, and once more at the end
		t.Run("hub/"+strconv.FormatUint(seed, 10), func(t *testing.T) {
			if _, err := exec.LookPath("git"); err != nil {
				t.Skip("git not installed")
			}
			hub := t.TempDir()
			os.WriteFile(filepath.Join(hub, "rc-store"), mustRead(t, filepath.Join(src.root, "rc-store")), 0o644)
			gitIn(t, hub, "init", "-q", "-b", "main")
			dst := newWorld(t)
			cs := chunks(r, all, 6)
			for i, c := range cs {
				writePackage(t, src.root, hub, c)
				gitIn(t, hub, "add", "-A")
				gitIn(t, hub, "commit", "-q", "-m", "c"+strconv.Itoa(i))
				clone := filepath.Join(t.TempDir(), "clone")
				gitIn(t, hub, "clone", "-q", hub, clone)
				if x := dst.run("pull", clone, "--from-checkout"); x.code != 0 {
					t.Fatalf("hub pull %d: exit %d\n%s", i, x.code, x.stdout)
				}
				if i == len(cs)-1 {
					if x := dst.run("pull", clone, "--from-checkout"); x.code != 0 {
						t.Fatalf("hub re-pull: exit %d\n%s", x.code, x.stdout)
					}
				}
			}
			check("hub seed "+strconv.FormatUint(seed, 10), dst.root)
		})
	}
}

// TestRelayersConverge: C-core-02. Two readers behind different relayers: relayer X withholds one seeded subset
// of the statement set, relayer Y another (every blob is served by both). Before convergence each reader's view
// is exactly the view of a fresh reader handed the same statements directly (the answer is a function of the
// held set, not of how it arrived), and every surface on which the two readers differ is explained by a
// statement one of them lacked: that statement is among the inputs `explain` lists for the ref on the converged
// view, or is the ref itself. After both relayers serve everything, the two readers hold the identical
// statement set, report the same policy digest and evaluator, and have identical view digests.
func TestRelayersConverge(t *testing.T) {
	conformance.Covers(t, "C-core-02")
	src := fixture(t)
	blobs, stmts := dataObjects(t, src.root)
	refs := refUniverse(t, src.root)
	full := surfaces(t, src.root, refs)

	for _, seed := range seeds(11, 2) {
		t.Run(strconv.FormatUint(seed, 10), func(t *testing.T) {
			r := rand.New(rand.NewPCG(seed, 0xc0de02))
			// each relayer withholds about a third of the statements, independently
			serve := func() (served, withheld []string) {
				for _, s := range stmts {
					if r.IntN(3) == 0 {
						withheld = append(withheld, s)
					} else {
						served = append(served, s)
					}
				}
				return
			}
			sx, wx := serve()
			sy, wy := serve()
			t.Logf("seed %d: X withholds %d, Y withholds %d of %d statements", seed, len(wx), len(wy), len(stmts))
			rx, ry := newWorld(t), newWorld(t)
			pull := func(dst *world, objs []string, extra ...string) {
				t.Helper()
				pkg := t.TempDir()
				writePackage(t, src.root, pkg, objs)
				if x := dst.run(append([]string{"pull", pkg}, extra...)...); x.code != 0 {
					t.Fatalf("pull: exit %d\n%s", x.code, x.stdout)
				}
			}
			pull(rx, append(slices.Clone(blobs), sx...))
			pull(ry, append(slices.Clone(blobs), sy...))

			// before: each view is the view of the held set alone
			vx, vy := surfaces(t, rx.root, refs), surfaces(t, ry.root, refs)
			for name, c := range map[string]struct {
				held []string
				v    map[string]string
			}{"X": {sx, vx}, "Y": {sy, vy}} {
				direct := newWorld(t)
				for _, s := range c.held {
					if _, err := direct.s.Commit("publish", [][]byte{mustRead(t, filepath.Join(src.root, s))}, nil); err != nil {
						t.Fatal(err)
					}
				}
				for _, b := range blobs {
					direct.blob(b, mustRead(t, filepath.Join(src.root, b)))
				}
				if viewDigest(surfaces(t, direct.root, refs)) != viewDigest(c.v) {
					t.Fatalf("reader behind %s: its view is not the view of its held statements alone", name)
				}
			}

			// every differing surface is explained by a statement one reader lacked
			lackedByOne := map[string]bool{}
			inX, inY := map[string]bool{}, map[string]bool{}
			for _, s := range sx {
				inX[filepath.Base(s)] = true
			}
			for _, s := range sy {
				inY[filepath.Base(s)] = true
			}
			for _, s := range stmts {
				id := filepath.Base(s)
				if inX[id] != inY[id] {
					lackedByOne[id] = true
				}
			}
			differ := 0
			for k := range vx {
				if vx[k] == vy[k] {
					continue
				}
				differ++
				if len(lackedByOne) == 0 {
					t.Fatalf("%q differs although both readers hold the same statements", k)
				}
				if k == "list" {
					continue // list is every blob's line; each line is the show of that blob, checked on its own
				}
				ref := strings.Fields(k)[1]
				if lackedByOne[ref] {
					continue
				}
				// an input explains the difference when a reader lacked it, or lacked a line of its signer's log it
				// reaches through prev and merges (the input then shows `detached` to that reader)
				inputs := explainInputs(t, full["explain "+ref])
				if !slices.ContainsFunc(prefixes(t, src.root, inputs), func(id string) bool { return lackedByOne[id] }) {
					t.Fatalf("%q differs between the readers, and no statement one of them lacked is among its explain inputs %v\nX: %s\nY: %s",
						k, inputs, vx[k], vy[k])
				}
			}
			t.Logf("seed %d: %d surfaces differed before convergence", seed, differ)

			// convergence: each relayer now serves everything (Y's set reaches X and X's reaches Y)
			pull(rx, stmts)
			pull(ry, stmts)
			_, hx := dataObjects(t, rx.root)
			_, hy := dataObjects(t, ry.root)
			if !slices.Equal(hx, hy) || !slices.Equal(hx, stmts) {
				t.Fatal("the readers do not hold the identical statement set")
			}
			ex := jsonOf(t, rx.run("explain", dig("sole"), "--json"))
			ey := jsonOf(t, ry.run("explain", dig("sole"), "--json"))
			for _, k := range []string{"policy", "evaluator"} {
				if string(canon.Encode(ex.Members[k])) != string(canon.Encode(ey.Members[k])) {
					t.Fatalf("%s differs: %s vs %s", k, canon.Encode(ex.Members[k]), canon.Encode(ey.Members[k]))
				}
			}
			dx, dy := viewDigest(surfaces(t, rx.root, refs)), viewDigest(surfaces(t, ry.root, refs))
			if dx != dy || dx != viewDigest(full) {
				t.Fatalf("view digests after convergence: X %s, Y %s, source %s", dx[:12], dy[:12], viewDigest(full)[:12])
			}
		})
	}
}

// prefixes is ids with every line each reaches through prev and merges in the source store.
func prefixes(t testing.TB, root string, ids []string) []string {
	t.Helper()
	lines, err := storeLines(root)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var walk func(id string)
	walk = func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		if st, ok := lines[id]; ok {
			if st.Prev != "" {
				walk(st.Prev)
			}
			for _, m := range st.Merges {
				walk(m)
			}
		}
	}
	for _, id := range ids {
		walk(id)
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

func storeLines(root string) (map[string]*wire.Statement, error) {
	s, err := store.Open(root, store.Options{NoSync: true})
	if err != nil {
		return nil, err
	}
	raw, err := s.Statements()
	if err != nil {
		return nil, err
	}
	out := map[string]*wire.Statement{}
	for id, b := range raw {
		if st, err := wire.Read(b); err == nil {
			out[id] = st
		}
	}
	return out, nil
}

// explainInputs is the statement ids an explain --json output lists as its inputs.
func explainInputs(t testing.TB, s string) []string {
	t.Helper()
	_, out, _ := strings.Cut(s, " ")
	o := jsonOf(t, result{stdout: out})
	var ids []string
	if l, ok := o.Members["statements"].(canon.Array); ok {
		for _, e := range l {
			if id, ok := e.(*canon.Object).Members["statement"].(canon.String); ok {
				ids = append(ids, string(id))
			}
		}
	}
	return ids
}
