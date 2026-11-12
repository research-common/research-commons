package btctime

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/conformance/fixture"
	"github.com/research-common/research-commons/internal/resolve"
)

// --- rig ------------------------------------------------------------------------------------------------------

// gitRoot makes a directory that is a git-backed hub as far as Locate can tell: a .git directory with a HEAD.
func gitRoot(t testing.TB) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func openR(t testing.TB, loc Location, opt ReceiptOptions) *Receipts {
	t.Helper()
	opt.NoSync = true
	r, err := OpenReceipts(loc, opt)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// rig: A anchored at block 10, BB at block 12, a 30-block chain, a git-backed hub with an open receipt store.
type rig struct {
	t   *testing.T
	w   *world
	s   *synth
	loc Location
	r   *Receipts
}

func newRig(t *testing.T) *rig {
	t.Helper()
	w := newWorld(t)
	w.authored("A1", "A", "X", "licence", "CC0-1.0")
	w.anchorAt("AA", "A", 10)
	w.authored("B1", "BB", "X", "licence", "MIT")
	w.anchorAt("BA", "BB", 12)
	s := w.chain(30)
	loc, err := Locate(gitRoot(t), "")
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, w: w, s: s, loc: loc, r: openR(t, loc, ReceiptOptions{})}
}

func (g *rig) v() *Verifier { return g.s.fresh(g.w.blobs) }

// read evaluates name through the receipt store, and cold, on one verifier, and requires identical evidence.
func (g *rig) read(v *Verifier, r *Receipts, name string) (Evidence, ReceiptUse) {
	g.t.Helper()
	cold := v.Evaluate(g.w.sts[name])
	e, use := r.Evaluate(v, g.w.sts[name])
	sameEvidence(g.t, cold, e, use)
	return e, use
}

func sameEvidence(t testing.TB, cold, warm Evidence, use ReceiptUse) {
	t.Helper()
	if !reflect.DeepEqual(cold, warm) {
		t.Fatalf("the receipt changed the answer (use %+v):\ncold %+v\nwarm %+v", use, cold, warm)
	}
}

func wantUse(t testing.TB, use ReceiptUse, used bool, why string) {
	t.Helper()
	if use.Used != used || !strings.Contains(use.Why, why) {
		t.Fatalf("receipt use %+v; want used=%v why containing %q", use, used, why)
	}
}

// viewOf is a fresh verifier over chain c (synced a minute ago, the clock ten minutes past the tip).
func viewOf(c *Chain, pol Policy, blobs BlobSource) *Verifier {
	v := c.Snapshot()
	now := time.Unix(int64(v.TipTime), 0).Add(10 * time.Minute)
	c.MarkSynced(now.Add(-time.Minute))
	return &Verifier{Policy: pol, View: c.Snapshot(), Blobs: blobs, Now: func() time.Time { return now }}
}

// copyChain builds a chain under provider from the active headers of v at heights 1..upTo.
func copyChain(t testing.TB, p Params, provider string, v *ChainView, upTo int64, now time.Time) *Chain {
	t.Helper()
	c, err := NewChain(p, provider)
	if err != nil {
		t.Fatal(err)
	}
	for h := int64(1); h <= upTo; h++ {
		hd, ok := v.HeaderAt(h)
		if !ok {
			t.Fatalf("no header at %d", h)
		}
		if err := c.Add(hd.Raw[:], now); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// fileBlobs is a blob source over files named by digest that, like a naive store, does not re-hash on open: the
// verifier must catch changed bytes itself.
type fileBlobs string

func (d fileBlobs) path(digest string) string {
	return filepath.Join(string(d), strings.TrimPrefix(digest, "sha256:"))
}

func (d fileBlobs) OpenBlob(digest string) (io.ReadCloser, bool) {
	f, err := os.Open(d.path(digest))
	if err != nil {
		return nil, false
	}
	return f, true
}

// --- §9.1 location ----------------------------------------------------------------------------------------------

// TestReceiptLocation: note §9.1. A git-backed hub keeps its state under the git directory Git resolves (a linked
// worktree finds the shared one, read from the .git file and commondir without running git, and the answer
// matches `git rev-parse --git-common-dir` where git is installed); any other root needs an explicitly configured
// directory, which may not lie inside the hub root (the data surface); with neither there is no state. GIT_DIR in
// the environment redirects nothing.
func TestReceiptLocation(t *testing.T) {
	// a plain repository
	main := gitRoot(t)
	loc, err := Locate(main, "")
	real, _ := filepath.EvalSymlinks(filepath.Join(main, ".git"))
	if err != nil || loc.Dir != filepath.Join(real, "research-commons") || loc.Hub != "git:"+real || loc.Via != "git" {
		t.Fatalf("plain repository: %+v %v", loc, err)
	}
	// a linked worktree, laid out by hand as git lays it out
	wt := t.TempDir()
	wtGit := filepath.Join(main, ".git", "worktrees", "wt")
	if err := os.MkdirAll(wtGit, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(wtGit, "HEAD"), []byte("ref: refs/heads/wt\n"), 0o644)
	os.WriteFile(filepath.Join(wtGit, "commondir"), []byte("../..\n"), 0o644)
	os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: "+wtGit+"\n"), 0o644)
	t.Setenv("GIT_DIR", t.TempDir()) // ignored
	if l2, err := Locate(wt, ""); err != nil || l2 != loc {
		t.Fatalf("linked worktree resolves to %+v (%v), not the shared %+v", l2, err, loc)
	}
	// no .git, nothing configured: no state at all (C-btc-06 then holds: every bound local)
	plain := t.TempDir()
	if _, err := Locate(plain, ""); !errors.Is(err, ErrNoState) {
		t.Fatalf("plain root: %v", err)
	}
	if _, err := OpenReceipts(Location{}, ReceiptOptions{}); !errors.Is(err, ErrNoState) {
		t.Fatalf("empty location: %v", err)
	}
	// configured: outside the hub root is used; inside it (the data surface) is refused
	cfg := t.TempDir()
	if l, err := Locate(plain, cfg); err != nil || l.Via != "configured" || !strings.HasPrefix(l.Hub, "dir:") {
		t.Fatalf("configured: %+v %v", l, err)
	}
	os.Mkdir(filepath.Join(plain, "state"), 0o700)
	if _, err := Locate(plain, filepath.Join(plain, "state")); err == nil || !strings.Contains(err.Error(), "data surface") {
		t.Fatalf("configured inside the hub root: %v", err)
	}
	if _, err := Locate(plain, plain); err == nil {
		t.Fatal("the hub root itself accepted as the state directory")
	}
	// malformed .git file
	bad := t.TempDir()
	os.WriteFile(filepath.Join(bad, ".git"), []byte("not a gitdir line\n"), 0o644)
	if _, err := Locate(bad, ""); err == nil {
		t.Fatal("a malformed .git file located state")
	}

	// against git itself, where installed
	if _, err := exec.LookPath("git"); err != nil {
		t.Log("git not installed; the hand-built worktree above stands in")
		return
	}
	t.Setenv("GIT_DIR", "")
	os.Unsetenv("GIT_DIR")
	base := t.TempDir()
	run := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.org")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	repo := filepath.Join(base, "hub")
	os.MkdirAll(repo, 0o755)
	run(repo, "init", "-q")
	run(repo, "commit", "-q", "--allow-empty", "-m", "init")
	run(repo, "worktree", "add", "-q", filepath.Join(base, "linked"))
	common := run(filepath.Join(base, "linked"), "rev-parse", "--path-format=absolute", "--git-common-dir")
	common, _ = filepath.EvalSymlinks(common)
	l1, err1 := Locate(repo, "")
	l2, err2 := Locate(filepath.Join(base, "linked"), "")
	if err1 != nil || err2 != nil || l1 != l2 || l2.Dir != filepath.Join(common, "research-commons") {
		t.Fatalf("git worktree: %+v %v / %+v %v; git says %s", l1, err1, l2, err2, common)
	}
}

// TestReceiptPermissions: note §9.1. Directories 0700, receipts and the key 0600; a receipt whose mode was
// loosened is not trusted.
func TestReceiptPermissions(t *testing.T) {
	g := newRig(t)
	v := g.v()
	if _, use := g.read(v, g.r, "AA"); !use.Written {
		t.Fatalf("no receipt written: %+v", use)
	}
	id := g.w.ids["AA"]
	for p, want := range map[string]os.FileMode{
		g.loc.Dir: 0o700, g.r.path(): 0o700, g.r.path(receiptSubdir): 0o700, g.r.path("tmp"): 0o700,
		g.r.path(keyFileName): 0o600, g.r.path(receiptSubdir, id): 0o600,
	} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != want {
			t.Fatalf("%s: %v %v, want %04o", p, fi.Mode().Perm(), err, want)
		}
	}
	_, use := g.read(v, g.r, "AA")
	wantUse(t, use, true, "")
	os.Chmod(g.r.path(receiptSubdir, id), 0o644)
	_, use = g.read(v, g.r, "AA")
	wantUse(t, use, false, "not owner-only")
	if !use.Downgraded || !use.Written {
		t.Fatalf("%+v", use)
	}
	if fi, _ := os.Stat(g.r.path(receiptSubdir, id)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("rewritten receipt mode %04o", fi.Mode().Perm())
	}
}

// --- C-btc-06 stays green with a store --------------------------------------------------------------------------

// TestReceiptsWithoutBackend: C-btc-06 with the store present. A receipt written while a backend was configured
// grants nothing once there is none: the bound is backend-unconfigured and local, exactly as with no store.
func TestReceiptsWithoutBackend(t *testing.T) {
	conformance.Partial(t, "C-btc-06", "with a receipt store holding a verified receipt, no backend still means backend-unconfigured, local, exit 3 (the case itself is covered by TestNoBackend)")
	g := newRig(t)
	if _, use := g.read(g.v(), g.r, "AA"); !use.Written {
		t.Fatalf("control: %+v", use)
	}
	if _, use := g.read(g.v(), g.r, "AA"); !use.Used {
		t.Fatalf("control: the receipt is used while the backend is there: %+v", use)
	}
	now := time.Now()
	v := &Verifier{Policy: g.s.policy(), Blobs: g.w.blobs, Now: func() time.Time { return now }}
	e, use := g.read(v, g.r, "AA")
	if use.Used || e.State != StateUnconfigured || e.Quality != QualityLocal || Exit([]Evidence{e}) != 3 {
		t.Fatalf("%s / %+v", e, use)
	}
	v.Unavailable = "header database unreadable"
	if e, use := g.read(v, g.r, "AA"); use.Used || e.State != StateUnavailable {
		t.Fatalf("%s / %+v", e, use)
	}
}

// --- C-btc-21: content binding ------------------------------------------------------------------------------------

// TestReceiptContentBinding: C-btc-21. (a) The proof file is rewritten with other bytes of the same size and its
// modification time put back: the read hashes the bytes it holds, the receipt is not used, and the bound is
// missing-proof, as cold. Putting the bytes back makes the same receipt usable again: what decided was content,
// not metadata. (b) An anchors statement with other bytes under the same id, and (c) the same line naming
// another proof: each is evaluated on its own bytes, never answered from the receipt.
func TestReceiptContentBinding(t *testing.T) {
	conformance.Covers(t, "C-btc-21")
	g := newRig(t)
	fb := fileBlobs(t.TempDir())
	for d, b := range g.w.blobs {
		if err := os.WriteFile(fb.path(d), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	v := g.s.fresh(fb)
	if _, use := g.read(v, g.r, "AA"); !use.Written {
		t.Fatalf("control: %+v", use)
	}
	e, use := g.read(v, g.r, "AA")
	wantUse(t, use, true, "")
	if !e.Live() || e.BlockHeight != 10 {
		t.Fatalf("control: %s", e)
	}

	// (a) same size, same mtime, other bytes (B's proof: same structure, another stamped digest and height)
	pa, pb := e.Proof, g.w.sts["BA"].Body.Members["proof"].(canon.String)
	path := fb.path(pa)
	fi, _ := os.Stat(path)
	orig, _ := os.ReadFile(path)
	other := g.w.blobs[string(pb)]
	if len(other) != len(orig) || bytes.Equal(other, orig) {
		t.Fatalf("fixture: the substitute proof must be the same size and different (%d vs %d)", len(other), len(orig))
	}
	os.WriteFile(path, other, 0o644)
	os.Chtimes(path, fi.ModTime(), fi.ModTime())
	if fi2, _ := os.Stat(path); fi2.Size() != fi.Size() || !fi2.ModTime().Equal(fi.ModTime()) {
		t.Fatal("fixture: size or mtime differ")
	}
	e, use = g.read(v, g.r, "AA")
	if use.Used || e.State != StateMissingProof || e.Live() || !strings.Contains(e.Why, "do not hash") {
		t.Fatalf("changed proof bytes: %s / %+v", e, use)
	}
	os.WriteFile(path, orig, 0o644)
	if e, use = g.read(v, g.r, "AA"); !use.Used || !e.Live() {
		t.Fatalf("restored bytes: %s / %+v", e, use)
	}

	// (b) other anchors bytes under the same id: a second anchors by A, at block 14, presented under AA's id
	g.w.anchorAt("AA2", "A", 14)
	forged := *g.w.sts["AA2"]
	forged.ID = g.w.ids["AA"]
	v = g.s.fresh(fb)
	for d, b := range g.w.blobs {
		os.WriteFile(fb.path(d), b, 0o644)
	}
	e, use = g.r.Evaluate(v, &forged)
	sameEvidence(t, v.Evaluate(&forged), e, use)
	wantUse(t, use, false, "id does not match")
	if e.Live() && e.BlockHeight == 10 {
		t.Fatalf("the receipt for AA answered other bytes: %s", e)
	}

	// (c) the same line, a body naming B's proof: the proof hashed is not the proof recorded
	sw := *g.w.sts["AA"]
	body := &canon.Object{Keys: sw.Body.Keys, Members: map[string]canon.Value{}}
	for k, x := range sw.Body.Members {
		body.Members[k] = x
	}
	body.Members["proof"] = pb
	sw.Body = body
	e, use = g.r.Evaluate(v, &sw)
	sameEvidence(t, v.Evaluate(&sw), e, use)
	wantUse(t, use, false, "changed since the receipt")
	if e.Live() {
		t.Fatalf("B's proof bound A's covered: %s", e)
	}
	// (d) the same signed string (so the same id) with other signature bytes: the receipt bound the whole line
	alt := *g.w.sts["AA"]
	alt.Sig = alt.Sig[:len(alt.Sig)-2] + map[bool]string{true: "AA", false: "AB"}[strings.HasSuffix(alt.Sig, "AA")]
	if !idMatches(&alt) || lineDigest(&alt) == lineDigest(g.w.sts["AA"]) {
		t.Fatal("fixture: the altered line must keep its id and change its bytes")
	}
	e, use = g.r.Evaluate(v, &alt)
	sameEvidence(t, v.Evaluate(&alt), e, use)
	wantUse(t, use, false, "anchors statement bytes changed")
	// control: the genuine statement is re-checked once (its receipt was replaced by the altered line's) and then
	// answered from its receipt
	g.read(v, g.r, "AA")
	if _, use := g.read(v, g.r, "AA"); !use.Used {
		t.Fatalf("control after: %+v", use)
	}
}

// TestReceiptHeaderCheck: §9.3 check 4 on its own. With no reorganisation (the recorded tip is active) the recorded
// header is necessarily active too, so the check only fires for a receipt this store authenticated that does not
// match the chain (a writer bug, an older verifier). Each such receipt, written through the store and so passing
// every other check, is not used; the read is cold.
func TestReceiptHeaderCheck(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(rc *receipt, v *Verifier)
	}{
		{"height", func(rc *receipt, v *Verifier) { rc.Height = 11 }},
		{"block hash", func(rc *receipt, v *Verifier) { h, _ := v.View.HeaderAt(11); rc.BlockHash = h.Hash.String() }},
		{"header digest", func(rc *receipt, v *Verifier) { rc.HeaderDigest = "sha256:" + strings.Repeat("0", 64) }},
		{"calculated digest", func(rc *receipt, v *Verifier) { rc.Digest = strings.Repeat("ab", 32) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := newRig(t)
			v := g.v()
			g.read(v, g.r, "AA")
			if _, use := g.read(v, g.r, "AA"); !use.Used {
				t.Fatalf("control: %+v", use)
			}
			rc, _, _ := g.r.read(g.w.ids["AA"])
			c.edit(rc, v)
			if err := g.r.put(rc); err != nil {
				t.Fatal(err)
			}
			_, use := g.read(v, g.r, "AA")
			wantUse(t, use, false, "recorded block is not active")
		})
	}
}

// --- C-btc-22: identity changes -----------------------------------------------------------------------------------

// TestReceiptIdentityChange: C-btc-22. After a change of policy, provider, network, verifier or hub identity a
// stored receipt is not used: the read is a full cold evaluation under the new identity (whose answer it
// returns), and the receipt is replaced only by that re-check, after which it is used again.
func TestReceiptIdentityChange(t *testing.T) {
	conformance.Covers(t, "C-btc-22")
	cases := []struct {
		name string
		// change returns the verifier and store to read with after the change
		change    func(g *rig) (*Verifier, *Receipts)
		why       string
		recovered bool // a re-check under the new identity writes a receipt that is then used
	}{
		{"policy: minimum confirmations", func(g *rig) (*Verifier, *Receipts) {
			v := g.v()
			v.Policy.MinConfirmations = 25 // 21 confirmations: insufficient under the new policy
			return v, g.r
		}, "policy changed", true},
		{"policy: priority margin", func(g *rig) (*Verifier, *Receipts) {
			v := g.v()
			v.Policy.PriorityMargin = 3
			return v, g.r
		}, "policy changed", true},
		{"provider", func(g *rig) (*Verifier, *Receipts) {
			old := g.s.c.Snapshot()
			c := copyChain(g.t, g.s.p, "other-headers", old, old.TipHeight, g.s.now)
			return viewOf(c, g.s.policy(), g.w.blobs), g.r
		}, "provider changed", true},
		{"network", func(g *rig) (*Verifier, *Receipts) {
			s2 := newSynth(g.t, testParams("othernet", 0x207fffff))
			s2.roots = g.w.roots
			s2.extend(s2.genesis(), 30, 0, "")
			v := s2.fresh(g.w.blobs)
			v.Policy = g.s.policy() // the reader's policy did not change; the chain it is pointed at did
			return v, g.r
		}, "network changed", false},
		{"verifier", func(g *rig) (*Verifier, *Receipts) {
			rc, _, _ := g.r.read(g.w.ids["AA"])
			rc.Verifier = "research-commons btctime/0"
			if err := g.r.put(rc); err != nil {
				g.t.Fatal(err)
			}
			return g.v(), g.r
		}, "verifier changed", true},
		{"hub", func(g *rig) (*Verifier, *Receipts) {
			// the same state directory read as another hub's (a configured directory pointed at a second hub)
			loc := Location{Dir: g.loc.Dir, Hub: "dir:/another/hub", Via: "configured"}
			return g.v(), openR(g.t, loc, ReceiptOptions{})
		}, "foreign hub", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newRig(t)
			g.read(g.v(), g.r, "AA")
			if _, use := g.read(g.v(), g.r, "AA"); !use.Used {
				t.Fatalf("control: the receipt is used before the change: %+v", use)
			}
			v, r := c.change(g)
			e, use := g.read(v, r, "AA")
			wantUse(t, use, false, c.why)
			_, use = g.read(v, r, "AA")
			if use.Used != c.recovered {
				t.Fatalf("after the re-check (%s): %+v", e, use)
			}
		})
	}
}

// --- C-btc-23: crashes, corruption, foreign caches ----------------------------------------------------------------

// TestReceiptCrashAtEveryPoint: C-btc-23 (crash mid-write), in the style of the store's crash tests. A receipt
// write is cut at every point, both for a first receipt and for one replacing an earlier receipt. The crashed read
// still returns the cold answer; after a restart the store holds either the previous state (no receipt, or the
// earlier one, which the changed policy makes ineligible) or the complete new receipt, never a partial file under
// its name; leftover temporaries are never read; the crashed writer's lock is broken once stale.
func TestReceiptCrashAtEveryPoint(t *testing.T) {
	conformance.Covers(t, "C-btc-23")
	points := []string{CrashPartialTemp, CrashTempWritten, CrashTempSynced, CrashRenamed, CrashDirSynced}
	for _, replace := range []bool{false, true} {
		for _, point := range points {
			t.Run(fmt.Sprintf("%s/replace=%v", point, replace), func(t *testing.T) {
				g := newRig(t)
				v := g.v()
				if replace {
					if _, use := g.read(v, g.r, "AA"); !use.Written {
						t.Fatalf("setup: %+v", use)
					}
					v = g.v()
					v.Policy.PriorityMargin = 2 // the earlier receipt is now ineligible: the read rewrites it
				}
				hits := 0
				crashing := openR(t, g.loc, ReceiptOptions{crash: func(p string) error {
					if p == point {
						hits++
						return ErrReceiptCrash
					}
					return nil
				}})
				e, use := g.read(v, crashing, "AA")
				if hits != 1 || use.Written || !e.Live() {
					t.Fatalf("crash at %s: hits %d, %s / %+v", point, hits, e, use)
				}
				complete := point == CrashRenamed || point == CrashDirSynced
				// restart: a fresh lock is respected (the write is skipped, the answer unchanged) ...
				r := openR(t, g.loc, ReceiptOptions{})
				_, use = g.read(v, r, "AA")
				if use.Used != complete {
					t.Fatalf("after a crash at %s: complete=%v but %+v", point, complete, use)
				}
				if !complete {
					if replace {
						wantUse(t, use, false, "policy changed")
					} else {
						wantUse(t, use, false, "no receipt")
					}
					if use.Written {
						t.Fatalf("wrote through a live lock: %+v", use)
					}
				}
				// ... and a stale one is broken
				r = openR(t, g.loc, ReceiptOptions{LockStale: time.Nanosecond})
				time.Sleep(time.Millisecond)
				_, use = g.read(v, r, "AA")
				if !complete && !use.Written {
					t.Fatalf("stale lock not broken: %+v", use)
				}
				if _, use = g.read(v, r, "AA"); !use.Used {
					t.Fatalf("no usable receipt after recovery: %+v", use)
				}
				// leftovers in tmp/ are not receipts, and an old one is swept on open
				ents, _ := os.ReadDir(r.path("tmp"))
				for _, en := range ents {
					old := time.Now().Add(-2 * time.Hour)
					os.Chtimes(r.path("tmp", en.Name()), old, old)
				}
				openR(t, g.loc, ReceiptOptions{})
				if ents, _ := os.ReadDir(r.path("tmp")); len(ents) != 0 {
					t.Fatalf("old temporaries not swept: %v", ents)
				}
			})
		}
	}
}

// TestReceiptCorruptOrForeign: C-btc-23 (corrupt cache, foreign-hub cache; also copied and unknown-version
// caches, note §9.3). Each mutation of a stored receipt that was being used (the control) makes the next read
// ignore it (downgraded), return the cold answer, and replace it.
func TestReceiptCorruptOrForeign(t *testing.T) {
	conformance.Covers(t, "C-btc-23")
	type mut struct {
		name string
		f    func(g *rig, path string) *Receipts // returns the store to read with (nil: the rig's)
		why  string
	}
	rewrite := func(g *rig, path string, edit func(o *canon.Object)) {
		b, _ := os.ReadFile(path)
		v, err := canon.Parse(bytes.TrimSpace(b))
		if err != nil {
			g.t.Fatal(err)
		}
		o := v.(*canon.Object)
		edit(o)
		os.WriteFile(path, canon.Encode(o), 0o600)
	}
	muts := []mut{
		{"truncated", func(g *rig, p string) *Receipts {
			b, _ := os.ReadFile(p)
			os.WriteFile(p, b[:len(b)/2], 0o600)
			return nil
		}, "corrupt"},
		{"empty", func(g *rig, p string) *Receipts { os.WriteFile(p, nil, 0o600); return nil }, "corrupt"},
		{"garbage", func(g *rig, p string) *Receipts { os.WriteFile(p, []byte("\x00\xffnot json"), 0o600); return nil }, "corrupt"},
		{"symlink to a valid receipt", func(g *rig, p string) *Receipts {
			q := filepath.Join(g.t.TempDir(), "elsewhere")
			b, _ := os.ReadFile(p)
			os.WriteFile(q, b, 0o600)
			os.Remove(p)
			os.Symlink(q, p)
			return nil
		}, "never followed"},
		{"one byte changed", func(g *rig, p string) *Receipts {
			rewrite(g, p, func(o *canon.Object) { o.Members["height"] = canon.String("11") })
			return nil
		}, "copied or forged"},
		{"unexpected member", func(g *rig, p string) *Receipts {
			rewrite(g, p, func(o *canon.Object) {
				o.Keys = append(o.Keys, "quality")
				o.Members["quality"] = canon.String("bitcoin")
			})
			return nil
		}, "unexpected members"},
		{"unknown version", func(g *rig, p string) *Receipts {
			rc, _, _ := g.r.read(g.w.ids["AA"])
			rc.Version = 2
			os.WriteFile(p, g.r.encode(rc), 0o600) // authenticated, but a version this store does not read
			return nil
		}, "unknown version"},
		{"another anchor's receipt", func(g *rig, p string) *Receipts {
			g.read(g.v(), g.r, "BA")
			b, _ := os.ReadFile(g.r.path(receiptSubdir, g.w.ids["BA"]))
			os.WriteFile(p, b, 0o600)
			return nil
		}, "names another"},
		{"copied from another reader", func(g *rig, p string) *Receipts {
			// another reader of the same hub path, with its own store (its own key), verified the same anchor
			other := Location{Dir: filepath.Join(g.t.TempDir(), "state"), Hub: g.loc.Hub}
			ro := openR(g.t, other, ReceiptOptions{})
			g.read(g.v(), ro, "AA")
			b, _ := os.ReadFile(ro.path(receiptSubdir, g.w.ids["AA"]))
			os.WriteFile(p, b, 0o600)
			return nil
		}, "copied or forged"},
		{"key replaced", func(g *rig, p string) *Receipts {
			os.WriteFile(g.r.path(keyFileName), []byte("not a key\n"), 0o600)
			return openR(g.t, g.loc, ReceiptOptions{})
		}, "copied or forged"},
		{"foreign hub (the whole state copied under another hub)", func(g *rig, p string) *Receipts {
			root2 := gitRoot(g.t)
			loc2, _ := Locate(root2, "")
			copyTree(g.t, g.loc.Dir, loc2.Dir)
			return openR(g.t, loc2, ReceiptOptions{})
		}, "foreign hub"},
	}
	for _, m := range muts {
		t.Run(m.name, func(t *testing.T) {
			g := newRig(t)
			v := g.v()
			g.read(v, g.r, "AA")
			if _, use := g.read(v, g.r, "AA"); !use.Used {
				t.Fatalf("control: %+v", use)
			}
			r := m.f(g, g.r.path(receiptSubdir, g.w.ids["AA"]))
			if r == nil {
				r = g.r
			}
			e, use := g.read(v, r, "AA")
			wantUse(t, use, false, m.why)
			if !use.Downgraded || !use.Written || !e.Live() {
				t.Fatalf("%s / %+v", e, use)
			}
			if _, use := g.read(v, r, "AA"); !use.Used {
				t.Fatalf("not replaced: %+v", use)
			}
		})
	}
}

// --- C-btc-20: receipt-shaped files are inert -----------------------------------------------------------------------

// TestReceiptShapedFileIsInert: C-btc-20 (file half). The anchor's proof stamps the right statement but its
// calculated digest is not the Merkle root of block 10, so a cold read says invalid-proof. A receipt-shaped file
// claiming the binding at block 10, consistent with the chain in every field the eligibility checks read, is
// planted (1) in the hub's data surface, where the store never reads, and (2) in the store itself, without the
// store's key (received from elsewhere, or written by anything but this store). Neither grants anything: the read
// is cold and invalid-proof. Control: the same record authenticated by this store is what the store would trust,
// so the key, not the field checks, is what kept the planted file inert.
func TestReceiptShapedFileIsInert(t *testing.T) {
	conformance.Covers(t, "C-btc-20")
	w := newWorld(t)
	w.authored("A1", "A", "X")
	cov := unhex(t, w.head["A"])
	w.roots[10] = sha([]byte("some other root"))
	proof := otsFile(cov, opAppendB(nonce("AA")), opSHA256B(), attBitcoin(10))
	w.anchorProof("AA", "A", proof, ProofFormat)
	s := w.chain(30)
	root := gitRoot(t)
	loc, _ := Locate(root, "")
	r := openR(t, loc, ReceiptOptions{})
	v := s.fresh(w.blobs)
	cold := v.Evaluate(w.sts["AA"])
	if cold.State != StateInvalidProof {
		t.Fatalf("fixture: %s", cold)
	}
	h10, _ := v.View.HeaderAt(10)
	rc := &receipt{Version: ReceiptVersion, Hub: loc.Hub, Anchor: w.ids["AA"], Signer: w.signer("A"), AnchorLine: lineDigest(w.sts["AA"]),
		Covered: w.ids["A1"], Proof: cold.Proof, Stamped: hex.EncodeToString(cov), Network: v.View.Network, Genesis: v.View.GenesisHash,
		Height: 10, BlockHash: h10.Hash.String(), HeaderDigest: headerDigest(h10), Digest: hex.EncodeToString(h10.MerkleRoot[:]),
		Provider: v.View.Provider, Bootstrap: v.View.Bootstrap, Mode: v.View.Mode, Verifier: VerifierVersion, Policy: v.Policy.Fingerprint(),
		TipHeight: v.View.TipHeight, TipHash: v.View.TipHash.String(), Epoch: 1, Notes: []string{}}
	if rc.Covered != w.ids["A1"] || cold.Covered != rc.Covered {
		t.Fatalf("fixture: covered %s vs %s", rc.Covered, cold.Covered)
	}
	foreign := &Receipts{loc: loc, key: bytes.Repeat([]byte{7}, 32)}
	planted := foreign.encode(rc)

	// (1) in the data surface: blobs/ and statements/ of the hub root
	for _, d := range []string{"blobs/sha256", "statements"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
		os.WriteFile(filepath.Join(root, d, w.ids["AA"]), r.encode(rc), 0o644)
	}
	e, use := r.Evaluate(v, w.sts["AA"])
	sameEvidence(t, cold, e, use)
	wantUse(t, use, false, "no receipt")
	// (2) in the store, without the store's key
	os.WriteFile(r.path(receiptSubdir, w.ids["AA"]), planted, 0o600)
	e, use = r.Evaluate(v, w.sts["AA"])
	sameEvidence(t, cold, e, use)
	wantUse(t, use, false, "copied or forged")
	if e.Live() || use.Written {
		t.Fatalf("%s / %+v", e, use)
	}
	// control: the identical record under this store's key passes every field check
	os.WriteFile(r.path(receiptSubdir, w.ids["AA"]), r.encode(rc), 0o600)
	if e, use := r.Evaluate(v, w.sts["AA"]); !use.Used || !e.Live() {
		t.Fatalf("control: the planted record is not consistent enough to have been trusted: %s / %+v", e, use)
	}
}

// --- C-btc-24: tip extension, reorgs, rollback ----------------------------------------------------------------------

// TestReceiptReorg: C-btc-24 with the receipt store. A tip extension is answered from the receipt (checks 3–5
// only, confirmations re-counted); a reorganisation orphaning the attested block makes the cached binding
// ineligible at once (orphaned, no priority); a reorganisation above the block re-selects cold and re-verifies;
// a reorganisation back makes the original receipt usable again only because its whole branch is active again;
// a deep rollback of the header store (a shorter chain from the same provider) is ineligible, re-evaluated cold:
// insufficient confirmations, then unknown height. Every read equals a cold read.
func TestReceiptReorg(t *testing.T) {
	conformance.Covers(t, "C-btc-24")
	g := newRig(t)
	v := g.v()
	g.read(v, g.r, "AA")
	g.read(v, g.r, "BA")
	tipA := v.View.TipHash

	// tip extension: re-check only
	g.s.extend(tipA, 3, 0, "")
	v = g.v()
	e, use := g.read(v, g.r, "AA")
	if !use.Used || !e.Live() || e.Confirmations != 24 {
		t.Fatalf("tip extension: %s / %+v", e, use)
	}
	// a policy that the new depth fails is applied to the cached binding too (same answer as cold)
	v2 := g.v()
	v2.Policy.MinConfirmations = 30
	if e, _ := g.read(v2, openR(t, g.loc, ReceiptOptions{ReadOnly: true}), "AA"); e.State != StateInsufficient {
		t.Fatalf("%s", e)
	}

	// a reorg above both blocks (fork at 20): the receipts' tip is gone, so both re-select cold, still verified
	h20, _ := v.View.HeaderAt(20)
	g.s.extend(h20.Hash, 15, 0, "above")
	v = g.v()
	e, use = g.read(v, g.r, "AA")
	wantUse(t, use, false, "reorganised")
	if !e.Live() || !use.Written {
		t.Fatalf("reorg above: %s / %+v", e, use)
	}
	if _, use = g.read(v, g.r, "AA"); !use.Used {
		t.Fatalf("re-verified receipt not used: %+v", use)
	}
	g.read(v, g.r, "BA")
	tipB := v.View.TipHash

	// a heavier branch from block 9 without A's root at 10: the cached binding never survives
	h9, _ := v.View.HeaderAt(9)
	saved := g.s.roots[10]
	delete(g.s.roots, 10)
	g.s.extend(h9.Hash, 40, 0, "fork")
	g.s.roots[10] = saved
	v = g.v()
	e, use = g.read(v, g.r, "AA")
	wantUse(t, use, false, "reorganised")
	if e.State != StateOrphaned || e.Live() || use.Written {
		t.Fatalf("after the reorg: %s / %+v", e, use)
	}
	if b := BoundOf(e, 0); b.Quality != resolve.Local {
		t.Fatalf("orphaned bound still ranks: %+v", b)
	}
	if e, _ := g.read(v, g.r, "BA"); !e.Live() {
		t.Fatalf("B's block is on the new branch too: %s", e)
	}

	// back: the branch the receipt was written on becomes the heaviest again, so its tip is active again
	g.s.extend(tipB, 30, 0, "back")
	v = g.v()
	if e, use = g.read(v, g.r, "AA"); !use.Used || !e.Live() {
		t.Fatalf("reorg back: %s / %+v", e, use)
	}

	// deep rollback: the header store replaced by a shorter copy from the same provider
	for _, upTo := range []int64{12, 8} {
		c := copyChain(t, g.s.p, "test-headers", v.View, upTo, g.s.now)
		vr := viewOf(c, g.s.policy(), g.w.blobs)
		e, use := g.read(vr, g.r, "AA")
		wantUse(t, use, false, "rolled back")
		want := map[int64]State{12: StateInsufficient, 8: StateUnknownHeight}[upTo]
		if e.State != want || e.Live() {
			t.Fatalf("rollback to %d: %s", upTo, e)
		}
	}
	// equal-work tips above the block: unresolved. A receipt written at the tied height has its tip above the fork
	// point, off the accepted chain, so it is re-checked cold (and the block below the fork still verifies)
	os.Remove(g.r.path(receiptSubdir, g.w.ids["AA"]))
	if _, use := g.read(v, g.r, "AA"); !use.Written {
		t.Fatalf("setup: %+v", use)
	}
	tip := v.View.TipHash
	tipNode := g.s.c.nodes[tip]
	parent := tipNode.parent.hash
	g.s.extend(parent, 1, 0, "tie")
	vt := g.v()
	if vt.View.Unresolved == 0 {
		t.Fatal("fixture: no tie")
	}
	e, use = g.read(vt, g.r, "AA")
	wantUse(t, use, false, "reorganised")
	if !e.Live() {
		t.Fatalf("tie above the block: %s", e)
	}
}

// --- P-07: a cache, never evidence ----------------------------------------------------------------------------------

// TestPropertyReceiptsColdEqualsWarm: P-07 for the receipt store. Seeded histories (fixture statements read as
// operations: anchors = anchor the signer's head at a coming block; authored = mine blocks; holds = a heavier
// branch replacing the last blocks, dropping the anchors' roots there; describes = change the policy; observed =
// shift the clock: fresh, stale, or before the last sync). After every step every anchor is read cold, through
// one persistent store, and through the resolver both ways: the answers are identical. At the end the state
// directory is deleted and a cold start gives the same answers again.
func TestPropertyReceiptsColdEqualsWarm(t *testing.T) {
	conformance.Partial(t, "P-07", "the bitcoin-time receipt store: warm, cold and deleted-store answers identical over seeded chain histories, at the evidence and through the resolver; the resolver's own caches are not wired")
	opts := fixture.Options{Keys: 3, Blobs: 3, MaxStatements: 14, Kinds: []string{"anchors", "anchors", "authored", "authored", "holds", "describes", "observed"}}
	used := 0
	fixture.Check(t, 0x7ec0_0000, 30, opts, func(f fixture.Fixture) string {
		msg, u := replayReceipts(t, f)
		used += u
		return msg
	})
	if used == 0 {
		t.Fatal("no read was answered from a receipt: the property never exercised the store")
	}
}

func replayReceipts(t *testing.T, f fixture.Fixture) (string, int) {
	w := newWorld(t)
	s := newSynth(t, testParams("testchain", 0x207fffff))
	s.roots = w.roots
	tip := s.extend(s.genesis(), 20, 0, "")
	loc, err := Locate(gitRoot(t), "")
	if err != nil {
		t.Fatal(err)
	}
	r := openR(t, loc, ReceiptOptions{})
	pol := s.policy()
	clock := 0 // 0 fresh, 1 stale view, 2 clock before the last sync
	var anchors []string
	used := 0
	verifier := func() *Verifier {
		snap := s.c.Snapshot()
		now := time.Unix(int64(snap.TipTime), 0).Add(10 * time.Minute)
		sync := now.Add(-time.Minute)
		switch clock {
		case 1:
			now = now.Add(3 * time.Hour)
		case 2:
			sync = now.Add(time.Hour)
		}
		s.c.MarkSynced(sync)
		return &Verifier{Policy: pol, View: s.c.Snapshot(), Blobs: w.blobs, Now: func() time.Time { return now }}
	}
	check := func(step int, r *Receipts) string {
		v := verifier()
		vr := *v
		vr.Receipts = r
		for _, a := range anchors {
			cold := v.Evaluate(w.sts[a])
			warm, use := r.Evaluate(v, w.sts[a])
			if use.Used {
				used++
			}
			if !reflect.DeepEqual(cold, warm) {
				return fmt.Sprintf("step %d anchor %s (%+v):\ncold %s %+v\nwarm %s %+v", step, a, use, cold, cold, warm, warm)
			}
			if again := vr.Evaluate(w.sts[a]); !reflect.DeepEqual(cold, again) {
				return fmt.Sprintf("step %d anchor %s through Verifier.Receipts: %s vs %s", step, a, cold, again)
			}
		}
		if len(anchors) > 0 {
			for _, x := range []string{"V", "W", "X"} {
				c := resolve.New(w.logs(nil), resolve.WithTimeVerifier(TimeVerifier{V: v})).Artifact(dig(x)).Render()
				h := resolve.New(w.logs(nil), resolve.WithTimeVerifier(TimeVerifier{V: &vr})).Artifact(dig(x)).Render()
				if c != h {
					return fmt.Sprintf("step %d blob %s: the resolver's answer changed with receipts:\n%s\nvs\n%s", step, x, c, h)
				}
			}
		}
		return ""
	}
	for i, st := range f.Statements {
		height := s.c.Snapshot().TipHeight
		switch st.Kind {
		case "anchors":
			name := fmt.Sprintf("a%d", i)
			w.authored("c"+name, st.Signer, st.Blob)
			h := height + 1 + int64(st.Time%3)
			for w.roots[h] != nil {
				h++
			}
			w.anchorAt(name, st.Signer, h)
			anchors = append(anchors, name)
		case "authored":
			tip = s.extend(s.c.Snapshot().TipHash, 1+st.Time%6, 0, fmt.Sprint("x", i))
		case "holds":
			k := int64(1 + st.Time%6)
			if height-k < 1 {
				continue
			}
			fork, _ := s.c.Snapshot().HeaderAt(height - k)
			saved := map[int64][]byte{}
			for h := height - k + 1; h <= height+1; h++ {
				if r, ok := s.roots[h]; ok {
					saved[h] = r
					delete(s.roots, h)
				}
			}
			tip = s.extend(fork.Hash, int(k)+1, 0, fmt.Sprint("r", i))
			for h, r := range saved {
				s.roots[h] = r
			}
		case "describes":
			pol.MinConfirmations = int64(1 + st.Time%8)
			pol.SettledDepth = int64(3 + st.Time%20)
		case "observed":
			clock = st.Time % 3
		}
		if msg := check(i, r); msg != "" {
			return msg, used
		}
	}
	_ = tip
	// a cold start: the state directory deleted, then reopened
	if err := os.RemoveAll(loc.Dir); err != nil {
		t.Fatal(err)
	}
	if msg := check(len(f.Statements), openR(t, loc, ReceiptOptions{})); msg != "" {
		return "after deleting the state directory: " + msg, used
	}
	return "", used
}

// TestReceiptsConcurrent: concurrent reads and writes of one store answer alike (run under -race).
func TestReceiptsConcurrent(t *testing.T) {
	g := newRig(t)
	v := g.v()
	want := v.Evaluate(g.w.sts["AA"])
	done := make(chan string, 8)
	for i := 0; i < 8; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				e, _ := g.r.Evaluate(v, g.w.sts["AA"])
				if !reflect.DeepEqual(e, want) {
					done <- fmt.Sprintf("%s vs %s", e, want)
					return
				}
			}
			done <- ""
		}()
	}
	for i := 0; i < 8; i++ {
		if m := <-done; m != "" {
			t.Fatal(m)
		}
	}
	if st := g.r.Stats(); st.Used+st.Cold != 80 || st.Written == 0 {
		t.Fatalf("%+v", st)
	}
}

// TestReceiptKeepsDisclosures: a receipt reproduces the cold evaluation's disclosures (a pending calendar, an
// unsupported attestation), not only its state; and on a view that is no longer fresh the eligibility half adds its
// settled-depth note and "as of" to the cached binding exactly as to a cold one.
func TestReceiptKeepsDisclosures(t *testing.T) {
	w := newWorld(t)
	w.authored("A1", "A", "X")
	cov := unhex(t, w.head["A"])
	w.roots[10] = sha(cov, nonce("AA"))
	proof := otsFile(cov, []byte{tagFork}, attPending("https://calendar.example"), []byte{tagFork}, attOther([8]byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte("x")),
		opAppendB(nonce("AA")), opSHA256B(), attBitcoin(10))
	w.anchorProof("AA", "A", proof, ProofFormat)
	s := w.chain(30)
	loc, _ := Locate(gitRoot(t), "")
	r := openR(t, loc, ReceiptOptions{})
	v := s.fresh(w.blobs)
	v.Policy.SettledDepth = 5
	cold := v.Evaluate(w.sts["AA"])
	if !cold.Live() || len(cold.Notes) != 2 || !cold.AsOf.IsZero() {
		t.Fatalf("fixture: %s %q", cold, cold.Notes)
	}
	r.Evaluate(v, w.sts["AA"])
	e, use := r.Evaluate(v, w.sts["AA"])
	wantUse(t, use, true, "")
	sameEvidence(t, cold, e, use)
	later := v.Now().Add(3 * time.Hour)
	v.Now = func() time.Time { return later }
	cold = v.Evaluate(w.sts["AA"])
	if !cold.Live() || len(cold.Notes) != 3 || cold.AsOf.IsZero() {
		t.Fatalf("fixture (stale view): %s %q", cold, cold.Notes)
	}
	e, use = r.Evaluate(v, w.sts["AA"])
	wantUse(t, use, true, "")
	sameEvidence(t, cold, e, use)
}

// copyTree copies a directory tree, keeping file modes.
func copyTree(t testing.TB, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		to := filepath.Join(dst, rel)
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(to, fi.Mode().Perm())
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(to, b, fi.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestReceiptStoreRefusesSymlinks: opening the receipt store refuses a symbolic link at its key, its directories or
// the state directory, naming the path; nothing is created or chmodded through the link and the link stays.
// (A link at one receipt file is a downgraded receipt: TestReceiptCorruptOrForeign.)
func TestReceiptStoreRefusesSymlinks(t *testing.T) {
	for _, at := range []string{"key", "receipts dir", "receipt subdir", "state dir"} {
		t.Run(at, func(t *testing.T) {
			real := Location{Dir: filepath.Join(t.TempDir(), "real"), Hub: "dir:/hub-under-test"}
			r0 := openR(t, real, ReceiptOptions{})
			keyBefore, _ := os.ReadFile(r0.path(keyFileName))
			loc := Location{Dir: filepath.Join(t.TempDir(), "state"), Hub: real.Hub}
			dir := filepath.Join(loc.Dir, receiptsDir)
			var link, target string
			switch at {
			case "key":
				os.MkdirAll(dir, 0o700)
				link, target = filepath.Join(dir, keyFileName), r0.path(keyFileName)
			case "receipts dir":
				os.MkdirAll(loc.Dir, 0o700)
				link, target = dir, r0.dir
			case "receipt subdir":
				os.MkdirAll(dir, 0o700)
				link, target = filepath.Join(dir, receiptSubdir), r0.path(receiptSubdir)
			case "state dir":
				link, target = loc.Dir, real.Dir
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			os.Chmod(target, 0o755) // a chmod through the link would tighten this back
			_, err := OpenReceipts(loc, ReceiptOptions{NoSync: true})
			if !errors.Is(err, ErrSymlink) || !strings.Contains(err.Error(), link) {
				t.Fatalf("open through a symlink at the %s: %v, want a refusal naming %s", at, err, link)
			}
			if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("the link at the %s was replaced", at)
			}
			if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o755 {
				t.Fatalf("the link's target was chmodded to %v", fi.Mode().Perm())
			}
			if after, _ := os.ReadFile(r0.path(keyFileName)); !bytes.Equal(keyBefore, after) {
				t.Fatal("the key behind the link changed")
			}
		})
	}
}
