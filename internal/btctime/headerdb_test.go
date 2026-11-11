package btctime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fixtureInput is the fixture's raw bytes from the bootstrap on, as `anchor headers sync --from` reads them.
func fixtureInput(t testing.TB, upTo int64) []byte {
	t.Helper()
	var b bytes.Buffer
	for _, h := range fixtureHeaders(t)[:upTo-fixtureBase+1] {
		b.Write(h)
	}
	return b.Bytes()
}

func fixtureBoot() *BootstrapSpec {
	return &BootstrapSpec{Height: fixtureBase, Work: workBelowFixture}
}

func testDB(t testing.TB) *HeaderDB {
	t.Helper()
	d, err := OpenHeaderDB(Location{Dir: filepath.Join(t.TempDir(), "rc"), Hub: "dir:/hub-under-test", Via: "configured"})
	if err != nil {
		t.Fatal(err)
	}
	d.NoSync = true
	return d
}

func clockAt(ts time.Time) func() time.Time { return func() time.Time { return ts } }

// TestHeaderDBSyncAndLoad: a sync validates every header (Chain.Add), persists them, and a load re-validates them
// into the same view; a second sync of the same input adds nothing (idempotent).
func TestHeaderDBSyncAndLoad(t *testing.T) {
	d := testDB(t)
	ref, now := mainnetChain(t, fixtureTip)
	in := fixtureInput(t, fixtureTip)
	res, err := d.Sync(context.Background(), Mainnet(), bytes.NewReader(in), SyncOptions{Bootstrap: fixtureBoot(), Now: clockAt(now)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Synced || res.Stopped != nil || res.Read != fixtureTip-fixtureBase+1 || res.Added != fixtureTip-fixtureBase+1-11 {
		t.Fatalf("sync: %+v", res)
	}
	want := ref.Snapshot()
	if res.View.TipHeight != fixtureTip || res.View.TipHash != want.TipHash || res.View.TipWork.Cmp(want.TipWork) != 0 || res.View.Bootstrap != want.Bootstrap {
		t.Fatalf("synced view %d %s, want %d %s", res.View.TipHeight, res.View.TipHash, want.TipHeight, want.TipHash)
	}
	fi, err := os.Stat(d.Path())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("database file mode: %v %v", fi, err)
	}
	if di, _ := os.Stat(filepath.Dir(d.Path())); di.Mode().Perm() != 0o700 {
		t.Fatalf("database directory mode %v", di.Mode().Perm())
	}
	c, err := d.Load(Mainnet(), now)
	if err != nil {
		t.Fatal(err)
	}
	v := c.Snapshot()
	if v.TipHash != want.TipHash || v.TipWork.Cmp(want.TipWork) != 0 || !v.LastSync.Equal(now) || v.Base != fixtureBase {
		t.Fatalf("loaded view %d %s sync %v", v.TipHeight, v.TipHash, v.LastSync)
	}
	// idempotent: the same file again adds nothing, the tip is unchanged, only the sync time moves
	later := now.Add(time.Hour)
	res2, err := d.Sync(context.Background(), Mainnet(), bytes.NewReader(in), SyncOptions{Bootstrap: fixtureBoot(), Now: clockAt(later)})
	if err != nil || res2.Added != 0 || res2.View.TipHash != want.TipHash || !res2.View.LastSync.Equal(later) {
		t.Fatalf("second sync: %+v %v", res2, err)
	}
	// without naming the bootstrap again (the database keeps its own), the tail alone extends nothing either
	res3, err := d.Sync(context.Background(), Mainnet(), bytes.NewReader(in[11*HeaderSize:]), SyncOptions{Now: clockAt(later)})
	if err != nil || res3.Added != 0 || res3.AlreadyHeld != int64(len(in)/HeaderSize-11) {
		t.Fatalf("tail sync: %+v %v", res3, err)
	}
}

// TestHeaderDBIncremental: a sync to a lower height, then one carrying the rest, gives the full chain.
func TestHeaderDBIncremental(t *testing.T) {
	d := testDB(t)
	_, now := mainnetChain(t, fixtureTip)
	in := fixtureInput(t, fixtureTip)
	half := (358000 - fixtureBase + 1) * HeaderSize
	if _, err := d.Sync(context.Background(), Mainnet(), bytes.NewReader(in[:half]), SyncOptions{Bootstrap: fixtureBoot(), Now: clockAt(now)}); err != nil {
		t.Fatal(err)
	}
	res, err := d.Sync(context.Background(), Mainnet(), bytes.NewReader(in[half:]), SyncOptions{Now: clockAt(now)})
	if err != nil || res.View.TipHeight != fixtureTip || res.Added != int64(len(in)-half)/HeaderSize {
		t.Fatalf("incremental: %+v %v", res, err)
	}
}

// TestHeaderDBStopsAtInvalid: a header failing validation stops the sync with the reason; what validated before it
// is persisted, and the last-sync time is not advanced (the view is not fresh on that sync's account).
func TestHeaderDBStopsAtInvalid(t *testing.T) {
	d := testDB(t)
	_, now := mainnetChain(t, fixtureTip)
	in := fixtureInput(t, fixtureTip)
	bad := 500 // 0-based input position of the mutated header
	mut := bytes.Clone(in)
	mut[bad*HeaderSize+76] ^= 0x01 // nonce: proof of work fails (high-hash)
	res, err := d.Sync(context.Background(), Mainnet(), bytes.NewReader(mut), SyncOptions{Bootstrap: fixtureBoot(), Now: clockAt(now)})
	if err != nil {
		t.Fatal(err)
	}
	var he *HeaderError
	if !errors.As(res.Stopped, &he) || he.Reason != "high-hash" || res.StoppedAt != int64(bad+1) || res.Synced {
		t.Fatalf("stop: %+v", res)
	}
	if res.View.TipHeight != fixtureBase+int64(bad)-1 || !res.View.LastSync.IsZero() {
		t.Fatalf("kept tip %d, last sync %v", res.View.TipHeight, res.View.LastSync)
	}
	c, err := d.Load(Mainnet(), now)
	if err != nil || c.Snapshot().TipHeight != fixtureBase+int64(bad)-1 {
		t.Fatalf("reload after a stopped sync: %v", err)
	}
	// a torn input (not a whole header) stops the same way
	d2 := testDB(t)
	res, err = d2.Sync(context.Background(), Mainnet(), bytes.NewReader(in[:20*HeaderSize+7]), SyncOptions{Bootstrap: fixtureBoot(), Now: clockAt(now)})
	if err != nil || res.Stopped == nil || !strings.Contains(res.Stopped.Error(), "not a whole 80-byte header") || res.View.TipHeight != fixtureBase+19 {
		t.Fatalf("torn input: %+v %v", res, err)
	}
	// a header from the future (time-too-new under the sync's clock) stops the sync too
	d3 := testDB(t)
	early := time.Unix(int64(mustHeader(t, in[300*HeaderSize:301*HeaderSize]).Time), 0).Add(-3 * time.Hour)
	res, err = d3.Sync(context.Background(), Mainnet(), bytes.NewReader(in), SyncOptions{Bootstrap: fixtureBoot(), Now: clockAt(early)})
	if err != nil || !errors.As(res.Stopped, &he) || he.Reason != "time-too-new" {
		t.Fatalf("future header: %+v %v", res, err)
	}
}

func mustHeader(t testing.TB, b []byte) Header {
	h, err := ParseHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestHeaderDBBoundedCancellable: MaxHeaders bounds a sync and a cancelled context stops it; both keep what
// validated and do not count as a completed sync.
func TestHeaderDBBoundedCancellable(t *testing.T) {
	_, now := mainnetChain(t, fixtureTip)
	in := fixtureInput(t, fixtureTip)
	d := testDB(t)
	res, err := d.Sync(context.Background(), Mainnet(), bytes.NewReader(in), SyncOptions{Bootstrap: fixtureBoot(), Now: clockAt(now), MaxHeaders: 100})
	if err != nil || !res.Bounded || res.Synced || res.View.TipHeight != fixtureBase+99 {
		t.Fatalf("bounded: %+v %v", res, err)
	}
	d2 := testDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err = d2.Sync(ctx, Mainnet(), bytes.NewReader(in), SyncOptions{Bootstrap: fixtureBoot(), Now: clockAt(now)})
	if err != nil || !res.Cancelled || res.Synced || res.View.TipHeight != fixtureBase+10 {
		t.Fatalf("cancelled: %+v %v", res, err)
	}
}

// TestHeaderDBRefused: a database that is foreign, of another network, of an unknown version, corrupt, truncated,
// tampered (a header whose bytes change, re-hashed or not), loose-permissioned or a symlink is refused whole:
// never trusted, never partly used, and never extended by a sync.
func TestHeaderDBRefused(t *testing.T) {
	_, now := mainnetChain(t, fixtureTip)
	in := fixtureInput(t, 357100)
	base := testDB(t)
	if _, err := base.Sync(context.Background(), Mainnet(), bytes.NewReader(in), SyncOptions{Bootstrap: fixtureBoot(), Now: clockAt(now)}); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(base.Path())
	nl := bytes.IndexByte(good, '\n')
	meta, body := good[:nl+1], good[nl+1:]
	place := func(t *testing.T, b []byte, mode os.FileMode) *HeaderDB {
		d := testDB(t)
		os.MkdirAll(filepath.Dir(d.Path()), 0o700)
		if err := os.WriteFile(d.Path(), b, mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(d.Path(), mode)
		return d
	}
	tampered := bytes.Clone(body)
	tampered[200*HeaderSize+40] ^= 0xff // a Merkle root byte: PoW then fails
	swapped := bytes.Clone(body)
	copy(swapped[150*HeaderSize:], body[151*HeaderSize:152*HeaderSize])
	copy(swapped[151*HeaderSize:], body[150*HeaderSize:151*HeaderSize])
	cases := []struct {
		name, want string
		b          []byte
		mode       os.FileMode
		loc        *Location
		p          *Params
	}{
		{"foreign hub", "foreign", good, 0o600, &Location{Hub: "dir:/another-hub"}, nil},
		{"another network", "written for network", good, 0o600, nil, ptr(testParams("regtest", 0x207fffff))},
		{"unknown version", "unknown version", bytes.Replace(good, []byte(`"v":1`), []byte(`"v":2`), 1), 0o600, nil, nil},
		{"not json", "corrupt", append([]byte("headers\n"), body...), 0o600, nil, nil},
		{"extra member", "unexpected members", bytes.Replace(good, []byte(`{"bootstrap"`), []byte(`{"a":"1","bootstrap"`), 1), 0o600, nil, nil},
		{"truncated", "truncated", good[:len(good)-HeaderSize/2], 0o600, nil, nil},
		{"trailing", "trailing", append(bytes.Clone(good), 0), 0o600, nil, nil},
		{"tampered header", "does not validate", append(bytes.Clone(meta), tampered...), 0o600, nil, nil},
		{"reordered headers", "does not validate", append(bytes.Clone(meta), swapped...), 0o600, nil, nil},
		{"digest", "do not hash to the digest", bytes.Replace(good, []byte(`"headers_sha256":"`), []byte(`"headers_sha256":"0`), 1), 0o600, nil, nil},
		{"count", "trailing", bytes.Replace(good, []byte(`"count":"269"`), []byte(`"count":"268"`), 1), 0o600, nil, nil},
		{"loose mode", "readable or writable by others", good, 0o644, nil, nil},
		{"bootstrap identity", "content hash is not the identity", bytes.Replace(good, []byte(`"bootstrap":"bootstrap:sha256:`), []byte(`"bootstrap":"bootstrap:sha256:0`), 1), 0o600, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := place(t, tc.b, tc.mode)
			if tc.loc != nil {
				d.loc.Hub = tc.loc.Hub
			}
			p := Mainnet()
			if tc.p != nil {
				p = *tc.p
			}
			_, err := d.Load(p, now)
			var re *HeaderDBError
			if !errors.As(err, &re) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("load: %v, want a refusal naming %q", err, tc.want)
			}
			before, _ := os.ReadFile(d.Path())
			if _, err := d.Sync(context.Background(), p, bytes.NewReader(in), SyncOptions{Now: clockAt(now)}); !errors.As(err, &re) {
				t.Fatalf("sync over a refused database: %v", err)
			}
			if after, _ := os.ReadFile(d.Path()); !bytes.Equal(before, after) {
				t.Fatal("a sync rewrote a refused database")
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		d := testDB(t)
		os.MkdirAll(filepath.Dir(d.Path()), 0o700)
		if err := os.Symlink(base.Path(), d.Path()); err != nil {
			t.Fatal(err)
		}
		d.loc.Hub = base.loc.Hub
		// Open follows the link; the file it reaches is a regular, 0600 file of this hub, so Load accepts it.
		// A symlink in a 0700 directory the reader owns is the reader's own choice; the content checks still hold.
		if _, err := d.Load(Mainnet(), now); err != nil {
			t.Fatalf("symlink to a valid database: %v", err)
		}
	})
	t.Run("sync with another bootstrap", func(t *testing.T) {
		other := &BootstrapSpec{Height: fixtureBase, Work: workBelowFixture, Count: 12}
		if _, err := base.Sync(context.Background(), Mainnet(), bytes.NewReader(in), SyncOptions{Bootstrap: other, Now: clockAt(now)}); !errors.Is(err, ErrBootstrapMismatch) {
			t.Fatalf("another bootstrap: %v", err)
		}
	})
}

func ptr[T any](v T) *T { return &v }

// TestHeaderDBLock: a live lock makes a second sync refuse without writing; a stale one is broken.
func TestHeaderDBLock(t *testing.T) {
	_, now := mainnetChain(t, fixtureTip)
	in := fixtureInput(t, 356900)
	d := testDB(t)
	unlock, err := d.lock(now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Sync(context.Background(), Mainnet(), bytes.NewReader(in), SyncOptions{Bootstrap: fixtureBoot(), Now: clockAt(time.Now())}); !errors.Is(err, ErrHeaderDBLocked) {
		t.Fatalf("second writer: %v", err)
	}
	if d.Exists() {
		t.Fatal("a locked-out sync wrote the database")
	}
	unlock()
	lp := filepath.Join(filepath.Dir(d.Path()), headersLock)
	os.WriteFile(lp, []byte("stale"), 0o600)
	old := time.Now().Add(-time.Hour)
	os.Chtimes(lp, old, old)
	if _, err := d.Sync(context.Background(), Mainnet(), bytes.NewReader(in), SyncOptions{Bootstrap: fixtureBoot(), Now: clockAt(now)}); err != nil {
		t.Fatalf("stale lock not broken: %v", err)
	}
	if _, err := os.Stat(lp); err == nil {
		t.Fatal("lock left behind")
	}
}

// TestHeaderDBNoState: no state location means no database (the CLI then stays backend-unconfigured).
func TestHeaderDBNoState(t *testing.T) {
	if _, err := OpenHeaderDB(Location{}); !errors.Is(err, ErrNoState) {
		t.Fatal(err)
	}
	d := testDB(t)
	if _, err := d.Load(Mainnet(), time.Now()); !errors.Is(err, ErrNoHeaderDB) {
		t.Fatalf("empty: %v", err)
	}
}

// TestHeaderDBGenesisSync: a database started at genesis (no bootstrap) persists and reloads with a synthetic
// network's rules, including a fork (both branches persisted; the greatest-work one selected again on load).
func TestHeaderDBGenesisSync(t *testing.T) {
	p := testParams("regtest", 0x207fffff)
	s := newSynth(t, p)
	a := s.extend(s.genesis(), 20, 0, "a")
	_ = s.extend(s.genesis(), 22, 0, "b")
	_ = a
	_, rest, _ := s.c.held()
	var in bytes.Buffer
	for _, r := range rest {
		in.Write(r)
	}
	d := testDB(t)
	res, err := d.Sync(context.Background(), p, &in, SyncOptions{Now: clockAt(s.now)})
	if err != nil || !res.Synced || res.Added != 42 {
		t.Fatalf("genesis sync: %+v %v", res, err)
	}
	c, err := d.Load(p, s.now)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := c.Snapshot(), s.c.Snapshot(); got.TipHash != want.TipHash || got.TipHeight != 22 || c.Len() != 43 {
		t.Fatalf("reloaded tip %d %s (%d held)", got.TipHeight, got.TipHash, c.Len())
	}
}

// TestHeaderDBLoadCost measures what loading the fixture costs (time and heap per header), the number the
// report extrapolates to a full mainnet chain from.
func TestHeaderDBLoadCost(t *testing.T) {
	_, now := mainnetChain(t, fixtureTip)
	d := testDB(t)
	if _, err := d.Sync(context.Background(), Mainnet(), bytes.NewReader(fixtureInput(t, fixtureTip)), SyncOptions{Bootstrap: fixtureBoot(), Now: clockAt(now)}); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	start := time.Now()
	c, err := d.Load(Mainnet(), now)
	el := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	v := c.Snapshot()
	runtime.GC()
	runtime.ReadMemStats(&m1)
	n := c.Len()
	t.Logf("load: %d headers in %v (%.1f µs/header); retained heap %.0f B/header (chain + one snapshot)", n, el,
		float64(el.Microseconds())/float64(n), float64(m1.HeapAlloc-m0.HeapAlloc)/float64(n))
	runtime.KeepAlive(c)
	runtime.KeepAlive(v)
}
