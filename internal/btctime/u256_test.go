package btctime

import (
	"bytes"
	"context"
	"math/big"
	"math/rand"
	"runtime"
	"testing"
	"time"
)

// TestU256AgreesWithBig: the in-place chainwork arithmetic agrees with math/big on random and edge values: the
// round trip, addition (and its overflow at 2^256), comparison, and the hash-as-integer reading CheckProofOfWork uses.
func TestU256AgreesWithBig(t *testing.T) {
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	max := new(big.Int).Sub(two256, big.NewInt(1))
	rng := rand.New(rand.NewSource(0x5eed_0256))
	randBig := func() *big.Int {
		switch rng.Intn(6) {
		case 0:
			return big.NewInt(0)
		case 1:
			return new(big.Int).Set(max)
		case 2:
			return new(big.Int).Lsh(big.NewInt(1), uint(rng.Intn(256)))
		}
		b := make([]byte, 1+rng.Intn(32))
		rng.Read(b)
		return new(big.Int).SetBytes(b)
	}
	for i := 0; i < 20000; i++ {
		a, b := randBig(), randBig()
		ua, ok1 := u256FromBig(a)
		ub, ok2 := u256FromBig(b)
		if !ok1 || !ok2 || ua.big().Cmp(a) != 0 || ub.big().Cmp(b) != 0 {
			t.Fatalf("round trip %x %x", a, b)
		}
		if got, want := ua.cmp(ub), a.Cmp(b); got != want {
			t.Fatalf("cmp(%x, %x) = %d, want %d", a, b, got, want)
		}
		sum := new(big.Int).Add(a, b)
		us, ok := ua.add(ub)
		if fits := sum.Cmp(two256) < 0; ok != fits || (fits && us.big().Cmp(sum) != 0) {
			t.Fatalf("add(%x, %x) = %x ok %v; want %x", a, b, us.big(), ok, sum)
		}
	}
	for _, bad := range []*big.Int{nil, big.NewInt(-1), two256} {
		if _, ok := u256FromBig(bad); ok {
			t.Fatalf("u256FromBig(%v) accepted", bad)
		}
	}
	for i := 0; i < 1000; i++ {
		var h Hash
		rng.Read(h[:])
		if hashU256(h).big().Cmp(hashInt(h)) != 0 {
			t.Fatalf("hashU256(%s) disagrees with hashInt", h)
		}
	}
}

// TestCompactNodeTipWork: the view's TipWork (the exported *big.Int) equals the big.Int sum of every header's work
// from the bootstrap's recorded work below, on the real fixture (one retarget inside it).
func TestCompactNodeTipWork(t *testing.T) {
	c, _ := mainnetChain(t, fixtureTip)
	v := c.Snapshot()
	want := new(big.Int).Set(workBelowFixture)
	for h := int64(fixtureBase); h <= fixtureTip; h++ {
		hd, ok := v.HeaderAt(h)
		if !ok {
			t.Fatalf("no header at %d", h)
		}
		if hd.Raw != hd.Serialize() || dsha256(hd.Raw[:]) != hd.Hash {
			t.Fatalf("header %d: fields read from the compact node disagree with its raw bytes", h)
		}
		want.Add(want, Work(target(hd.Bits)))
	}
	if v.TipWork.Cmp(want) != 0 {
		t.Fatalf("tip work %x, want %x", v.TipWork, want)
	}
}

// BenchmarkHeaderDBLoadSynthetic loads a database of b.N-independent size (100,000 easy-work headers from genesis)
// and reports the retained heap and time per header: the figure a genesis sync's load cost extrapolates from,
// over far more headers than the mainnet fixture holds. Run: go test -run X -bench HeaderDBLoadSynthetic.
func BenchmarkHeaderDBLoadSynthetic(b *testing.B) {
	const n = 100_000
	p := testParams("bench", 0x207fffff)
	s := newSynth(b, p)
	s.extend(s.genesis(), n, 0, "")
	_, rest, _ := s.c.held()
	var in bytes.Buffer
	for _, r := range rest {
		in.Write(r)
	}
	d := testDB(b)
	if _, err := d.Sync(context.Background(), p, bytes.NewReader(in.Bytes()), SyncOptions{Now: clockAt(s.now)}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	var heap float64
	for i := 0; i < b.N; i++ {
		runtime.GC()
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		start := time.Now()
		c, err := d.Load(p, s.now)
		if err != nil {
			b.Fatal(err)
		}
		v := c.Snapshot()
		el := time.Since(start)
		runtime.GC()
		runtime.ReadMemStats(&m1)
		heap = float64(m1.HeapAlloc-m0.HeapAlloc) / float64(c.Len())
		b.ReportMetric(float64(el.Nanoseconds())/1000/float64(c.Len()), "µs/header")
		runtime.KeepAlive(c)
		runtime.KeepAlive(v)
	}
	b.ReportMetric(heap, "B/header")
}
