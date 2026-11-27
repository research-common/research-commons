package resolve

import (
	"fmt"
	"slices"
	"testing"

	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// mergeDenseLines signs a legal log, including repeated merges of old forks.
// The sequence number always advances along prev; all merges name lower seqs.
func mergeDenseLines(n, m int) (string, [][]byte) {
	k := testKey("K01") // Ed25519: signing does not dominate the cost test.
	var lines [][]byte
	sign := func(seq int64, prev, name string, merges []string) string {
		line, id := wire.Sign(wire.Draft{Kind: "authored", Seq: seq, Prev: prev, TS: "2026-10-16T03:00:00Z", Merges: merges,
			Body: obj("content", contentOf(name), "type", "dataset")}, k)
		lines = append(lines, line)
		return id
	}
	root := sign(0, "", "root", nil)
	forks := make([]string, n)
	for i := range forks {
		forks[i] = sign(1, root, fmt.Sprintf("fork-%d", i), nil)
	}
	slices.Sort(forks)
	prev := forks[0]
	for i := 0; i < m; i++ {
		prev = sign(int64(i+2), prev, fmt.Sprintf("merge-%d", i), forks[1:])
	}
	return k.Signer(), lines
}

func deliverDense(tb testing.TB, signer string, lines [][]byte) *keylog.Store {
	tb.Helper()
	s := keylog.NewStoredStore()
	for _, line := range lines {
		if _, err := s.Log(signer).Add(line); err != nil {
			tb.Fatal(err)
		}
	}
	return s
}

// BenchmarkMergeDensePipeline separates parsing and signature verification in
// delivery from resolver construction and log rendering. Signing is setup only.
func BenchmarkMergeDensePipeline(b *testing.B) {
	for _, size := range [][2]int{{100, 100}, {200, 200}, {20, 2000}, {900, 1300}} {
		b.Run(fmt.Sprintf("%d-forks-%d-merges", size[0], size[1]), func(b *testing.B) {
			signer, lines := mergeDenseLines(size[0], size[1])
			s := deliverDense(b, signer, lines)
			b.Run("delivery-cold", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					wire.ResetMemo()
					b.StartTimer()
					deliverDense(b, signer, lines)
				}
			})
			b.Run("resolve.New", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					r := New(s)
					if len(r.byID) != len(lines) {
						b.Fatal("lost lines")
					}
				}
			})
			b.Run("keylog.View", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					v := s.Log(signer).View()
					if len(v.Forks) != 1 || !v.Forks[0].Cleared() || len(v.Lines) != len(lines) {
						b.Fatal("wrong view")
					}
				}
			})
		})
	}
}

func BenchmarkMergeDenseRevocation(b *testing.B) {
	for _, size := range [][2]int{{100, 100}, {200, 200}, {20, 2000}, {900, 1300}} {
		b.Run(fmt.Sprintf("%d-forks-%d-merges", size[0], size[1]), func(b *testing.B) {
			signer, lines := mergeDenseLines(size[0], size[1])
			last, err := wire.ReadStored(lines[len(lines)-1])
			if err != nil {
				b.Fatal(err)
			}
			rev, _ := wire.Sign(wire.Draft{Kind: "revoke_key", Seq: last.Seq + 1, Prev: last.ID, TS: "2026-10-16T03:00:00Z", Body: obj("reason", "superseded")}, testKey("K01"))
			lines = append(lines, rev)
			s := deliverDense(b, signer, lines)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				r := New(s)
				if len(r.byID) != len(lines) {
					b.Fatal("lost lines")
				}
			}
		})
	}
}
