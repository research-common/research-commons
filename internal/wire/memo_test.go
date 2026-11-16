package wire

import (
	"bytes"
	"slices"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
)

// memoCorpus is every line the wire tests hold: the rc/1 vectors (positive and negative, both algorithms), the signed
// rc/2 identity vectors, and two lines no reader accepts.
func memoCorpus(t *testing.T) [][]byte {
	t.Helper()
	var lines [][]byte
	v := vectors(t)
	for _, set := range [][]conformance.Vector{v.Positive, v.EdPositive, v.Negative, v.EdNegative} {
		for _, x := range set {
			switch {
			case x.Delivered != "":
				lines = append(lines, []byte(x.Delivered))
			case x.SignedString != "" && x.Sig != "":
				lines = append(lines, lineFor(t, x.SignedString, x.Sig))
			}
		}
	}
	iv := ivLoad(t)
	for _, x := range iv.Positive {
		lines = append(lines, []byte(x.Line))
	}
	for _, x := range iv.Negative {
		lines = append(lines, []byte(x.Delivered))
	}
	lines = append(lines, []byte("not json"), nil)
	// distinct bytes only: a line that appears twice is one memo entry, which the counting test must not read as a miss
	var out [][]byte
	for _, l := range lines {
		if !slices.ContainsFunc(out, func(o []byte) bool { return bytes.Equal(o, l) }) {
			out = append(out, l)
		}
	}
	return out
}

// TestMemoIsInvisible: ReadStored through the memo returns exactly what a cold read returns, for every line of the
// corpus, on the first read and on every later one (a hit), refusals included; a caller that changes what it was
// given changes no later caller's statement.
func TestMemoIsInvisible(t *testing.T) {
	lines := memoCorpus(t)
	if len(lines) < 40 {
		t.Fatalf("only %d corpus lines", len(lines))
	}
	var cold []*Statement
	var coldErr []error
	restore := SetMemo(false)
	for _, l := range lines {
		st, err := ReadStored(l)
		cold, coldErr = append(cold, st), append(coldErr, err)
	}
	restore()
	restore = SetMemo(true)
	defer restore()
	refused, verified := 0, 0
	for round := 0; round < 3; round++ {
		for i, l := range lines {
			st, err := ReadStored(l)
			if d := sameRead(cold[i], coldErr[i], st, err); d != "" {
				t.Fatalf("round %d line %d: %s", round, i, d)
			}
			if round == 0 {
				if err != nil {
					refused++
				} else if st.Verified {
					verified++
				}
			}
			if err == nil && (st.Status != cold[i].Status || st.Why != cold[i].Why || !slices.Equal(st.Crit, cold[i].Crit) ||
				!slices.Equal(st.Unpinned, cold[i].Unpinned) || !slices.Equal(st.References(), cold[i].References())) {
				t.Fatalf("round %d line %d: status fields differ", round, i)
			}
			if err == nil && st.Actor != nil && *st.Actor != *cold[i].Actor {
				t.Fatalf("round %d line %d: actor differs", round, i)
			}
			if err == nil { // vandalise the copy: no later read may see it
				st.Verified, st.Status, st.Why, st.Seq, st.ID = !st.Verified, "vandalised", "x", -1, "x"
				for j := range st.Merges {
					st.Merges[j] = "x"
				}
				if st.Actor != nil {
					st.Actor.Identity = "x"
				}
			}
		}
	}
	if refused == 0 || verified < 20 {
		t.Fatalf("the corpus does not reach both outcomes: %d refused, %d verified", refused, verified)
	}
}

// TestMemoVerifiesOncePerLine: the counting test. However often a line is read, its signature is verified once; a
// line that differs by one byte is its own entry and is verified on its own; with the memo off every read verifies.
// The counter sits on the signature check itself (verify), so it counts the work, not the calls.
func TestMemoVerifiesOncePerLine(t *testing.T) {
	lines := memoCorpus(t)
	count := func(on bool, reads int) (map[string]int, int) {
		restore := SetMemo(on)
		defer restore()
		per := map[string]int{}
		total := 0
		stop := ObserveVerify(func(id string) { per[id]++; total++ })
		defer stop()
		for r := 0; r < reads; r++ {
			for _, l := range lines {
				ReadStored(l)
			}
		}
		return per, total
	}
	per1, once := count(true, 1)
	per3, thrice := count(true, 3)
	_, coldThrice := count(false, 3)
	if once == 0 {
		t.Fatal("no signature was verified: the counter did not reach the boundary")
	}
	if thrice != once {
		t.Fatalf("3 reads of every line verified %d signatures, 1 read verified %d", thrice, once)
	}
	if coldThrice != 3*once {
		t.Fatalf("with the memo off 3 reads verified %d, want %d (the counter misses verifications)", coldThrice, 3*once)
	}
	for id, n := range per3 {
		if per1[id] != n {
			t.Fatalf("statement %s verified %d times over 3 reads, %d over one", id, n, per1[id])
		}
	}
	// a line with a different byte is a different key: it is verified, and refused, on its own
	restore := SetMemo(true)
	defer restore()
	var good []byte
	for _, l := range lines {
		if st, err := ReadStored(l); err == nil && st.Verified {
			good = l
			break
		}
	}
	if good == nil {
		t.Fatal("no verified line")
	}
	n := 0
	stop := ObserveVerify(func(string) { n++ })
	defer stop()
	ReadStored(good) // memoised
	if n != 0 {
		t.Fatalf("a memoised line was verified again (%d)", n)
	}
	bad := bytes.Replace(good, []byte(`"sig":"`), []byte(`"sig":"0`), 1)
	if bytes.Equal(bad, good) {
		t.Fatal("the line has no sig member to damage")
	}
	if _, err := ReadStored(bad); err == nil {
		t.Fatal("a line with a damaged sig was read")
	}
	if n > 1 {
		t.Fatalf("a damaged copy verified %d times", n)
	}
}

// TestMemoSharesAcrossReaders: the identity evaluator reads every held line with the identity reader after the store
// and the view read it with the dual reader. The answers of the two readers differ (the identity reader holds a
// verified bad body as Invalid; the dual reader refuses an rc/1 one), so the line memos are separate and each
// reader's answer is its own; the cryptographic verification under both is one.
func TestMemoSharesAcrossReaders(t *testing.T) {
	lines := memoCorpus(t)
	run := func(on bool, readers ...func([]byte) (*Statement, error)) (map[string]int, []*Statement, []error) {
		restore := SetMemo(on)
		defer restore()
		per := map[string]int{}
		stop := ObserveVerify(func(id string) { per[id]++ })
		defer stop()
		var sts []*Statement
		var errs []error
		for _, l := range lines {
			for _, rd := range readers {
				st, err := rd(l)
				sts, errs = append(sts, st), append(errs, err)
			}
		}
		return per, sts, errs
	}
	dual := func(l []byte) (*Statement, error) { return ReadStored(l) }
	ident := func(l []byte) (*Statement, error) { return NewIdentityReader().Read(l) }
	dOnly, _, _ := run(true, dual)
	iOnly, _, _ := run(true, ident)
	both, memoSts, memoErrs := run(true, dual, ident)
	_, coldSts, coldErrs := run(false, dual, ident)
	sum := func(m map[string]int) (n int) {
		for _, v := range m {
			n += v
		}
		return
	}
	union := 0
	for id, n := range dOnly {
		union += max(n, iOnly[id])
	}
	for id, n := range iOnly {
		if _, ok := dOnly[id]; !ok {
			union += n
		}
	}
	if sum(both) != union || sum(both) >= sum(dOnly)+sum(iOnly) {
		t.Fatalf("dual %d + identity %d verifications alone, %d together, %d if every signature were checked once", sum(dOnly), sum(iOnly), sum(both), union)
	}
	if sum(iOnly) < 20 {
		t.Fatalf("only %d verifications: the corpus does not reach the boundary", sum(iOnly))
	}
	// each reader's answer is its own, and is the cold one
	for k := range memoSts {
		if x := sameRead(coldSts[k], coldErrs[k], memoSts[k], memoErrs[k]); x != "" {
			t.Fatalf("read %d: %s", k, x)
		}
	}
}

// TestMemoBound: past the byte bound ReadStored stops retaining lines and reads cold; the answers are unchanged.
func TestMemoBound(t *testing.T) {
	lines := memoCorpus(t)
	restore := SetMemo(true)
	defer restore()
	old, oldSigs := memoMaxBytes, memoMaxSigs
	memoMaxBytes, memoMaxSigs = 0, 0
	defer func() { memoMaxBytes, memoMaxSigs = old, oldSigs }()
	total := 0
	stop := ObserveVerify(func(string) { total++ })
	defer stop()
	for r := 0; r < 2; r++ {
		for _, l := range lines {
			ReadStored(l)
		}
	}
	memoMaxBytes, memoMaxSigs = old, oldSigs
	ResetMemo()
	once := 0
	stop2 := ObserveVerify(func(string) { once++ })
	defer stop2()
	for _, l := range lines {
		ReadStored(l)
	}
	if total != 2*once {
		t.Fatalf("with no room the memo still retained: %d verifications over 2 reads, %d over one", total, once)
	}
}
