package gate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// xzSecret is `{"secret":1}` compressed with xz (`xz -9e --check=crc32`): the forbidden key is in it, but not
// in its bytes, so a reader that read the member as opaque bytes would wrongly find it clean.
var xzSecret = func() []byte {
	b, _ := hex.DecodeString("fd377a585a0000016922de36020021011c00000010cf58cc01000b7b22736563726574223a317d008f9ca1410001200ca2ddb4bc9042990d010000000001595a")
	return b
}()

// tarFiles packs regular files (and, for a name ending in "/", a directory) in the given order.
func tarFiles(t testing.TB, files ...[2]string) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, f := range files {
		h := &tar.Header{Name: f[0], Mode: 0o644, Size: int64(len(f[1])), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if strings.HasSuffix(f[0], "/") {
			h.Typeflag, h.Size, h.Mode = tar.TypeDir, 0, 0o755
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gz(t testing.TB, b []byte) []byte {
	var o bytes.Buffer
	w := gzip.NewWriter(&o)
	w.Write(b)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return o.Bytes()
}

func unitsOf(us []resolve.ContentUnit) string {
	var s []string
	for _, u := range us {
		if u.Unscanned != "" {
			s = append(s, u.Name+" unscanned("+u.Unscanned+")")
		} else {
			s = append(s, u.Name+"="+string(u.Data))
		}
	}
	return strings.Join(s, " | ")
}

// TestScanUnits: the shipped content reader. An archive is walked by the store's scanner: one unit per member
// read, one unscanned unit per member it could not examine (named, with the limit); a non-archive blob is one
// unit as before; a blob in a compression the scanner cannot read is one unscanned unit, never opaque bytes.
func TestScanUnits(t *testing.T) {
	lim := store.DefaultLimits()
	ar := tarFiles(t, [2]string{"d/", ""}, [2]string{"d/a.json", `{"ok":1}`}, [2]string{"d/b.json.xz", string(xzSecret)})
	cases := []struct {
		name string
		data []byte
		lim  store.Limits
		want string
	}{
		{"plain", []byte(`{"secret":1}`), lim, `x={"secret":1}`},
		{"tar with an xz member", ar, lim, `x!/d/a.json={"ok":1} | x!/d/b.json.xz unscanned(compression=xz)`},
		{"tar.gz", gz(t, ar), lim, `x!/d/a.json={"ok":1} | x!/d/b.json.xz unscanned(compression=xz)`},
		{"gzip of one file", gz(t, []byte(`{"secret":1}`)), lim, `x={"secret":1}`},
		{"xz blob", xzSecret, lim, `x unscanned(compression=xz)`},
		{"nested", tarFiles(t, [2]string{"in.tar", string(tarFiles(t, [2]string{"s.json", `{"secret":1}`}))}), lim, `x!/in.tar!/s.json={"secret":1}`},
		{"member over member_bytes", tarFiles(t, [2]string{"a", "12345"}, [2]string{"b", "1"}), store.Limits{MemberBytes: 4}, `x!/a unscanned(member_bytes=4) | x!/b=1`},
		{"members limit stops the run", tarFiles(t, [2]string{"a", "1"}, [2]string{"b", "2"}), store.Limits{Members: 1}, `x!/a=1 | x!/<members from 2 on> unscanned(members=1)`},
	}
	for _, c := range cases {
		if got := unitsOf(ScanUnits("x", c.data, c.lim)); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
	// zip
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	f, _ := zw.Create("z.json")
	f.Write([]byte(`{"z":1}`))
	zw.Close()
	if got := unitsOf(ScanUnits("x", zb.Bytes(), lim)); got != `x!/z.json={"z":1}` {
		t.Errorf("zip: %s", got)
	}
}

// TestScanReader: the read bound depends on what the leading bytes are. A non-archive blob past plainMax is one
// unit carrying plainLabel (the pre-pin reader's existing size limit); an archive larger than plainMax is still
// read and walked (its bound is the scanner's own); an archive past that bound is one unscanned unit.
func TestScanReader(t *testing.T) {
	lim := store.DefaultLimits()
	us, err := ScanReader("x", strings.NewReader(`{"secret":1,"pad":"xxxxxxxx"}`), lim, 8, "size limit=8")
	if err != nil || unitsOf(us) != "x unscanned(size limit=8)" {
		t.Fatalf("plain over plainMax: %v %s", err, unitsOf(us))
	}
	ar := tarFiles(t, [2]string{"a.json", `{"secret":1}`})
	us, err = ScanReader("x", bytes.NewReader(ar), lim, 8, "size limit=8")
	if err != nil || unitsOf(us) != `x!/a.json={"secret":1}` {
		t.Fatalf("archive over plainMax is still walked: %v %s", err, unitsOf(us))
	}
	small := store.Limits{TotalBytes: 16, Members: 1}
	big := tarFiles(t, [2]string{"a.json", strings.Repeat("x", 20000)})
	us, err = ScanReader("x", bytes.NewReader(big), small, 1<<20, "size limit")
	if want := "x unscanned(total_bytes=" + itoa(store.MaxArchiveFileBytes(small)) + ")"; err != nil || unitsOf(us) != want {
		t.Fatalf("archive past its bound: %v %s, want %s", err, unitsOf(us), want)
	}
	us, err = ScanReader("x", strings.NewReader("tiny"), lim, 8, "size limit=8")
	if err != nil || unitsOf(us) != "x=tiny" {
		t.Fatalf("short blob: %v %s", err, unitsOf(us))
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// TestUnscannedArchiveMember: C-core-95 with the shipped reader. The candidate blob is a real tar whose one
// member holding the forbidden key is xz-compressed. (a) As an edition rule: unchecked naming the member,
// never ok, no "clean", not endorsed. (b) As a pre-pin check: the draft passes with outcome `unchecked`
// recorded; (c) re-applied by a reader (hub), it admits nothing. Control: the same tar with the member stored
// uncompressed fails the rule, so the walk does reach members.
func TestUnscannedArchiveMember(t *testing.T) {
	conformance.Covers(t, "C-core-95")
	w := newWorld(t)
	arch := tarFiles(t, [2]string{"a.json", `{"ok":1}`}, [2]string{"b.json.xz", string(xzSecret)})
	plain := tarFiles(t, [2]string{"a.json", `{"ok":1}`}, [2]string{"b.json", `{"secret":1}`})
	content := scanTable{}
	for _, b := range [][]byte{arch, plain} {
		content[blobDigest(b)] = b
	}
	x := w.authored("X", arch)
	y := w.authored("X", plain)
	g := w.sign("A", "genesis", obj("type", "collection", "name", "c", "controllers", []string{w.signer("A")}, "rule", obj("any_one", true)))
	e1 := w.sign("A", "edition", obj("resource", g, "predecessors", []string{g}, "contents", obj(
		"members", canon.Array{resolve.Entry("statement", x, "member"), resolve.Entry("statement", y, "member")},
		"rules", canon.Array{obj("dialect", "rc-test/1", "expr", "FORBID secret")})))
	opts := []resolve.Option{resolve.WithDialect(forbidDialect{}), resolve.WithContent(content)}
	res := func() *resolve.Resolver {
		s := keylog.NewStore()
		for _, id := range sortedIDs(w.lines) {
			if st, err := wire.Read(w.lines[id]); err == nil {
				_, _ = s.Log(st.Signer).Add(w.lines[id])
			}
		}
		return resolve.New(s, opts...)
	}
	r := res()
	// (a)
	m, ok := r.Membership(g, x)
	if !ok || len(m.Evals) != 1 {
		t.Fatalf("(a) no membership: %v", m)
	}
	e := m.Evals[0]
	if e.Outcome != resolve.RuleUnchecked || m.Endorsed || !strings.Contains(e.Why, "!/b.json.xz unscanned (compression=xz)") {
		t.Fatalf("(a) %s", m.Render())
	}
	if strings.Contains(m.Render(), "clean") {
		t.Fatalf("(a) clean shown: %s", m.Render())
	}
	// control: the member read as stored reaches the rule
	if mc, _ := r.Membership(g, y); mc == nil || mc.Evals[0].Outcome != resolve.RuleFail || mc.Endorsed {
		t.Fatalf("control: %s", mc.Render())
	}
	// (b) pre-pin
	ed := resolve.EditionID(mustBody(t, w.lines[e1]))
	draft := obj("content", canon.Value(contentOf(arch)), "type", "dataset")
	p, err := r.CheckIntendedFor(draft, g, ed)
	if err != nil || p.Outcome != resolve.RuleUnchecked {
		t.Fatalf("(b) %v %+v", err, p)
	}
	iv, _ := p.Body.Get("intended_for")
	if o, _ := iv.(*canon.Object).Get("outcome"); o != canon.String("unchecked") {
		t.Fatalf("(b) outcome %v", o)
	}
	// (c) re-applied by a reader
	pub := w.sign("P", "authored", p.Body)
	rec, ok := res().CheckRecorded(pub)
	if !ok || rec.Named != resolve.RuleUnchecked || rec.Endorsed {
		t.Fatalf("(c) %+v", rec)
	}
}

// scanTable is the shipped reader over blobs held in memory.
type scanTable map[string][]byte

func (c scanTable) Units(d string) ([]resolve.ContentUnit, bool) {
	b, ok := c[d]
	if !ok {
		return nil, false
	}
	return ScanUnits(d, b, store.DefaultLimits()), true
}

func mustBody(t *testing.T, line []byte) *canon.Object {
	st, err := wire.Read(line)
	if err != nil {
		t.Fatal(err)
	}
	return st.Body
}

// TestPairUnits: scanned members pair with the collected bytes in order. If the counts ever disagree, every scanned
// member becomes an unscanned unit naming it (a rule over it is unchecked, never ok) rather than being skipped or
// paired with another member's bytes; unscanned members keep their limit either way.
func TestPairUnits(t *testing.T) {
	ms := []store.MemberResult{
		{Path: "x!/a", Status: store.MemberScanned},
		{Path: "x!/d", Status: store.MemberSkipped},
		{Path: "x!/b", Status: store.MemberUnscanned, Limit: "member_bytes", Value: "8"},
		{Path: "x!/c", Status: store.MemberScanned},
	}
	out, un := pairUnits(ms, [][]byte{[]byte("A"), []byte("C")})
	if got := unitsOf(out); !un || got != "x!/a=A | x!/b unscanned(member_bytes=8) | x!/c=C" {
		t.Fatalf("aligned: %v %s", un, got)
	}
	for _, data := range [][][]byte{{[]byte("A")}, {[]byte("A"), []byte("C"), []byte("E")}, nil} {
		out, un := pairUnits(ms, data)
		want := "x!/a unscanned(" + unpaired + ") | x!/b unscanned(member_bytes=8) | x!/c unscanned(" + unpaired + ")"
		if got := unitsOf(out); !un || got != want {
			t.Fatalf("%d collected for 2 scanned: %v %s", len(data), un, got)
		}
	}
	if out, un := pairUnits(ms[:2], [][]byte{[]byte("A")}); un || unitsOf(out) != "x!/a=A" {
		t.Fatalf("all scanned: %v %s", un, unitsOf(out))
	}
}

// countingContent counts how often a reader is asked about each digest.
type countingContent struct {
	inner resolve.ContentReader
	calls map[string]int
}

func (c *countingContent) Units(d string) ([]resolve.ContentUnit, bool) {
	c.calls[d]++
	return c.inner.Units(d)
}

// TestMemoContent: the memo answers a repeated digest from memory (one inner scan however many rules and members
// ask), returns exactly the units the inner reader returns, keeps nothing for a blob that is not held, and keeps
// nothing past its byte bound (an answer over the bound is returned, and asked again each time, as without a memo).
func TestMemoContent(t *testing.T) {
	arch := tarFiles(t, [2]string{"a.json", `{"ok":1}`}, [2]string{"b.json", `{"secret":1}`})
	d := blobDigest(arch)
	in := &countingContent{inner: scanTable{d: arch}, calls: map[string]int{}}
	m := NewMemoContent(in, 0)
	first, ok := m.Units(d)
	if !ok || len(first) != 2 {
		t.Fatalf("first: %v %d", ok, len(first))
	}
	for i := 0; i < 5; i++ {
		again, ok := m.Units(d)
		if !ok || unitsOf(again) != unitsOf(first) {
			t.Fatalf("repeat %d: %v %s", i, ok, unitsOf(again))
		}
		again[0].Name = "mutated" // a caller's edit of the slice never reaches the memo
	}
	if in.calls[d] != 1 {
		t.Fatalf("inner scanned %d times for one digest", in.calls[d])
	}
	if got, _ := m.Units(d); unitsOf(got) != unitsOf(first) {
		t.Fatalf("memo changed by a caller: %s", unitsOf(got))
	}
	// not held: not kept, so a later answer is the inner reader's
	if us, ok := m.Units("sha256:" + strings.Repeat("0", 64)); ok || us != nil {
		t.Fatalf("a blob not held answered: %v", us)
	}
	// over the bound: returned, never kept
	small := NewMemoContent(in, 10)
	for i := 0; i < 3; i++ {
		if us, ok := small.Units(d); !ok || len(us) != 2 {
			t.Fatalf("over bound: %v %d", ok, len(us))
		}
	}
	// the first memo answered every repeat itself, so only the three bounded calls add to the one scan
	if in.calls[d] != 4 || small.kept != 0 {
		t.Fatalf("bounded memo kept %d bytes, inner calls %d (want 0 kept, 4 calls)", small.kept, in.calls[d])
	}
}

// TestMemoContentOneScanPerRun: an edition with three rules over a member is evaluated with the content reader asked
// once per digest through the memo (three times without it), with identical evaluations either way.
func TestMemoContentOneScanPerRun(t *testing.T) {
	w := newWorld(t)
	arch := tarFiles(t, [2]string{"a.json", `{"ok":1}`}, [2]string{"b.json", `{"secret":1}`})
	d := blobDigest(arch)
	x := w.authored("X", arch)
	g := w.sign("A", "genesis", obj("type", "collection", "name", "c", "controllers", []string{w.signer("A")}, "rule", obj("any_one", true)))
	w.sign("A", "edition", obj("resource", g, "predecessors", []string{g}, "contents", obj(
		"members", canon.Array{resolve.Entry("statement", x, "member")},
		"rules", canon.Array{obj("dialect", "rc-test/1", "expr", "FORBID secret"), obj("dialect", "rc-test/1", "expr", "FORBID pad"), obj("dialect", "rc-test/1", "expr", "FORBID ok")})))
	eval := func(memo bool) (int, string) {
		in := &countingContent{inner: scanTable{d: arch}, calls: map[string]int{}}
		var rc resolve.ContentReader = in
		if memo {
			rc = NewMemoContent(in, 0)
		}
		s := keylog.NewStore()
		for _, id := range sortedIDs(w.lines) {
			if st, err := wire.Read(w.lines[id]); err == nil {
				_, _ = s.Log(st.Signer).Add(w.lines[id])
			}
		}
		m, ok := resolve.New(s, resolve.WithDialect(forbidDialect{}), resolve.WithContent(rc)).Membership(g, x)
		if !ok {
			t.Fatal("no membership")
		}
		return in.calls[d], m.Render()
	}
	plainCalls, plainOut := eval(false)
	memoCalls, memoOut := eval(true)
	if plainCalls != 3 || memoCalls != 1 || plainOut != memoOut {
		t.Fatalf("calls without memo %d (want 3), with %d (want 1); same output: %v", plainCalls, memoCalls, plainOut == memoOut)
	}
}
