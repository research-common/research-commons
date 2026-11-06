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
