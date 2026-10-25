package store

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
)

type tarMember struct {
	name string
	data []byte
	dir  bool
}

func mkTar(t *testing.T, ms ...tarMember) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, m := range ms {
		h := &tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if m.dir {
			h.Typeflag, h.Size = tar.TypeDir, 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(m.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	_, _ = w.Write(b)
	_ = w.Close()
	return out.Bytes()
}

func mkZip(t *testing.T, ms ...tarMember) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, m := range ms {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: m.name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(m.data)
	}
	_ = zw.Close()
	return b.Bytes()
}

func find(r *ScanResult, sub string) *MemberResult {
	for i, m := range r.Members {
		if strings.Contains(m.Path, sub) {
			return &r.Members[i]
		}
	}
	return nil
}

// TestScanUnscannedMembers: C-core-130. One member is unscannable (over the limit, unsupported compression,
// truncated): the output names it `unscanned` with the limit value, and `clean`/`ok` is never printed for
// the archive; the members that were scanned are still reported.
func TestScanUnscannedMembers(t *testing.T) {
	conformance.Covers(t, "C-core-130")
	insp := KeyScan{}
	okMember := tarMember{"data/ok.csv", []byte("a,b\n1,2\n"), false}
	secret := tarMember{"data/leaky.json", []byte(`{"api_key": "x"}`), false}

	t.Run("over the member limit", func(t *testing.T) {
		a := mkTar(t, okMember, tarMember{"data/big.bin", bytes.Repeat([]byte("z"), 5000), false})
		sc := Scanner{Limits: Limits{MemberBytes: 4096}, Inspector: insp}
		r, err := sc.Scan("a.tar", a)
		if err != nil {
			t.Fatal(err)
		}
		m := find(r, "big.bin")
		if m == nil || m.Status != MemberUnscanned || m.Limit != LimitMemberBytes || m.Value != "4096" || m.Label() != "unscanned (member_bytes=4096)" {
			t.Fatalf("%+v", m)
		}
		if ok := find(r, "ok.csv"); ok == nil || ok.Status != MemberScanned {
			t.Fatal("the scannable member was not scanned")
		}
		assertIncomplete(t, r)
	})
	t.Run("unsupported compression", func(t *testing.T) {
		xz := append([]byte{0xfd, '7', 'z', 'X', 'Z', 0}, bytes.Repeat([]byte{1}, 40)...)
		a := mkTar(t, okMember, tarMember{"data/packed.xz", xz, false})
		r, _ := (&Scanner{Inspector: insp}).Scan("a.tar", a)
		m := find(r, "packed.xz")
		if m == nil || m.Limit != LimitCompression || m.Value != "xz" || m.Label() != "unscanned (compression=xz)" {
			t.Fatalf("%+v", m)
		}
		assertIncomplete(t, r)
		// zip with an unsupported method (bzip2 = 12)
		var zb bytes.Buffer
		zw := zip.NewWriter(&zb)
		w, _ := zw.CreateRaw(&zip.FileHeader{Name: "x.bz", Method: 12, CompressedSize64: 4, UncompressedSize64: 9})
		_, _ = w.Write([]byte("BZh9"))
		_ = zw.Close()
		r2, _ := (&Scanner{Inspector: insp}).Scan("a.zip", zb.Bytes())
		if m := find(r2, "x.bz"); m == nil || m.Limit != LimitCompression || !strings.Contains(m.Value, "method 12") {
			t.Fatalf("%+v", m)
		}
		assertIncomplete(t, r2)
	})
	t.Run("truncated", func(t *testing.T) {
		a := mkTar(t, okMember, tarMember{"data/cut.bin", bytes.Repeat([]byte("q"), 3000), false})
		cut := a[:len(a)-2300] // inside the second member's data
		r, err := (&Scanner{Inspector: insp}).Scan("a.tar", cut)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, m := range r.Unscanned() {
			found = found || (m.Limit == LimitTruncated && strings.Contains(m.Path, "cut.bin"))
		}
		if !found {
			t.Fatalf("a truncated member was not named: %s", r.Render())
		}
		assertIncomplete(t, r)
		// truncated gzip and truncated zip
		g := gz(t, a)
		rg, _ := (&Scanner{Inspector: insp}).Scan("a.tar.gz", g[:len(g)/2])
		if len(rg.Unscanned()) == 0 || rg.Unscanned()[0].Limit != LimitTruncated {
			t.Fatalf("%s", rg.Render())
		}
		assertIncomplete(t, rg)
		z := mkZip(t, okMember)
		rz, _ := (&Scanner{Inspector: insp}).Scan("a.zip", z[:len(z)-10])
		if len(rz.Unscanned()) == 0 {
			t.Fatalf("%s", rz.Render())
		}
		assertIncomplete(t, rz)
	})
	t.Run("a complete scan is clean, and findings are not clean", func(t *testing.T) {
		r, err := (&Scanner{Inspector: insp}).Scan("a.tar", mkTar(t, okMember, tarMember{"dir/", nil, true}))
		if err != nil || !r.Complete || r.Verdict() != "clean" || !strings.Contains(r.Render(), "clean: 1 member(s) scanned, none unscanned") || r.RequireClean() != nil {
			t.Fatal(r.Render(), err)
		}
		r, _ = (&Scanner{Inspector: insp}).Scan("a.tar", mkTar(t, okMember, secret))
		if r.Verdict() != "findings" || strings.Contains(r.Render(), "clean") || len(r.Findings) != 1 || r.Findings[0].Rule != "forbidden-key:api_key" {
			t.Fatal(r.Render())
		}
		if strings.Contains(r.Render(), `"x"`) {
			t.Fatal("a finding repeated the secret")
		}
	})
	t.Run("zip members read through deflate", func(t *testing.T) {
		r, err := (&Scanner{Inspector: insp}).Scan("a.zip", mkZip(t, okMember, secret))
		if err != nil || len(r.Findings) != 1 || len(r.Members) != 2 {
			t.Fatal(r.Render(), err)
		}
	})
	t.Run("gzip single file and gzip of tar", func(t *testing.T) {
		r, err := (&Scanner{Inspector: insp}).Scan("a.tar.gz", gz(t, mkTar(t, okMember)))
		if err != nil || !r.Complete || len(r.Members) != 1 {
			t.Fatal(r.Render(), err)
		}
		r, err = (&Scanner{Inspector: insp}).Scan("note.txt.gz", gz(t, []byte("hello")))
		if err != nil || !r.Complete || find(r, "note.txt") == nil {
			t.Fatal(r.Render(), err)
		}
	})
	t.Run("not an archive", func(t *testing.T) {
		r, _ := (&Scanner{Inspector: insp}).Scan("blob", []byte("plain"))
		if r.Complete || r.Verdict() == "clean" || len(r.Unscanned()) != 1 || r.Unscanned()[0].Limit != LimitUnsupported {
			t.Fatal(r.Render())
		}
	})
}

func assertIncomplete(t *testing.T, r *ScanResult) {
	t.Helper()
	out := r.Render()
	if r.Complete || r.Verdict() == "clean" || strings.Contains(out, "clean:") || strings.Contains(out, "ok") && !strings.Contains(out, "this is not a clean result") {
		t.Fatalf("an incomplete scan read as clean:\n%s", out)
	}
	if !strings.Contains(out, "incomplete:") {
		t.Fatalf("not marked incomplete:\n%s", out)
	}
	err := r.RequireClean()
	var ref *refusal.Refusal
	if !errors.As(err, &ref) || ref.Class != refusal.Policy || ref.Reason != "incomplete scan" || !strings.Contains(ref.Detail, "not a statement about the archive") {
		t.Fatalf("the release policy refusal: %v", err)
	}
	for _, m := range r.Unscanned() {
		if !strings.Contains(ref.Detail, m.Label()) {
			t.Fatalf("the refusal does not name %s: %v", m.Path, ref)
		}
	}
}

// TestScanLimitHitMidRun: C-core-131. A nested archive beyond the depth bound, the member-count bound and the
// total-bytes budget each stop or mark the run; the refusal is operational and names the limit, its value
// and the scope it cut; partial results stay incomplete; nothing past the bound reads as checked.
func TestScanLimitHitMidRun(t *testing.T) {
	conformance.Partial(t, "C-core-131", "nested archive depth, member count and byte budget of the archive scanner: checked here; the provenance-graph traversal bound is the resolver's (checked there)")
	insp := KeyScan{}
	leaf := tarMember{"leaf.txt", []byte("fine"), false}

	t.Run("depth, strict", func(t *testing.T) {
		inner := mkTar(t, leaf)
		mid := mkTar(t, tarMember{"inner.tar", inner, false})
		outer := mkTar(t, tarMember{"mid.tar", mid, false}, tarMember{"after.txt", []byte("after"), false})
		sc := Scanner{Limits: Limits{Depth: 2, Strict: true}, Inspector: insp}
		r, err := sc.Scan("outer.tar", outer)
		var ref *refusal.Refusal
		if !errors.As(err, &ref) || ref.Class != refusal.Operational || ref.Reason != refusal.SizeLimit ||
			!strings.Contains(ref.Detail, "depth=2") || !strings.Contains(ref.Detail, "scope: ") || !strings.Contains(ref.Detail, "inner.tar") || !strings.Contains(ref.Detail, "incomplete") {
			t.Fatalf("refusal: %v", err)
		}
		if r.Stopped == nil || r.Complete || r.Verdict() == "clean" {
			t.Fatal("a stopped run read as complete")
		}
		if m := find(r, "inner.tar"); m == nil || m.Status != MemberUnscanned || m.Limit != LimitDepth {
			t.Fatalf("%+v", m)
		}
		if find(r, "leaf.txt") != nil {
			t.Fatal("a member past the depth bound reads as checked")
		}
		if find(r, "after.txt") != nil {
			t.Fatal("the run continued past the refusal")
		}
	})
	t.Run("depth, lenient: unscanned and the run goes on", func(t *testing.T) {
		inner := mkTar(t, leaf)
		outer := mkTar(t, tarMember{"inner.tar", inner, false}, tarMember{"after.txt", []byte("after"), false})
		r, err := (&Scanner{Limits: Limits{Depth: 1}, Inspector: insp}).Scan("outer.tar", outer)
		if err != nil {
			t.Fatal(err)
		}
		if m := find(r, "inner.tar"); m == nil || m.Limit != LimitDepth || m.Value != "1" {
			t.Fatalf("%+v", m)
		}
		if m := find(r, "after.txt"); m == nil || m.Status != MemberScanned {
			t.Fatal("scan did not continue")
		}
		assertIncomplete(t, r)
		// Within the bound the nested archive is walked.
		ok, err := (&Scanner{Limits: Limits{Depth: 2}, Inspector: insp}).Scan("outer.tar", outer)
		if err != nil || !ok.Complete || find(ok, "inner.tar!/leaf.txt") == nil {
			t.Fatal(ok.Render(), err)
		}
	})
	t.Run("member count", func(t *testing.T) {
		var ms []tarMember
		for i := 0; i < 6; i++ {
			ms = append(ms, tarMember{fmt.Sprintf("f%d", i), []byte("x"), false})
		}
		r, err := (&Scanner{Limits: Limits{Members: 4}, Inspector: insp}).Scan("many.tar", mkTar(t, ms...))
		var ref *refusal.Refusal
		if !errors.As(err, &ref) || ref.Class != refusal.Operational || !strings.Contains(ref.Detail, "members=4") || !strings.Contains(ref.Detail, "every member after the first 4") {
			t.Fatal(err)
		}
		if find(r, "f3") == nil || find(r, "f4") != nil && find(r, "f4").Status == MemberScanned {
			t.Fatal("members past the bound read as scanned")
		}
		if r.Complete || r.Verdict() != "incomplete" {
			t.Fatal(r.Verdict())
		}
	})
	t.Run("total bytes", func(t *testing.T) {
		r, err := (&Scanner{Limits: Limits{TotalBytes: 100, MemberBytes: 100}, Inspector: insp}).Scan("t.tar",
			mkTar(t, tarMember{"a", bytes.Repeat([]byte("a"), 60), false}, tarMember{"b", bytes.Repeat([]byte("b"), 60), false}, tarMember{"c", []byte("c"), false}))
		var ref *refusal.Refusal
		if !errors.As(err, &ref) || !strings.Contains(ref.Detail, "total_bytes=100") || !strings.Contains(ref.Detail, "scope: ") {
			t.Fatal(err)
		}
		if m := find(r, "!/b"); m == nil || m.Status != MemberUnscanned || m.Limit != LimitTotalBytes {
			t.Fatalf("%+v", m)
		}
		if find(r, "!/c") != nil {
			t.Fatal("scan continued past the budget")
		}
	})
	t.Run("expansion ratio: a bomb stops at a bounded cost", func(t *testing.T) {
		var bomb bytes.Buffer
		fw, _ := flate.NewWriter(&bomb, flate.BestCompression)
		_, _ = fw.Write(bytes.Repeat([]byte{0}, 30<<20))
		_ = fw.Close()
		var zb bytes.Buffer
		zw := zip.NewWriter(&zb)
		w, _ := zw.CreateHeader(&zip.FileHeader{Name: "bomb", Method: zip.Deflate})
		_, _ = w.Write(bytes.Repeat([]byte{0}, 30<<20))
		_ = zw.Close()
		r, err := (&Scanner{Limits: Limits{MemberBytes: 64 << 20, ExpansionRatio: 50}}).Scan("b.zip", zb.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if m := find(r, "bomb"); m == nil || m.Limit != LimitRatio || m.Value != "50" {
			t.Fatalf("%+v", m)
		}
		assertIncomplete(t, r)
	})
	t.Run("long names", func(t *testing.T) {
		r, _ := (&Scanner{Limits: Limits{PathBytes: 16}}).Scan("n.tar", mkTar(t, tarMember{strings.Repeat("n", 40), []byte("x"), false}))
		if u := r.Unscanned(); len(u) != 1 || u[0].Limit != LimitPathBytes {
			t.Fatal(r.Render())
		}
	})
	t.Run("limits are printed and digested", func(t *testing.T) {
		l := DefaultLimits()
		if !strings.Contains(l.String(), "depth=3") || l.Digest() == (Limits{Depth: 2}).Digest() {
			t.Fatal(l.String())
		}
		if (Limits{}).String() != l.String() {
			t.Fatal("zero fields do not take the defaults")
		}
	})
}

// TestKeyScanConfigurable: the optional secret and forbidden-key hook has configurable patterns; findings
// never repeat the value.
func TestKeyScanConfigurable(t *testing.T) {
	data := []byte(`{"Password": "hunter2hunter2", "note": "AKIAABCDEFGHIJKLMNOP"}` + "\n-----BEGIN OPENSSH PRIVATE KEY-----\n")
	fs, _ := KeyScan{}.Inspect("m", data)
	rules := map[string]bool{}
	for _, f := range fs {
		rules[f.Rule] = true
		if strings.Contains(f.Detail, "hunter2") {
			t.Fatal("secret echoed")
		}
	}
	for _, want := range []string{"forbidden-key:password", "secret-pattern:aws-access-key-id", "secret-pattern:private-key-block"} {
		if !rules[want] {
			t.Errorf("default scan missed %s: %v", want, rules)
		}
	}
	none, _ := KeyScan{Patterns: []SecretPattern{}, ForbiddenKeys: []string{}}.Inspect("m", data)
	if len(none) != 0 {
		t.Fatalf("configured-empty scan found %v", none)
	}
	custom, _ := KeyScan{Patterns: []SecretPattern{{"x", mustRE(`hunter\d`)}}, ForbiddenKeys: []string{"note"}}.Inspect("m", data)
	if len(custom) != 2 {
		t.Fatalf("%v", custom)
	}
	if f, _ := (KeyScan{}).Inspect("m", []byte(`{"passwords": 1, "x": "password"}`)); len(f) != 0 {
		t.Fatalf("a value or a longer name matched a forbidden key: %v", f)
	}
}

func mustRE(s string) *regexp.Regexp { return regexp.MustCompile(s) }
