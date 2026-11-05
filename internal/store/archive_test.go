package store

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/refusal"
)

type tm struct {
	name string
	typ  byte
	data []byte
	link string
}

func mkIngestTar(t *testing.T, ms ...tm) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, m := range ms {
		h := &tar.Header{Name: m.name, Typeflag: m.typ, Mode: 0o644, Size: int64(len(m.data)), Linkname: m.link, Format: tar.FormatPAX}
		if m.typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if m.typ == tar.TypeReg {
			tw.Write(m.data)
		}
	}
	tw.Close()
	return b.Bytes()
}

func wantRefusal(t *testing.T, err error, class refusal.Class, reason string) *refusal.Refusal {
	t.Helper()
	var r *refusal.Refusal
	if !errors.As(err, &r) || r.Class != class || r.Reason != reason {
		t.Fatalf("want %s/%s, got %v", class, reason, err)
	}
	return r
}

// TestReadArchiveMembers: names, types and bytes as the archive carries them; nothing cleaned but one leading
// "./"; directories and the global header are not members; a symlink, a hard link and a device are members
// without bytes; a nested archive is bytes, not descended.
func TestReadArchiveMembers(t *testing.T) {
	inner := mkIngestTar(t, tm{name: "x", typ: tar.TypeReg, data: []byte("x")})
	a := mkIngestTar(t,
		tm{name: "./", typ: tar.TypeDir},
		tm{name: "./rc-store", typ: tar.TypeReg, data: []byte("m")},
		tm{name: "blobs/", typ: tar.TypeDir},
		tm{name: "blobs/a", typ: tar.TypeReg, data: []byte("bytes\x00\xff")},
		tm{name: "../up", typ: tar.TypeReg, data: []byte("u")},
		tm{name: "/abs", typ: tar.TypeReg, data: []byte("a")},
		tm{name: "ln", typ: tar.TypeSymlink, link: "/etc/passwd"},
		tm{name: "hard", typ: tar.TypeLink, link: "blobs/a"},
		tm{name: "dev", typ: tar.TypeChar},
		tm{name: "fifo", typ: tar.TypeFifo},
		tm{name: "nested.tar", typ: tar.TypeReg, data: inner},
	)
	for _, data := range [][]byte{a, gz(t, a)} {
		ar, err := ReadArchive(data, Limits{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]ArchiveMember{}
		var names []string
		for _, m := range ar.Members {
			got[m.Name] = m
			names = append(names, m.Name)
		}
		want := "rc-store blobs/a ../up /abs ln hard dev fifo nested.tar"
		if strings.Join(names, " ") != want {
			t.Fatalf("%s members %q, want %q", ar.Format, names, want)
		}
		if string(got["blobs/a"].Data) != "bytes\x00\xff" || got["blobs/a"].Type != TypeFile {
			t.Fatalf("binary member: %+v", got["blobs/a"])
		}
		if got["ln"].Type != TypeSymlink || got["ln"].Data != nil {
			t.Fatalf("symlink: %+v", got["ln"])
		}
		for _, n := range []string{"hard", "dev", "fifo"} {
			if got[n].Type != TypeOther || got[n].Data != nil {
				t.Fatalf("%s: %+v", n, got[n])
			}
		}
		if !bytes.Equal(got["nested.tar"].Data, inner) {
			t.Fatal("a nested archive is not its bytes")
		}
		if !ar.Scan.Complete {
			t.Fatalf("scan not complete: %+v", ar.Scan.Unscanned())
		}
	}
	if f := IngestFormat(a); f != FormatTar {
		t.Fatal(f)
	}
	if f := IngestFormat(gz(t, a)); f != FormatTarGzip {
		t.Fatal(f)
	}
	if f := IngestFormat(gz(t, []byte("not a tar"))); f != "gzip" {
		t.Fatal(f)
	}
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	zw.Create("rc-store")
	zw.Close()
	if f := IngestFormat(zb.Bytes()); f != "zip" {
		t.Fatal(f)
	}
	if f := IngestFormat([]byte{0xfd, '7', 'z', 'X', 'Z', 0, 1}); f != "xz" {
		t.Fatal(f)
	}
}

// TestReadArchiveBounds: the per-member bound reads to the bound plus one (the judge refuses it, as for a tree
// file); a name over path_bytes is a placeholder with no bytes; the members and total_bytes limits and the gzip
// expansion ratio stop the run with an operational refusal naming the limit, and the partial scan is incomplete.
func TestReadArchiveBounds(t *testing.T) {
	big := bytes.Repeat([]byte("z"), 5000)
	ar, err := ReadArchive(mkIngestTar(t, tm{name: "big", typ: tar.TypeReg, data: big}, tm{name: "ok", typ: tar.TypeReg, data: []byte("k")}), Limits{MemberBytes: 100}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ar.Members[0].Data) != 101 || string(ar.Members[1].Data) != "k" {
		t.Fatalf("bounded read: %d bytes", len(ar.Members[0].Data))
	}
	if ar.Scan.Complete || ar.Scan.Unscanned()[0].Label() != "unscanned (member_bytes=100)" {
		t.Fatalf("%+v", ar.Scan.Unscanned())
	}

	long := strings.Repeat("n", 40)
	ar, err = ReadArchive(mkIngestTar(t, tm{name: long, typ: tar.TypeReg, data: []byte("secret")}), Limits{PathBytes: 32}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m := ar.Members[0]; m.Name != "<name of 40 bytes>" || m.Data != nil {
		t.Fatalf("%+v", m)
	}

	var many []tm
	for i := 0; i < 5; i++ {
		many = append(many, tm{name: "m" + string(rune('a'+i)), typ: tar.TypeReg, data: []byte("x")})
	}
	ar, err = ReadArchive(mkIngestTar(t, many...), Limits{Members: 3}, nil)
	r := wantRefusal(t, err, refusal.Operational, refusal.SizeLimit)
	if !strings.Contains(r.Detail, "members=3") || len(ar.Members) != 3 || ar.Scan.Complete || ar.Scan.Stopped == nil {
		t.Fatalf("%v; %d members", r, len(ar.Members))
	}

	_, err = ReadArchive(mkIngestTar(t, tm{name: "a", typ: tar.TypeReg, data: big}, tm{name: "b", typ: tar.TypeReg, data: big}), Limits{TotalBytes: 8000}, nil)
	if r := wantRefusal(t, err, refusal.Operational, refusal.SizeLimit); !strings.Contains(r.Detail, "total_bytes=8000") || !strings.Contains(r.Detail, `"b"`) {
		t.Fatal(r)
	}

	// a gzip bomb: 8 MiB of zeros in one member compresses ~1000:1; the default ratio (200) stops it while reading
	bomb := gz(t, mkIngestTar(t, tm{name: "z", typ: tar.TypeReg, data: make([]byte, 8<<20)}))
	_, err = ReadArchive(bomb, Limits{}, nil)
	if r := wantRefusal(t, err, refusal.Operational, refusal.SizeLimit); !strings.Contains(r.Detail, "expansion_ratio=200") {
		t.Fatal(r)
	}
}

// TestReadArchiveAmbiguous: an archive two readers could read as two packages is refused whole (intrinsic):
// one name twice, bytes after the tar's end, a second gzip member. Zero padding after the end is not ambiguous
// (tar writers pad to a record). A truncated archive is operational, with nothing returned as judged.
func TestReadArchiveAmbiguous(t *testing.T) {
	one := tm{name: "rc-store", typ: tar.TypeReg, data: []byte("m")}
	dup := mkIngestTar(t, one, tm{name: "a", typ: tar.TypeReg, data: []byte("1")}, tm{name: "./a", typ: tar.TypeReg, data: []byte("2")})
	_, err := ReadArchive(dup, Limits{}, nil)
	if r := wantRefusal(t, err, refusal.Intrinsic, ReasonMalformedArchive); !strings.Contains(r.Detail, `two members named "a"`) {
		t.Fatal(r)
	}

	plain := mkIngestTar(t, one)
	if _, err := ReadArchive(append(append([]byte{}, plain...), make([]byte, 10240)...), Limits{}, nil); err != nil {
		t.Fatalf("zero padding: %v", err)
	}
	_, err = ReadArchive(append(append([]byte{}, plain...), mkIngestTar(t, tm{name: "smuggled", typ: tar.TypeReg, data: []byte("s")})...), Limits{}, nil)
	wantRefusal(t, err, refusal.Intrinsic, ReasonMalformedArchive)

	twoMembers := append(gz(t, plain), gz(t, mkIngestTar(t, tm{name: "more", typ: tar.TypeReg, data: []byte("s")}))...)
	_, err = ReadArchive(twoMembers, Limits{}, nil)
	wantRefusal(t, err, refusal.Intrinsic, ReasonMalformedArchive)

	full := mkIngestTar(t, one, tm{name: "b", typ: tar.TypeReg, data: bytes.Repeat([]byte("b"), 3000)})
	ar, err := ReadArchive(full[:1500], Limits{}, nil)
	wantRefusal(t, err, refusal.Operational, ReasonTruncatedArchive)
	if ar.Scan.Complete {
		t.Fatal("a truncated archive's scan is complete")
	}
	g := gz(t, full)
	_, err = ReadArchive(g[:len(g)/2], Limits{}, nil)
	wantRefusal(t, err, refusal.Operational, ReasonTruncatedArchive)
}

// TestReadArchiveSkip: a skipped member is listed with no bytes read; a skipped directory is listed even when
// empty.
func TestReadArchiveSkip(t *testing.T) {
	a := mkIngestTar(t, tm{name: ".git/", typ: tar.TypeDir}, tm{name: ".git/config", typ: tar.TypeReg, data: []byte("c")}, tm{name: "rc-store", typ: tar.TypeReg, data: []byte("m")})
	ar, err := ReadArchive(a, Limits{}, func(n string) bool { return strings.HasPrefix(n, ".git/") })
	if err != nil {
		t.Fatal(err)
	}
	if len(ar.Members) != 3 || !ar.Members[0].Skipped || !ar.Members[1].Skipped || ar.Members[1].Data != nil || ar.Members[2].Skipped {
		t.Fatalf("%+v", ar.Members)
	}
}
