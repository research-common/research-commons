package gate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/store"
)

// tarOf packs a directory as `tar -C dir .` does (members "./…", directories included, symlinks as symlinks,
// fifos as fifos), in walk order.
func tarOf(t *testing.T, dir string) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		name := "./" + filepath.ToSlash(rel)
		if rel == "." {
			name = "./"
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		link := ""
		if fi.Mode()&fs.ModeSymlink != 0 {
			link, _ = os.Readlink(p)
		}
		h, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			return err
		}
		h.Name = name
		if d.IsDir() && rel != "." {
			h.Name += "/"
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			data, _ := os.ReadFile(p)
			tw.Write(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	tw.Close()
	return b.Bytes()
}

func gzOf(b []byte) []byte {
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	zw.Write(b)
	zw.Close()
	return out.Bytes()
}

// reportSig is every result of a report reduced to path, verdict, class, reason and labels, in report order.
func reportSig(rep *Report) string {
	var s []string
	for _, r := range rep.Results {
		s = append(s, r.Path+" "+signature(r))
	}
	return strings.Join(s, "\n")
}

// TestArchiveIsTree: a directory and a tar of it (plain and gzip-compressed) are one package: the same objects
// and the same report, verdict for verdict, for a tree that carries good data and every hostile entry a
// directory can hold: a symlink out, a fifo, a `.git` directory with a hook, a nested `.git`, a path outside the
// layout, a blob over the size limit, a non-canonical statement, a hash mismatch.
func TestArchiveIsTree(t *testing.T) {
	w := newWorld(t)
	good := []byte("good bytes")
	id := w.authored("K1", good)
	big := bytes.Repeat([]byte("B"), 2048)
	dir := t.TempDir()
	put := func(p string, b []byte) {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755)
		if err := os.WriteFile(filepath.Join(dir, p), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("rc-store", []byte(LayoutMarker+"\n"))
	put(BlobPath(blobDigest(good)), good)
	put(w.path(id), w.lines[id])
	put(BlobPath(blobDigest(big)), big)
	put(BlobPath(blobDigest([]byte("x"))), []byte("not x"))
	put("statements/"+strings.Split(w.path(id), "/")[1]+"/"+strings.Repeat("0", 64), append(w.lines[id], ' '))
	put("README.md", []byte("outside"))
	put(".git/hooks/post-checkout", []byte("#!/bin/sh\n"))
	put("blobs/.git/config", []byte("x"))
	os.Symlink("/etc/passwd", filepath.Join(dir, "blobs", "ln"))
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Skip("no fifo here:", err)
	}
	pol := DefaultPolicy()
	pol.Limits[LimitBlobBytes] = 1024

	tree, err := ReadTree(dir, pol.Limits[LimitBlobBytes])
	if err != nil {
		t.Fatal(err)
	}
	want := mustAdmit(t, "pull", tree, MemHeld{}, pol, Options{})
	wantRefused(t, want, BlobPath(blobDigest(big)), refusal.Operational, refusal.SizeLimit)
	wantRefused(t, want, ".git", refusal.Intrinsic, UnsafePath)
	wantRefused(t, want, "fifo", refusal.Intrinsic, UnsafePath)
	wantRefused(t, want, "blobs/ln", refusal.Intrinsic, UnsafePath)
	wantRefused(t, want, "blobs/.git/config", refusal.Intrinsic, OutsideSurface)
	wantAdmitted(t, want, w.path(id))

	a := tarOf(t, dir)
	for name, data := range map[string][]byte{"tar": a, "tar.gz": gzOf(a)} {
		pkg, ar, err := ReadArchive(data, pol.Limits[LimitBlobBytes], store.Limits{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ar.Format != map[string]string{"tar": store.FormatTar, "tar.gz": store.FormatTarGzip}[name] {
			t.Fatalf("%s: format %s", name, ar.Format)
		}
		got := mustAdmit(t, "pull", pkg, MemHeld{}, pol, Options{})
		if g, w := reportSig(got), reportSig(want); g != w {
			t.Fatalf("%s: the archive's report differs from the tree's\n got:\n%s\nwant:\n%s", name, g, w)
		}
		lt, la := got.Admitted()
		wl, wb := want.Admitted()
		if len(lt) != len(wl) || len(la) != len(wb) {
			t.Fatalf("%s: admitted sets differ", name)
		}
	}
}

// TestArchiveHostileMembers: what only an archive can carry is refused as the gate refuses an unsafe path in a
// tree, and nothing is ever written at a member's name (ReadArchive writes nothing at all; the canary next to
// the package is unchanged): `..` and absolute names (zip-slip), a hard link, a character device, a long name,
// and a symlink whose target is the canary. The good data beside them is still admitted.
func TestArchiveHostileMembers(t *testing.T) {
	w := newWorld(t)
	good := []byte("good bytes")
	id := w.authored("K1", good)
	root := t.TempDir()
	canary := filepath.Join(root, "canary")
	os.WriteFile(canary, []byte("unchanged"), 0o644)

	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	add := func(h *tar.Header, data []byte) {
		h.Mode, h.Size = 0o644, int64(len(data))
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write(data)
	}
	add(&tar.Header{Name: "rc-store", Typeflag: tar.TypeReg}, []byte(LayoutMarker))
	add(&tar.Header{Name: BlobPath(blobDigest(good)), Typeflag: tar.TypeReg}, good)
	add(&tar.Header{Name: w.path(id), Typeflag: tar.TypeReg}, w.lines[id])
	add(&tar.Header{Name: "../canary", Typeflag: tar.TypeReg}, []byte("overwritten"))
	add(&tar.Header{Name: canary, Typeflag: tar.TypeReg}, []byte("overwritten"))
	add(&tar.Header{Name: "blobs/sha256/../../canary", Typeflag: tar.TypeReg}, []byte("overwritten"))
	add(&tar.Header{Name: "blobs/ln", Typeflag: tar.TypeSymlink, Linkname: canary}, nil)
	add(&tar.Header{Name: "blobs/hard", Typeflag: tar.TypeLink, Linkname: "rc-store"}, nil)
	add(&tar.Header{Name: "dev", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3}, nil)
	add(&tar.Header{Name: `blobs\sha256\x`, Typeflag: tar.TypeReg}, []byte("x"))
	add(&tar.Header{Name: strings.Repeat("d/", 600) + "x", Typeflag: tar.TypeReg}, []byte("x"))
	tw.Close()

	pkg, _, err := ReadArchive(b.Bytes(), 1<<20, store.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	rep := mustAdmit(t, "pull", pkg, MemHeld{}, nil, Options{})
	for _, p := range []string{"../canary", canary, "blobs/sha256/../../canary", "blobs/ln", "blobs/hard", "dev", `blobs\sha256\x`} {
		wantRefused(t, rep, p, refusal.Intrinsic, UnsafePath)
	}
	wantRefused(t, rep, "<name of 1201 bytes>", refusal.Intrinsic, OutsideSurface)
	wantAdmitted(t, rep, w.path(id))
	wantAdmitted(t, rep, BlobPath(blobDigest(good)))
	if got, _ := os.ReadFile(canary); string(got) != "unchanged" {
		t.Fatal("the canary changed")
	}
	if rep.Exit() != 1 {
		t.Fatalf("exit %d", rep.Exit())
	}
}
