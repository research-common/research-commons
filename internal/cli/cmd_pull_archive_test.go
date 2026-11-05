package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binBlob = []byte("\x00\xff\r\n\x1f\x8b binary \x00")

// archiveWorld is a source store with one authored blob and a fresh reader, and the package's data objects.
func archiveWorld(t *testing.T) (src, dst *world, objs [][2]string) {
	src = newWorld(t)
	src.blob("a", []byte("a"))
	src.authored("A:a", "K1", "a", "licence", "CC0-1.0")
	src.blob("bin", binBlob) // unreferenced: the gate admits it labelled; its bytes must arrive intact (#64)
	blobs, stmts := dataObjects(t, src.root)
	objs = [][2]string{{"rc-store", ""}}
	for _, o := range append(blobs, stmts...) {
		objs = append(objs, [2]string{o, ""})
	}
	return src, newWorld(t), objs
}

func writeFile(t *testing.T, b []byte, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPullArchive: pull reads a tar archive (plain or gzip, recognised from its bytes, whatever its name) as it
// reads the same tree; the binary blob arrives intact; a dry run commits nothing; the report names the format.
func TestPullArchive(t *testing.T) {
	src, dst, objs := archiveWorld(t)
	a := tarPackage(t, src.root, objs, false)
	misnamed := writeFile(t, mustRead(t, tarPackage(t, src.root, objs, true)), "package.zip")

	before := snapshot(t, dst.root)
	if r := dst.run("pull", a, "--dry-run", "--json"); r.code != 0 || !strings.Contains(r.stdout, `"package_format":"tar"`) {
		t.Fatalf("dry run: exit %d\n%s", r.code, r.stdout)
	}
	if snapshot(t, dst.root) != before {
		t.Fatal("a dry run changed the store")
	}
	r := dst.run("pull", misnamed, "--json")
	if r.code != 0 || !strings.Contains(r.stdout, `"package_format":"tar+gzip"`) || !strings.Contains(r.stdout, `"refused":0`) || !strings.Contains(r.stdout, "committed one operation") {
		t.Fatalf("tar.gz named .zip: exit %d\n%s", r.code, r.stdout)
	}
	if got := mustRead(t, filepath.Join(dst.root, "blobs", "sha256", strings.TrimPrefix(dig(string(binBlob)), "sha256:"))); !bytes.Equal(got, binBlob) {
		t.Fatalf("binary blob changed in transit: %q", got)
	}
	if r := dst.run("pull", a); r.code != 0 || !strings.Contains(r.stdout, "nothing new") {
		t.Fatalf("re-pull: exit %d\n%s", r.code, r.stdout)
	}
}

// TestPullArchiveRefusals: the exits of an archive package. Not a tar (zip, a gzip of something else, xz,
// garbage): exit 2 before any work. Ambiguous (one name twice, bytes after the end): exit 1, refused whole.
// Not read to its end (truncated): exit 3, nothing judged. A hostile member beside good data: exit 1 for that
// member, the good data committed, exactly as for the same entry in a tree. Nothing is written in the first
// three cases.
func TestPullArchiveRefusals(t *testing.T) {
	src, dst, objs := archiveWorld(t)
	good := mustRead(t, tarPackage(t, src.root, objs, false))

	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	f, _ := zw.Create("rc-store")
	f.Write(mustRead(t, filepath.Join(src.root, "rc-store")))
	zw.Close()
	var gzOther bytes.Buffer
	gw := gzip.NewWriter(&gzOther)
	gw.Write([]byte("rc-store\n"))
	gw.Close()

	before := snapshot(t, dst.root)
	for name, b := range map[string][]byte{"pkg.zip": zb.Bytes(), "pkg.gz": gzOther.Bytes(), "pkg.tar.xz": {0xfd, '7', 'z', 'X', 'Z', 0, 0, 0}, "pkg.tar": []byte("not an archive")} {
		r := dst.run("pull", writeFile(t, b, name), "--json")
		if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "not an archive this tool reads") || !strings.Contains(r.stdout, `"committed":false`) {
			t.Fatalf("%s: exit %d\n%s", name, r.code, r.stdout)
		}
	}

	dup := mustRead(t, tarPackage(t, src.root, append(objs, objs[1]), false))
	smuggled := append(append([]byte{}, good...), mustRead(t, tarPackage(t, src.root, objs[:1], false))...)
	for name, b := range map[string][]byte{"duplicate name": dup, "bytes after the end": smuggled} {
		r := dst.run("pull", writeFile(t, b, "pkg.tar"), "--json")
		if r.code != ExitWrong || !strings.Contains(r.stdout, "malformed archive") || !strings.Contains(r.stdout, `"class":"intrinsic"`) {
			t.Fatalf("%s: exit %d\n%s", name, r.code, r.stdout)
		}
	}
	r := dst.run("pull", writeFile(t, good[:len(good)-1500], "pkg.tar"), "--json")
	if r.code != ExitCouldNot || !strings.Contains(r.stdout, "truncated archive") || !strings.Contains(r.stdout, `"class":"operational"`) {
		t.Fatalf("truncated: exit %d\n%s", r.code, r.stdout)
	}
	if snapshot(t, dst.root) != before {
		t.Fatal("a refused archive changed the store")
	}

	// a symlink, a hard link and a `..` member beside the good data: those refused, the data committed
	var b bytes.Buffer
	b.Write(good[:len(good)-1024]) // drop the closing record, append more members
	tw := tar.NewWriter(&b)
	tw.WriteHeader(&tar.Header{Name: "blobs/ln", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	tw.WriteHeader(&tar.Header{Name: "blobs/hard", Typeflag: tar.TypeLink, Linkname: "rc-store"})
	tw.WriteHeader(&tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644})
	tw.Write([]byte("x"))
	tw.Close()
	r = dst.run("pull", writeFile(t, b.Bytes(), "pkg.tar"), "--json")
	if r.code != ExitWrong || strings.Count(r.stdout, "unsafe path") != 3 || !strings.Contains(r.stdout, `"refused":3`) || !strings.Contains(r.stdout, "committed one operation") {
		t.Fatalf("hostile members: exit %d\n%s", r.code, r.stdout)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dst.root), "escape")); err == nil {
		t.Fatal("a member was written outside the store")
	}
}

// TestPullGitArchive: `git archive --format=tar` (and tar.gz) of a hub is a package: its global header (the
// commit id) is not a member, and no .git is in it. With --prefix every member is under one directory, so the
// archive is not a store tree (no rc-store at its root): refused whole, the way a directory holding a hub
// checkout one level down is. A tar of a checkout that carries .git is refused without --from-checkout and
// skipped once with it.
func TestPullGitArchive(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	src, _, objs := archiveWorld(t)
	hub := t.TempDir()
	var paths []string
	for _, o := range objs {
		paths = append(paths, o[0])
	}
	writePackage(t, src.root, hub, paths[1:])
	gitIn(t, hub, "init", "-q", "-b", "main")
	gitIn(t, hub, "add", "-A")
	gitIn(t, hub, "commit", "-q", "-m", "c")
	for _, args := range [][]string{{"--format=tar"}, {"--format=tar.gz"}} {
		out := filepath.Join(t.TempDir(), "hub.archive")
		gitIn(t, hub, append(append([]string{"archive"}, args...), "-o", out, "HEAD")...)
		dst := newWorld(t)
		if r := dst.run("pull", out, "--json"); r.code != 0 || !strings.Contains(r.stdout, `"refused":0`) {
			t.Fatalf("git archive %v: exit %d\n%s", args, r.code, r.stdout)
		}
	}
	out := filepath.Join(t.TempDir(), "hub.tar")
	gitIn(t, hub, "archive", "--format=tar", "--prefix=hub-main/", "-o", out, "HEAD")
	if r := newWorld(t).run("pull", out, "--json"); r.code != ExitWrong || !strings.Contains(r.stdout, "not a store tree") {
		t.Fatalf("prefixed git archive: exit %d\n%s", r.code, r.stdout)
	}

	// a tar of the checkout itself, .git included
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	filepath.WalkDir(hub, func(p string, d os.DirEntry, err error) error {
		rel, _ := filepath.Rel(hub, p)
		if rel == "." || d.IsDir() {
			return nil
		}
		data, _ := os.ReadFile(p)
		tw.WriteHeader(&tar.Header{Name: filepath.ToSlash(rel), Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))})
		tw.Write(data)
		return nil
	})
	tw.Close()
	co := writeFile(t, b.Bytes(), "checkout.tar")
	if r := newWorld(t).run("pull", co, "--json"); r.code != ExitWrong || !strings.Contains(r.stdout, `"path":".git"`) {
		t.Fatalf("checkout tar without the flag: exit %d\n%s", r.code, r.stdout)
	}
	r := newWorld(t).run("pull", co, "--from-checkout", "--json")
	if r.code != 0 || strings.Count(r.stdout, ".git (transport metadata, --from-checkout)") != 1 {
		t.Fatalf("checkout tar with the flag: exit %d\n%s", r.code, r.stdout)
	}
}
