package run

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
)

// canary is a file outside every staging root. check fails if its bytes or mtime changed.
type canary struct {
	path  string
	data  []byte
	mtime time.Time
}

func newCanary(t *testing.T) *canary {
	dir := t.TempDir()
	p := filepath.Join(dir, "canary")
	data := []byte("CANARY-" + t.Name())
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	return &canary{path: p, data: data, mtime: old}
}

func (c *canary) check(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile(c.path)
	if err != nil || !bytes.Equal(b, c.data) {
		t.Fatalf("canary changed: %q %v", b, err)
	}
	fi, _ := os.Stat(c.path)
	if !fi.ModTime().Equal(c.mtime) {
		t.Fatalf("canary written: mtime %v", fi.ModTime())
	}
}

func wantPath(t *testing.T, err error, what string) *PathRefusal {
	t.Helper()
	var pr *PathRefusal
	if !errors.As(err, &pr) {
		t.Fatalf("want unsafe path (%s), got %v", what, err)
	}
	if pr.Class != refusal.Intrinsic || pr.Reason != ReasonUnsafePath || pr.What != what {
		t.Fatalf("want intrinsic unsafe path: %s, got %s: %s (%s)", what, pr.Class, pr.Reason, pr.What)
	}
	return pr
}

func tarOf(t *testing.T, members ...*tar.Header) []byte {
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, h := range members {
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(h.Name))
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			w.Write([]byte(h.Name))
		}
	}
	w.Close()
	return b.Bytes()
}

// TestJoinRules: every row of the §3 table, against the real filesystem.
func TestJoinRules(t *testing.T) {
	c := newCanary(t)
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "sub"), 0o755)
	os.Symlink(filepath.Dir(c.path), filepath.Join(root, "out-link"))
	os.Symlink("sub", filepath.Join(root, "in-link")) // a symlink even to inside is refused: every component
	syscall.Mkfifo(filepath.Join(root, "fifo"), 0o644)
	for _, x := range []struct{ name, what string }{
		{"", PathMalformed},
		{"a\x00b", PathMalformed},
		{".", PathMalformed},
		{"/etc/passwd", PathAbsolute},
		{`\\server\share`, PathAbsolute},
		{`C:\x`, PathAbsolute},
		{"~/x", PathAbsolute},
		{"../canary", PathTraversal},
		{`sub\..\..\x`, PathTraversal},
		{"sub/../x", PathTraversal},
		{"out-link/canary", PathSymlink},
		{"in-link/x", PathSymlink},
		{"out-link", PathSymlink},
	} {
		_, err := Join(root, x.name, "workflow W")
		pr := wantPath(t, err, x.what)
		if !strings.Contains(pr.Detail, "in workflow W") {
			t.Fatalf("scope missing: %s", pr.Detail)
		}
	}
	// control characters are printed escaped, the name verbatim
	_, err := Join(root, "../\x1b[31mred", "s")
	if pr := wantPath(t, err, PathTraversal); strings.ContainsRune(pr.Detail, 0x1b) || !strings.Contains(pr.Detail, `\x1b[31mred`) {
		t.Fatalf("detail not escaped: %q", pr.Detail)
	}
	_, err = ReadRegular(root, "fifo", "s", 0)
	wantPath(t, err, PathNotRegular)
	_, err = ReadRegular(root, "sub", "s", 0)
	wantPath(t, err, PathNotRegular)
	if _, err := ReadRegular(root, "missing", "s", 0); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	// a hard link is a regular file and is admitted
	os.WriteFile(filepath.Join(root, "f"), []byte("ok"), 0o644)
	if err := os.Link(filepath.Join(root, "f"), filepath.Join(root, "hard")); err == nil {
		if b, err := ReadRegular(root, "hard", "s", 0); err != nil || string(b) != "ok" {
			t.Fatalf("hard link: %q %v", b, err)
		}
	}
	// Join returns the resolved form (built on the realpath of root), so compare against that, by components: on
	// macOS t.TempDir() is under /var, a symlink to /private/var, and a textual prefix would also admit a sibling
	// such as root+"X".
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Join(root, "sub/new/file", "s")
	if err != nil {
		t.Fatalf("a missing tail inside root: %v", err)
	}
	if r, err := filepath.Rel(realRoot, p); err != nil || r != filepath.Join("sub", "new", "file") {
		t.Fatalf("a missing tail inside root: %q (relative to %q: %q, %v)", p, realRoot, r, err)
	}
	c.check(t)
}

// TestStagingConfined: C-exec-08. Inputs and attachments named with an absolute path and with `..`, and an
// archive attachment carrying a symlink out of staging (the only way a peer-supplied symlink reaches staging);
// each is refused before the sandbox starts (intrinsic: unsafe path, the path named), the canary is unchanged,
// nothing is spawned, and staging is removed.
func TestStagingConfined(t *testing.T) {
	conformance.Covers(t, "C-exec-08")
	c := newCanary(t)
	data := []byte("d")
	cases := []struct {
		name string
		spec map[string]string
		att  []Attachment
		what string
	}{
		{"input absolute", map[string]string{c.path: Digest(data)}, nil, PathAbsolute},
		{"input traversal", map[string]string{"../../" + filepath.Base(c.path): Digest(data)}, nil, PathTraversal},
		{"attachment absolute", nil, []Attachment{{Name: c.path, Data: []byte("x")}}, PathAbsolute},
		{"attachment traversal", nil, []Attachment{{Name: "a/../../canary", Data: []byte("x")}}, PathTraversal},
		{"archive symlink out", nil, []Attachment{{Name: "pkg", Tar: true, Data: tarOf(t,
			&tar.Header{Name: "ok.txt", Typeflag: tar.TypeReg},
			&tar.Header{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: c.path})}}, PathNotRegular},
		{"archive member traversal", nil, []Attachment{{Name: "pkg", Tar: true, Data: tarOf(t,
			&tar.Header{Name: "ok.txt", Typeflag: tar.TypeReg},
			&tar.Header{Name: "../../canary", Typeflag: tar.TypeReg})}}, PathTraversal},
		{"archive hard link", nil, []Attachment{{Name: "pkg", Tar: true, Data: tarOf(t,
			&tar.Header{Name: "h", Typeflag: tar.TypeLink, Linkname: c.path})}}, PathNotRegular},
	}
	for _, x := range cases {
		t.Run(x.name, func(t *testing.T) {
			s := mustSpec(t, specB("s", x.spec))
			f := newFake().step("s", writeStep("out"))
			staging := t.TempDir()
			_, err := Execute(context.Background(), grantAll(), f, Invocation{Request: Request{Spec: s, Signer: ownerKey},
				Blobs: blobsFor(s, "s", map[string][]byte{"d": data}), Attachments: x.att, StagingRoot: staging})
			pr := wantPath(t, err, x.what)
			if !strings.Contains(pr.Detail, "workflow "+s.Digest) {
				t.Fatalf("scope: %s", pr.Detail)
			}
			if f.Spawned != 0 {
				t.Fatal("the step was started")
			}
			if left, _ := os.ReadDir(staging); len(left) != 0 {
				t.Fatalf("staging left behind: %v", left)
			}
			// nothing of an archive is extracted when one member fails: proved by the canary and the empty root
			c.check(t)
		})
	}
	// control: the same archive without the bad member stages, and the step sees it
	s := mustSpec(t, specB("s", nil))
	f := newFake().step("s", catStep("pkg/ok.txt"))
	res, err := Execute(context.Background(), grantAll(), f, Invocation{Request: Request{Spec: s, Signer: ownerKey},
		Blobs: blobsFor(s, "s", nil), Attachments: []Attachment{{Name: "pkg", Tar: true, Data: tarOf(t, &tar.Header{Name: "ok.txt", Typeflag: tar.TypeReg})}}})
	if err != nil || !res.Completed() || string(res.Outputs[0].Bytes) != "ok.txt" {
		t.Fatalf("control: %v %+v", err, res)
	}
}

// TestOutputsConfined: C-exec-09. A declared output name that is absolute, traverses with `..`, or is a symlink
// the step created pointing out of staging: read-back refuses the name without following it, the canary is
// unchanged and never read, and the run result is `incomplete output`, never a pass; nothing is published.
func TestOutputsConfined(t *testing.T) {
	conformance.Covers(t, "C-exec-09")
	c := newCanary(t)
	for _, x := range []struct {
		name, file, what string
		step             Step
	}{
		{"absolute", c.path, PathAbsolute, writeStep("x")},
		{"traversal", "../../" + filepath.Base(c.path), PathTraversal, writeStep("x")},
		{"symlink out", "result.txt", PathSymlink, func(_ context.Context, _, out string, _ map[string]string) (int, Resources) {
			os.Symlink(c.path, filepath.Join(out, "result.txt"))
			return 0, Resources{CapMemory: 1}
		}},
		{"symlinked directory", "d/result.txt", PathSymlink, func(_ context.Context, _, out string, _ map[string]string) (int, Resources) {
			os.Symlink(filepath.Dir(c.path), filepath.Join(out, "d"))
			return 0, Resources{CapMemory: 1}
		}},
		{"fifo", "result.txt", PathNotRegular, func(_ context.Context, _, out string, _ map[string]string) (int, Resources) {
			syscall.Mkfifo(filepath.Join(out, "result.txt"), 0o644)
			return 0, Resources{CapMemory: 1}
		}},
	} {
		t.Run(x.name, func(t *testing.T) {
			s := mustSpec(t, specB("s", nil, "outputs", object("result", canon.String(x.file))))
			f := newFake().step("s", x.step)
			res, err := Execute(context.Background(), grantAll(), f, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobsFor(s, "s", nil)})
			if err != nil {
				t.Fatal(err)
			}
			if f.Spawned != 1 {
				t.Fatal("the step must run: the boundary under test is read-back")
			}
			if res.Token.Kind != IncompleteOutput || res.Token.Exit() != 3 || len(res.Outputs) != 0 {
				t.Fatalf("token %s outputs %d", res.Token, len(res.Outputs))
			}
			if len(res.Unsafe) != 1 || res.Unsafe[0].What != x.what {
				t.Fatalf("unsafe %+v", res.Unsafe)
			}
			if res.Record.Result != "incomplete output" {
				t.Fatalf("record result %s", res.Record.Result)
			}
			for _, o := range res.Outputs {
				if bytes.Contains(o.Bytes, c.data) {
					t.Fatal("canary read")
				}
			}
			if _, err := PlanPublish(PublishInput{Spec: s, Result: res}); err == nil {
				t.Fatal("an incomplete output was published")
			}
			c.check(t)
		})
	}
}
