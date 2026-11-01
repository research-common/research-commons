package hubcheck

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// repo reads a git repository through plumbing only (hub template contract H-03): `rev-parse`, `merge-base`,
// `ls-tree`, `diff --raw -z` and `cat-file`. Objects are read as raw bytes: no text conversion, no textconv,
// no external diff, no filters, no attributes; no command that runs a hook is ever invoked. The environment
// drops system and global configuration and attribute files, so nothing outside the repository's own object
// database shapes what is read.
type repo struct {
	dir string
	env []string
}

func newRepo(dir string) *repo {
	env := []string{}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GIT_") {
			continue // nothing from the caller's environment redirects git (GIT_DIR, GIT_EXTERNAL_DIFF, …)
		}
		env = append(env, kv)
	}
	env = append(env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_ATTR_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C")
	return &repo{dir: dir, env: env}
}

// git runs one plumbing command and returns its stdout. `-c safe.directory` is not set: a repository git
// refuses to read is an error the caller reports.
func (r *repo) git(stdin []byte, args ...string) ([]byte, error) {
	full := append([]string{"-C", r.dir, "-c", "core.attributesFile=" + os.DevNull, "-c", "diff.external=",
		"-c", "core.fsmonitor=false"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Env = r.env
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// commit resolves rev to a full commit id, or reports that it is not a commit here.
func (r *repo) commit(rev string) (string, error) {
	if rev == "" || strings.HasPrefix(rev, "-") {
		return "", fmt.Errorf("%q is not a revision", rev)
	}
	out, err := r.git(nil, "rev-parse", "--verify", "--quiet", "--end-of-options", rev+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("%q is not a commit in this repository", rev)
	}
	return strings.TrimSpace(string(out)), nil
}

func (r *repo) mergeBase(a, b string) (string, error) {
	out, err := r.git(nil, "merge-base", a, b)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// entry is one tree entry.
type entry struct {
	mode, typ, oid, path string
}

// tree lists every entry of rev's tree recursively, paths as stored (no quoting under -z).
func (r *repo) tree(rev string) ([]entry, error) {
	out, err := r.git(nil, "ls-tree", "-r", "-z", "--full-tree", rev)
	if err != nil {
		return nil, err
	}
	var es []entry
	for _, rec := range bytes.Split(out, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		tab := bytes.IndexByte(rec, '\t')
		if tab < 0 {
			return nil, errors.New("ls-tree: malformed record")
		}
		f := strings.Fields(string(rec[:tab]))
		if len(f) != 3 {
			return nil, errors.New("ls-tree: malformed record")
		}
		es = append(es, entry{mode: f[0], typ: f[1], oid: f[2], path: string(rec[tab+1:])})
	}
	return es, nil
}

// change is one path of `diff --raw -z --no-renames`.
type change struct {
	oldMode, newMode, oldOID, newOID, status, path string
}

// diff lists the paths that differ between a and b. Renames and copies are not detected: a rename is a
// deletion and an addition, each judged on its own.
func (r *repo) diff(a, b string) ([]change, error) {
	out, err := r.git(nil, "diff-tree", "-r", "-z", "--raw", "--no-renames", "--no-abbrev", "--no-ext-diff", "--no-textconv", a, b)
	if err != nil {
		return nil, err
	}
	parts := bytes.Split(out, []byte{0})
	var cs []change
	for i := 0; i < len(parts); i++ {
		head := string(parts[i])
		if head == "" {
			continue
		}
		if !strings.HasPrefix(head, ":") || i+1 >= len(parts) {
			return nil, fmt.Errorf("diff: malformed record %q", head)
		}
		f := strings.Fields(head[1:])
		if len(f) != 5 {
			return nil, fmt.Errorf("diff: malformed record %q", head)
		}
		i++
		cs = append(cs, change{oldMode: f[0], newMode: f[1], oldOID: f[2], newOID: f[3], status: f[4][:1], path: string(parts[i])})
	}
	return cs, nil
}

// blobs reads raw object contents by id in one `cat-file --batch` (no --filters, no --textconv).
func (r *repo) blobs(oids []string) (map[string][]byte, error) {
	out := map[string][]byte{}
	if len(oids) == 0 {
		return out, nil
	}
	var in bytes.Buffer
	for _, o := range oids {
		in.WriteString(o + "\n")
	}
	raw, err := r.git(in.Bytes(), "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(bytes.NewReader(raw))
	for range oids {
		hdr, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("cat-file: %v", err)
		}
		f := strings.Fields(hdr)
		if len(f) != 3 {
			return nil, fmt.Errorf("cat-file: %q", strings.TrimSpace(hdr))
		}
		n, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("cat-file: %q", hdr)
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, err
		}
		if _, err := br.ReadByte(); err != nil { // the LF after each object
			return nil, err
		}
		out[f[0]] = b
	}
	return out, nil
}

// fileAt returns the raw bytes of path in rev's tree, or nil when absent.
func (r *repo) fileAt(rev, path string) ([]byte, error) {
	out, err := r.git(nil, "ls-tree", "-z", "--full-tree", rev, "--", path)
	if err != nil {
		return nil, err
	}
	rec := bytes.TrimSuffix(out, []byte{0})
	if len(rec) == 0 {
		return nil, nil
	}
	tab := bytes.IndexByte(rec, '\t')
	f := strings.Fields(string(rec[:max(tab, 0)]))
	if tab < 0 || len(f) != 3 || string(rec[tab+1:]) != path {
		return nil, fmt.Errorf("ls-tree %s: malformed record", path)
	}
	if f[1] != "blob" || f[0] == "120000" {
		return nil, fmt.Errorf("%s at %s is not a regular file (mode %s)", path, rev, f[0])
	}
	m, err := r.blobs([]string{f[2]})
	if err != nil {
		return nil, err
	}
	return m[f[2]], nil
}
