package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/store"
)

// heldUnreferenced installs data as a blob no statement names and ages it past the default grace window.
func heldUnreferenced(t *testing.T, p *pubWorld, data string, by time.Duration) (string, string) {
	t.Helper()
	d, _, err := p.s.InstallBlob(strings.NewReader(data), "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(p.root, "blobs", "sha256", strings.TrimPrefix(string(d), "sha256:"))
	old := time.Now().Add(-by)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	return string(d), path
}

// TestPublishReuseRestartsWindow: C-core-146 (a) through the command. An unreferenced blob older than the grace
// window is named by a publish that brings no bytes (the draft names the digest); the publish fails after step 1
// (before its record); gc --apply runs with the default window; the blob is kept because the reuse restarted its
// window, and the retry commits without the content file.
func TestPublishReuseRestartsWindow(t *testing.T) {
	conformance.Partial(t, "C-core-146", "(a) through publish with a refusal before the record (the before-commit test seam, so the abort path runs): the reuse restarted the window, gc keeps the blob, the retry commits without the bytes; the process crash is TestPublishReuseCrashThenGC; (d) is TestHistoryNeverDecides")
	p := newPubWorld(t)
	data := "bytes this store released long ago"
	d, path := heldUnreferenced(t, p, data, 72*time.Hour)
	if r := p.run("gc", "--json"); !strings.Contains(r.stdout, d) {
		t.Fatalf("setup: the aged blob should be a gc candidate: %s", r.stdout)
	}
	draft := p.file("a.json", `{"kind":"authored","body":{"type":"dataset","content":{"digest":"`+d+`","size":`+strconv.Itoa(len(data))+`}}}`)

	// the first attempt stops after step 1, before its record (nothing committed)
	beforeCommit = func() error { return errors.New("stopped before the record") }
	r := p.publish("--draft", draft)
	beforeCommit = func() error { return nil }
	if r.code != ExitCouldNot || outObj(t, r).Members["committed"] != canon.Bool(false) {
		t.Fatalf("stopped publish: %d %s", r.code, r.stdout)
	}
	if fi, err := os.Stat(path); err != nil || time.Since(fi.ModTime()) > time.Hour {
		t.Fatalf("the reuse did not restart the blob's window: %v %v", fi, err)
	}

	// gc with the default window keeps it: its window restarted at the reuse
	if g := p.run("gc", "--apply", "--json"); g.code != 0 || strings.Contains(string(canon.Encode(jsonOf(t, g).Members["deleted"])), d) {
		t.Fatalf("gc deleted a blob a publish had just reused: %d %s", g.code, g.stdout)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("blob gone after gc: %v", err)
	}

	// the retry commits against the held blob, with no content file
	r = p.publish("--draft", draft)
	if r.code != 0 || !strings.Contains(r.stdout, "blob "+d+" already held") {
		t.Fatalf("retry: %d %s", r.code, r.stdout)
	}
}

// TestPublishRefusesCorruptHeldBlob: a held blob whose bytes no longer hash to its name is never reused. With no
// bytes to give, publish is refused naming both hashes and nothing is committed; given the bytes, the corrupt copy
// is quarantined and the verified copy installed.
func TestPublishRefusesCorruptHeldBlob(t *testing.T) {
	p := newPubWorld(t)
	data := "the bytes as published"
	d, path := heldUnreferenced(t, p, data, 0)
	os.Chmod(path, 0o644)
	if err := os.WriteFile(path, []byte("the bytes as damaged!!"), 0o444); err != nil {
		t.Fatal(err)
	}
	draft := p.file("a.json", `{"kind":"authored","body":{"type":"dataset","content":{"digest":"`+d+`","size":`+strconv.Itoa(len(data))+`}}}`)
	before := snapshot(t, p.root)
	r := p.publish("--draft", draft)
	o := outObj(t, r)
	if r.code != ExitCouldNot || o.Members["committed"] != canon.Bool(false) || !strings.Contains(r.stdout, store.CorruptBlob) ||
		!strings.Contains(r.stdout, "hashes to "+dig("the bytes as damaged!!")) || !strings.Contains(r.stdout, "commons fetch "+d) {
		t.Fatalf("corrupt held blob reused or refused without naming it: %d %s", r.code, r.stdout)
	}
	if snapshot(t, p.root) != before {
		t.Fatal("a refused publish changed the store")
	}
	if pend, _ := os.ReadDir(filepath.Join(p.root, "journal", "pending")); len(pend) != 0 {
		t.Fatal("record written")
	}
	// with the bytes: the corrupt copy goes to quarantine, the verified one is installed and the publish commits
	r = p.publish("--kind", "authored", "--content", p.file("c", data))
	if r.code != 0 {
		t.Fatalf("publish with the bytes: %d %s", r.code, r.stdout)
	}
	if b, _ := os.ReadFile(path); !bytes.Equal(b, []byte(data)) {
		t.Fatal("the corrupt copy was kept")
	}
	if q, _ := os.ReadDir(filepath.Join(p.root, "quarantine")); len(q) != 1 {
		t.Fatalf("quarantine: %v", q)
	}
}

// TestDegradedOpenCommands: a committed operation the store cannot finish on open (its key's statement directory
// is not writable) no longer makes every command fail. status exits 0 and names the operation, the error and the
// next step; fsck runs; reads work and do not show the half-installed operation; a publish by that key is refused
// naming the operation, with nothing written; once the cause is fixed, the next open finishes it.
func TestDegradedOpenCommands(t *testing.T) {
	conformance.Partial(t, "C-core-126", "through the commands: a committed operation whose replay fails does not block status, fsck or reads (degraded open); its statements stay hidden, its key's writes are refused naming it, and the next open after the fix finishes it; the repair command and its exits are TestRepairMissingBlob")
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions; the fault cannot be injected")
	}
	p := newPubWorld(t)
	if r := p.publish("--kind", "authored", "--content", p.file("first", "first bytes")); r.code != 0 {
		t.Fatalf("first publish: %d %s", r.code, r.stdout)
	}
	dir := filepath.Join(p.root, "statements", strings.ReplaceAll(p.signer, ":", "-"))
	os.Chmod(dir, 0o500) // the install step (3) fails after the record (2) is written, and on every open after
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	r := p.publish("--kind", "authored", "--content", p.file("c", "blocked bytes"))
	if r.code != ExitCouldNot || outObj(t, r).Members["committed"] != canon.Bool(true) {
		t.Fatalf("pending install: %d %s", r.code, r.stdout)
	}
	op := string(outObj(t, r).Members["scope"].(canon.String))
	op = strings.TrimPrefix(op, "operation ")

	st := p.run("status", "--json")
	if st.code != 0 || !strings.Contains(st.stdout, `"what":"replay failed"`) || !strings.Contains(st.stdout, op) ||
		!strings.Contains(st.stdout, "permission denied") || !strings.Contains(st.stdout, "fix the cause in peer_text") {
		t.Fatalf("status under a failing replay: %d %s", st.code, st.stdout)
	}
	if f := p.run("fsck", "--json"); f.code == ExitDidNotStart || !strings.Contains(f.stdout, op) {
		t.Fatalf("fsck under a failing replay: %d %s", f.code, f.stdout)
	}
	if l := p.run("list", "--json"); l.code != 0 || !strings.Contains(l.stdout, dig("first bytes")) || strings.Contains(l.stdout, dig("blocked bytes")) {
		t.Fatalf("list under a failing replay: %d %s", l.code, l.stdout)
	}
	before := snapshot(t, p.root)
	w := p.publish("--kind", "describes", "--about", dig("first bytes"), "--note", "x")
	if w.code != ExitCouldNot || outObj(t, w).Members["committed"] != canon.Bool(false) || !strings.Contains(w.stdout, op) ||
		!strings.Contains(w.stdout, "replay failed") || !strings.Contains(w.stdout, "every open of the store replays the operation") {
		t.Fatalf("a write by the blocked key: %d %s", w.code, w.stdout)
	}
	if snapshot(t, p.root) != before {
		t.Fatal("a refused write changed the store")
	}

	os.Chmod(dir, 0o755)
	if s := p.run("status", "--json"); s.code != 0 || !strings.Contains(s.stdout, `"what":"replayed"`) || !strings.Contains(s.stdout, `"store_state":"nothing pending"`) {
		t.Fatalf("status after the fix: %d %s", s.code, s.stdout)
	}
	if l := p.run("list", "--json"); !strings.Contains(l.stdout, dig("blocked bytes")) {
		t.Fatalf("the finished operation is not listed: %s", l.stdout)
	}
}
