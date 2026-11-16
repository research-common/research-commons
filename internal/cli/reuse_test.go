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
	conformance.Partial(t, "C-core-146", "(a) end to end through publish: an aged held blob reused by a publish that stops before its record survives gc --apply and the retry commits without the bytes (the stop is the before-commit test seam; the crash seam with a real process exit is a later slice); (b) and the policy floor of (c) are the store's (TestGCRecheckAtDeletion, TestGCGraceFloor); (d) needs the operation history")
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
