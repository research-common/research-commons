//go:build sandbox_oci

// The OCI backend against a real container runtime. Not part of `go test ./...`: run with
//
//	RC_TEST_IMAGE=alpine:latest go test -tags sandbox_oci -run OCI -v ./internal/run
//
// The image must already be held by the runtime (it is never pulled) and provide `sh` and `sleep`.

package run

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

func ociImage(t *testing.T) Image {
	t.Helper()
	ref := os.Getenv("RC_TEST_IMAGE")
	if ref == "" {
		t.Skip("RC_TEST_IMAGE is not set")
	}
	o := &OCI{}
	if err := o.Available(context.Background()); err != nil {
		t.Skip("no OCI runtime: " + err.Error())
	}
	out, err := o.cli(context.Background(), "image", "inspect", "--format", "{{.Id}}", ref)
	if err != nil {
		t.Skip("image not held: " + err.Error())
	}
	return Image{Reference: ref, Digest: out}
}

// ociSpec is a spec whose code is the shell script given, under the test image, with caps.
func ociSpec(t *testing.T, img Image, script string, res *canon.Object, outputs *canon.Object, network canon.Value) (*Spec, map[string][]byte) {
	t.Helper()
	code := []byte(script)
	kv := []any{"code", canon.String(Digest(code)), "image", object("reference", canon.String(img.Reference), "digest", canon.String(img.Digest)),
		"resources", res}
	if outputs != nil {
		kv = append(kv, "outputs", outputs)
	}
	if network != nil {
		kv = append(kv, "network", network)
	}
	b := specB("unused", nil, kv...)
	s := mustSpec(t, b)
	return s, map[string][]byte{s.Code: code}
}

func ociPolicy() *Policy {
	return &Policy{ExecSigners: []string{ownerKey}, Ceiling: Resources{CapMemory: 256 << 20, CapWallTime: 30_000, CapPids: 64, CapDisk: 16 << 20}}
}

type audit struct {
	mu   sync.Mutex
	pids map[int]bool
}

func (a *audit) observe(p []int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, x := range p {
		a.pids[x] = true
	}
}

func (a *audit) alive(t *testing.T) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.pids) == 0 {
		t.Fatal("the audit saw no process: the run did not reach the cgroup")
	}
	for p := range a.pids {
		if err := syscall.Kill(p, 0); err == nil || err == syscall.EPERM {
			t.Fatalf("pid %d still alive", p)
		}
	}
}

func leftovers(t *testing.T) {
	t.Helper()
	out, _ := (&OCI{}).cli(context.Background(), "ps", "-aq", "--filter", "label=research-commons.run=1")
	if strings.TrimSpace(out) != "" {
		t.Fatalf("containers left: %s", out)
	}
}

// TestOCIRoundTrip: a sandbox run produces an output, a record with a measured peak RSS, and the boundary named.
func TestOCIRoundTrip(t *testing.T) {
	img := ociImage(t)
	s, blobs := ociSpec(t, img, "echo hello > \"$OUT_DIR/result.txt\"\n", object("memory", canon.Int(64<<20), "wall_time", canon.Int(20_000)), nil, nil)
	res, err := Execute(context.Background(), ociPolicy(), &OCI{}, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobs})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Completed() || string(res.Outputs[0].Bytes) != "hello\n" {
		t.Fatalf("%s %+v", res.Token, res.Outputs)
	}
	if res.Record.PeakRSS == nil || *res.Record.PeakRSS <= 0 || !strings.HasPrefix(res.Record.Boundary, "sandbox: oci, image sha256:") || !strings.HasPrefix(res.Record.Cleanup, "ok") {
		t.Fatalf("%+v", res.Record)
	}
	if err := res.Record.Validate(); err != nil {
		t.Fatal(err)
	}
	leftovers(t)
}

// TestOCICapsDuringExecution: C-exec-10. A step that forks without bound and writes an unbounded stream, caps low
// enough to trip during execution: stopped while running (`failed: operational: pids` / `memory` / `disk`), the
// container and every descendant gone (PIDs recorded while it ran are dead), nothing published, nothing reads as
// match. The step's script never exits on its own, so a result at all proves the cap stopped it.
func TestOCICapsDuringExecution(t *testing.T) {
	conformance.Covers(t, "C-exec-10")
	img := ociImage(t)
	for _, c := range []struct {
		name, script, cap string
		res               *canon.Object
	}{
		{"fork bomb", "while true; do sleep 1000 & done\n", CapPids, object("pids", canon.Int(16), "wall_time", canon.Int(20_000), "memory", canon.Int(64<<20))},
		{"memory", "x=a; while true; do x=\"$x$x\"; done\n", CapMemory, object("memory", canon.Int(16<<20), "wall_time", canon.Int(20_000))},
		{"unbounded stream", "while true; do echo 0123456789abcdef0123456789abcdef; done > \"$OUT_DIR/result.txt\"\n", CapDisk,
			object("disk", canon.Int(1<<20), "wall_time", canon.Int(20_000), "memory", canon.Int(64<<20))},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := &audit{pids: map[int]bool{}}
			s, blobs := ociSpec(t, img, c.script, c.res, nil, nil)
			start := time.Now()
			res, err := Execute(context.Background(), ociPolicy(), &OCI{Observe: a.observe}, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobs})
			if err != nil {
				t.Fatal(err)
			}
			if res.Token.String() != "failed: operational: "+c.cap || res.Token.Kind == Match || len(res.Outputs) != 0 {
				t.Fatalf("%s after %v; record %+v", res.Token, time.Since(start), res.Record)
			}
			if time.Since(start) > 15*time.Second {
				t.Fatalf("not stopped during execution: %v", time.Since(start))
			}
			if _, err := PlanPublish(PublishInput{Spec: s, Result: res}); err == nil {
				t.Fatal("published")
			}
			a.alive(t)
			leftovers(t)
		})
	}
}

// TestOCITimeout: C-exec-11. A step that sleeps past the wall-time cap and leaves a child: the container is
// killed, no container or process is left, staging is cleaned, the token is `timeout` with resources used,
// verify exits 3 (not 5), and no `reproduced` is emitted.
func TestOCITimeout(t *testing.T) {
	conformance.Covers(t, "C-exec-11")
	img := ociImage(t)
	a := &audit{pids: map[int]bool{}}
	s, blobs := ociSpec(t, img, "(sleep 1000 &) ; sleep 1000\n", object("wall_time", canon.Int(1500), "memory", canon.Int(64<<20)), nil, nil)
	staging := t.TempDir()
	res, err := Execute(context.Background(), ociPolicy(), &OCI{Observe: a.observe}, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobs, StagingRoot: staging})
	if err != nil {
		t.Fatal(err)
	}
	if res.Token.Kind != Timeout || res.Token.Exit() != 3 || res.Record.ExitStatus != "killed: wall_time" || res.Record.PeakRSS == nil {
		t.Fatalf("%s %+v", res.Token, res.Record)
	}
	has(t, strings.Join(res.Explain, "\n"), "resources used up to the kill")
	if left, _ := os.ReadDir(staging); len(left) != 0 || !res.StagingRemoved {
		t.Fatalf("staging left: %v", left)
	}
	if _, err := PlanPublish(PublishInput{Spec: s, Result: res, Own: []HeldAuthored{{strings.Repeat("ab", 32), Digest([]byte("x"))}}, Mode: "bytes"}); err == nil {
		t.Fatal("a reproduced was planned")
	}
	a.alive(t)
	leftovers(t)
}

// TestOCIBoundary: C-exec-12. A step that reads a canary environment variable and a canary file outside its
// directory and connects to a canary listener the test controls; delivery is proven by its stdout marker (here
// its output file: the step demonstrably ran and wrote). The listener records no connection, the canary values
// never appear in outputs, the record names the boundary, nothing outside is written.
func TestOCIBoundary(t *testing.T) {
	conformance.Covers(t, "C-exec-12")
	img := ociImage(t)
	c := newCanary(t)
	t.Setenv("RC_CANARY_SECRET", "CANARY-ENV-VALUE")
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var conns int
	var mu sync.Mutex
	go func() {
		for {
			cn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns++
			mu.Unlock()
			cn.Close()
		}
	}()
	port := strings.TrimPrefix(ln.Addr().String()[strings.LastIndex(ln.Addr().String(), ":"):], ":")
	gw := "172.17.0.1"
	script := strings.Join([]string{
		`o="$OUT_DIR/result.txt"`,
		`echo MARKER-RAN > "$o"`,
		`echo "env=$RC_CANARY_SECRET" >> "$o"`,
		`cat ` + c.path + ` >> "$o" 2>/dev/null || echo nofile >> "$o"`,
		`echo x > ` + c.path + ` 2>/dev/null || echo nowrite >> "$o"`,
		`(nc -w 2 ` + gw + ` ` + port + ` </dev/null || wget -T 2 -q -O- http://` + gw + `:` + port + `/) >/dev/null 2>&1 || echo noconnect >> "$o"`,
	}, "\n") + "\n"
	s, blobs := ociSpec(t, img, script, object("memory", canon.Int(64<<20), "wall_time", canon.Int(20_000)), nil, nil)
	res, err := Execute(context.Background(), ociPolicy(), &OCI{}, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobs})
	if err != nil || !res.Completed() {
		t.Fatalf("%v %s", err, res.Token)
	}
	out := string(res.Outputs[0].Bytes)
	has(t, out, "MARKER-RAN")
	has(t, out, "nofile")
	has(t, out, "noconnect")
	hasNot(t, out, "CANARY")
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	n := conns
	mu.Unlock()
	if n != 0 {
		t.Fatalf("listener saw %d connections", n)
	}
	if !strings.HasPrefix(res.Record.Boundary, "sandbox: oci, image ") {
		t.Fatalf("boundary %q", res.Record.Boundary)
	}
	if got := string(canon.Encode(res.Record.Object().Members["network"])); got != `"none"` {
		t.Fatalf("network %s", got)
	}
	c.check(t)

	// control: the same probe with the network granted reaches the listener, so the refusal above was the
	// boundary and not a probe that could never connect
	sn, blobsN := ociSpec(t, img, script, object("memory", canon.Int(64<<20), "wall_time", canon.Int(20_000)), nil,
		object("required", strings2array([]string{"tcp://" + gw + ":" + port})))
	pn := ociPolicy()
	pn.Network = []string{sn.Digest}
	resN, err := Execute(context.Background(), pn, &OCI{}, Invocation{Request: Request{Spec: sn, Signer: ownerKey}, Blobs: blobsN})
	if err != nil || !resN.Completed() {
		t.Fatalf("control: %v %s", err, resN.Token)
	}
	if resN.Record.NetworkEnforced != EnforcedAll { // the OCI runner opens the bridge as a whole (§6)
		t.Fatalf("control: network.enforced %q, want all", resN.Record.NetworkEnforced)
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	n = conns
	mu.Unlock()
	if n == 0 {
		t.Skip("control: the probe cannot reach the listener even with a network (host firewall?); the no-connection result proves nothing on this host")
	}
	hasNot(t, string(resN.Outputs[0].Bytes), "CANARY") // the env canary still never crosses: no grant names it
	leftovers(t)
}

// TestOCIOutputSymlink: C-exec-09 against the real runtime: a symlink the step makes in /out pointing at a host
// canary is recreated as a symlink (never followed) and refused at read-back; `incomplete output`.
func TestOCIOutputSymlink(t *testing.T) {
	img := ociImage(t)
	c := newCanary(t)
	s, blobs := ociSpec(t, img, "ln -s "+c.path+" \"$OUT_DIR/result.txt\"\n", object("memory", canon.Int(64<<20), "wall_time", canon.Int(20_000)), nil, nil)
	res, err := Execute(context.Background(), ociPolicy(), &OCI{}, Invocation{Request: Request{Spec: s, Signer: ownerKey}, Blobs: blobs})
	if err != nil {
		t.Fatal(err)
	}
	if res.Token.Kind != IncompleteOutput || len(res.Unsafe) != 1 || res.Unsafe[0].What != PathSymlink {
		t.Fatalf("%s %+v", res.Token, res.Unsafe)
	}
	c.check(t)
	_ = filepath.Join
	_ = slices.Contains[[]string]
}
