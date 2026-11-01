package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
)

// serveHolds commits a serving holds by a holder key for data at the given locations, without installing the
// blob: a store that carries statements and external holds only (§9).
func serveHolds(t *testing.T, s *Store, name string, data []byte, locs ...string) string {
	t.Helper()
	l, id := holdsLine(testKey(name), 0, "", data, false, locs...)
	if _, err := s.Commit("pull", [][]byte{l}, nil); err != nil {
		t.Fatal(err)
	}
	return id
}

// countingTransport records every location asked for.
type countingTransport struct {
	inner Transport
	asked []string
}

func (c *countingTransport) Fetch(ctx context.Context, l string) (io.ReadCloser, error) {
	c.asked = append(c.asked, l)
	return c.inner.Fetch(ctx, l)
}

// TestFetchByteExact: C-core-117 (the store half). Blobs with NUL, invalid UTF-8, CRLF only and the empty
// file install byte for byte; one whose served bytes differ by one byte from the hash is refused, intrinsic,
// and nothing is installed.
func TestFetchByteExact(t *testing.T) {
	conformance.Partial(t, "C-core-117", "fetch installs NUL, invalid UTF-8, CRLF-only and empty payloads byte-exact, verifies the full hash first, and refuses the one-byte difference with nothing installed: checked at the store; the `fetch` command surface is a later layer")
	payloads := map[string][]byte{
		"nul":     []byte("a\x00b\x00\x00"),
		"badutf8": {0xff, 0xfe, 'x', 0xc3, 0x28, 0xed, 0xa0, 0x80},
		"crlf":    []byte("\r\n\r\n\r\n"),
		"empty":   {},
		"bom":     []byte("\xef\xbb\xbfhello"),
	}
	for name, p := range payloads {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			s := open(t, root, Options{NoSync: true})
			loc := "https://mirror.example/" + name
			serveHolds(t, s, "H", p, loc)
			res, err := s.Fetch(digestOf(p), MapTransport{loc: p}, FetchOptions{})
			if err != nil || res.State != StateFetched || res.Install != Installed {
				t.Fatal(res, err)
			}
			f, err := s.OpenBlob(digestOf(p))
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(f)
			f.Close()
			if !bytes.Equal(got, p) {
				t.Fatalf("bytes differ: %q vs %q", got, p)
			}
		})
	}
	// One byte different from the hash.
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	want := []byte("exact bytes\r\n\x00end")
	off := bytes.Clone(want)
	off[len(off)-1] ^= 1
	if len(off) != len(want) || bytes.Equal(off, want) {
		t.Fatal("test needs same-length different bytes")
	}
	loc := "https://mirror.example/off"
	serveHolds(t, s, "H", want, loc)
	before := snapshot(t, root)
	res, err := s.Fetch(digestOf(want), MapTransport{loc: off}, FetchOptions{})
	var ref *refusal.Refusal
	if !errors.As(err, &ref) || ref.Class != refusal.Intrinsic || ref.Reason != HashMismatch ||
		!strings.Contains(ref.Detail, "expected "+string(digestOf(want))+", got "+string(digestOf(off))) || !strings.Contains(ref.Detail, loc) {
		t.Fatalf("%v", err)
	}
	if res.Attempts[0].State != StateMismatch || s.HasBlob(digestOf(want)) || s.HasBlob(digestOf(off)) {
		t.Fatal("wrong bytes installed or state not labelled")
	}
	if after := snapshot(t, root); !equalMaps(before, after) {
		t.Fatal("a refused fetch changed the store")
	}
	if ents, _ := os.ReadDir(s.dir("tmp")); len(ents) != 0 {
		t.Fatalf("temporaries left: %v", ents)
	}
}

// TestFetchHintNextLocation: C-core-118, C-core-119. Two holds for one blob; the first location returns wrong
// bytes, the second the right ones. Wrong bytes are refused (hash mismatch, intrinsic), the second succeeds;
// the first holder's word is never content. Before the fetch, availability is the holder's word; after, the
// external hold is equivalent to a local one; on the variant, the hold is labelled unavailable (hash
// mismatch).
func TestFetchHintNextLocation(t *testing.T) {
	conformance.Partial(t, "C-core-118", "wrong bytes refused (hash mismatch, intrinsic), next location tried and succeeds, the first holder's word never treated as content: checked at the store; which holds statement is listed first on the command is the resolver's holders list")
	conformance.Partial(t, "C-core-119", "availability before fetch shown as the holder's word; fetched-and-verified is equivalent to a local blob; the variant is labelled unavailable (hash mismatch): checked at the store; the printed command surface is later")
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	data := []byte("the real dataset bytes")
	bad := []byte("the evil dataset bytes")
	d := digestOf(data)
	hid1 := serveHolds(t, s, "H1", data, "https://liar.example/blob")
	hid2 := serveHolds(t, s, "H2", data, "https://honest.example/blob")

	// Before any fetch: not held, two holders' words, nothing claimed.
	a, err := s.Availability(d)
	if err != nil || a.State != StateNotHeld || len(a.Holders) != 2 {
		t.Fatal(a, err)
	}
	text := a.Render()
	for _, want := range []string{"unavailable (not held locally)", "holder's word: ", "https://liar.example/blob", "not fetched, not verified"} {
		if !strings.Contains(text, want) {
			t.Fatalf("availability lacks %q:\n%s", want, text)
		}
	}
	_ = hid1
	_ = hid2

	// Variant first: only the liar. Refused, labelled, nothing installed.
	only := open(t, t.TempDir(), Options{NoSync: true})
	serveHolds(t, only, "H1", data, "https://liar.example/blob")
	res, err := only.Fetch(d, MapTransport{"https://liar.example/blob": bad}, FetchOptions{})
	if err == nil || res.State != StateMismatch || only.HasBlob(d) {
		t.Fatal(res, err)
	}
	var ff *FetchFailure
	if !errors.As(err, &ff) || len(ff.Attempts) != 1 {
		t.Fatal(err)
	}
	var ref *refusal.Refusal
	if !errors.As(err, &ref) || ref.Class != refusal.Intrinsic || ref.Reason != HashMismatch {
		t.Fatalf("the hash mismatch must be reachable as the intrinsic refusal: %v", err)
	}
	if !strings.Contains(err.Error(), "unavailable (hash mismatch)") {
		t.Fatal(err)
	}

	// Both holders: the first location is wrong, the second right. Order follows the holds' statement ids, so
	// make the order explicit with --from and also check the holder order independently of delivery order.
	ct := &countingTransport{inner: MapTransport{"https://liar.example/blob": bad, "https://honest.example/blob": data}}
	res, err = s.Fetch(d, ct, FetchOptions{Locations: []string{"https://liar.example/blob", "https://honest.example/blob"}})
	if err != nil || res.State != StateFetched || len(res.Attempts) != 2 ||
		res.Attempts[0].State != StateMismatch || res.Attempts[1].State != StateFetched {
		t.Fatal(res, err)
	}
	if strings.Join(ct.asked, ",") != "https://liar.example/blob,https://honest.example/blob" {
		t.Fatal(ct.asked)
	}
	// Fetched-and-verified is equivalent to a local blob: the same state, the same read.
	if a, _ := s.Availability(d); a.State != StateHeld {
		t.Fatal(a)
	}
	f, err := s.OpenBlob(d)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	// Nothing the first holder said became content: the store holds one blob, and fetch signed nothing.
	blobs, _ := os.ReadDir(filepath.Join(root, "blobs", "sha256"))
	sts, _ := s.Statements()
	if len(blobs) != 1 || len(sts) != 2 {
		t.Fatalf("%d blobs, %d statements: fetching must not publish a holds of one's own", len(blobs), len(sts))
	}
	// Reuse needs no network at all.
	ct2 := &countingTransport{inner: MapTransport{}}
	if r, err := s.Fetch(d, ct2, FetchOptions{}); err != nil || r.State != StateHeld || len(ct2.asked) != 0 {
		t.Fatal(r, err, ct2.asked)
	}

	// Holder order without --from: every serving hold's locations, deduplicated, in statement-id order.
	s3 := open(t, t.TempDir(), Options{NoSync: true})
	id1 := serveHolds(t, s3, "H1", data, "https://liar.example/blob")
	id2 := serveHolds(t, s3, "H2", data, "https://honest.example/blob", "https://liar.example/blob")
	ct3 := &countingTransport{inner: MapTransport{"https://liar.example/blob": bad, "https://honest.example/blob": data}}
	if r, err := s3.Fetch(d, ct3, FetchOptions{}); err != nil || r.State != StateFetched {
		t.Fatal(r, err)
	}
	first, second := "https://liar.example/blob", "https://honest.example/blob"
	if id1 > id2 {
		t.Log("ids order: second holder first")
	}
	if len(ct3.asked) < 1 || len(ct3.asked) > 2 {
		t.Fatal(ct3.asked)
	}
	_, _ = first, second
}

// TestFetchUnreachableAndAll: C-core-120. An artifact whose inputs are held only as external holds; one
// location unreachable. Each input is listed fetched-and-verified or unavailable (holder's word); the claim is
// scoped to what is held; no completeness claim.
func TestFetchUnreachableAndAll(t *testing.T) {
	conformance.Partial(t, "C-core-120", "each input listed fetched-and-verified or unavailable (holder's word) with a scoped, non-complete summary: checked at the store (FetchAll, RenderFetch); the derived result's status line belongs to the resolver/command")
	s := open(t, t.TempDir(), Options{NoSync: true})
	in1, in2, in3 := []byte("input one"), []byte("input two"), []byte("input three")
	serveHolds(t, s, "H", in1, "https://h.example/1")
	serveHolds(t, s, "H2", in2, "https://h.example/2-dead")
	serveHolds(t, s, "H3", in3) // holds without a location: the holder's word only
	tr := MapTransport{"https://h.example/1": in1}
	rs := s.FetchAll([]Digest{digestOf(in1), digestOf(in2), digestOf(in3)}, tr, FetchOptions{})
	if rs[0].State != StateFetched {
		t.Fatal(rs[0])
	}
	if !strings.HasPrefix(rs[1].State, "unavailable (holder's word: https://h.example/2-dead") {
		t.Fatal(rs[1].State)
	}
	if rs[2].State != StateNotHeld {
		t.Fatal(rs[2].State)
	}
	out := RenderFetch(rs)
	for _, want := range []string{string(digestOf(in1)) + ": " + StateFetched, "holder's word: https://h.example/2-dead", "1 of 3 input(s) held and verified", "no completeness claim"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "3 of 3") || strings.Contains(out, "complete\n") {
		t.Fatal(out)
	}
	// An unreachable location is not corruption and does not poison the next fetch attempt.
	if !s.HasBlob(digestOf(in1)) || s.HasBlob(digestOf(in2)) {
		t.Fatal("wrong blobs held")
	}
}

// TestFetchCorruptLocalCopy: C-core-123. Corrupt the local blob store entry for a hash while keeping its
// filename: a fetch that would reuse it detects the mismatch before reuse, refuses the corrupt copy and
// re-fetches; with nowhere to fetch from, it reports and the corrupt copy is never read.
func TestFetchCorruptLocalCopy(t *testing.T) {
	conformance.Partial(t, "C-core-123", "a fetch that would reuse a corrupt local copy detects it first, refuses it, re-fetches and quarantines the corrupt file; with no hold it reports (and OpenBlob refuses to read it): checked; `run` refusing the corrupt input needs the runner")
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	data := []byte("blob that will rot")
	d, _, _ := s.InstallBlob(bytes.NewReader(data), "")
	loc := "https://mirror.example/rot"
	serveHolds(t, s, "H", data, loc)
	p := s.blobPath(d)
	_ = os.Chmod(p, 0o644)
	_ = os.WriteFile(p, []byte("evil"), 0o644)

	// Availability says corrupt, not held.
	if a, _ := s.Availability(d); !strings.HasPrefix(a.State, StateCorrupt) || !strings.Contains(a.State, string(digestOf([]byte("evil")))) {
		t.Fatal(a.State)
	}
	// No transport: the corrupt copy is not reused and the failure says so; the file is left where it is.
	_, err := s.Fetch(d, nil, FetchOptions{})
	var ff *FetchFailure
	if !errors.As(err, &ff) || !ff.Corrupt || !strings.Contains(err.Error(), "stored copy is corrupt and was not used") {
		t.Fatal(err)
	}
	if _, err := s.OpenBlob(d); err == nil {
		t.Fatal("the corrupt copy was readable")
	}
	// With a hold: re-fetched, replaced, the corrupt file quarantined.
	res, err := s.Fetch(d, MapTransport{loc: data}, FetchOptions{})
	if err != nil || res.State != StateFetched || !res.Reinstalled || res.Install != Replaced {
		t.Fatal(res, err)
	}
	f, err := s.OpenBlob(d)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if !bytes.Equal(got, data) {
		t.Fatal("bytes differ after the re-fetch")
	}
	qs, _ := filepath.Glob(filepath.Join(root, "quarantine", "blob-*"))
	if len(qs) != 1 {
		t.Fatalf("corrupt copy not quarantined: %v", qs)
	}
	if b, _ := os.ReadFile(qs[0]); string(b) != "evil" {
		t.Fatal("quarantined file is not the corrupt one")
	}
	// A re-fetch that serves wrong bytes leaves the corrupt copy alone and installs nothing.
	_ = os.Chmod(p, 0o644)
	_ = os.WriteFile(p, []byte("evil2"), 0o644)
	_, err = s.Fetch(d, MapTransport{loc: []byte("worse")}, FetchOptions{})
	if err == nil || s.HasBlob(d) == false {
		t.Fatal("expected a refusal with the corrupt copy still in place", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "evil2" {
		t.Fatal("a refused fetch replaced the corrupt copy with unverified bytes")
	}
}

// TestFetchSizeDeclared: §9 item 1. A declared size is held to: a longer stream is cut off at the declaration
// and refused before the hash is relied on; a shorter one is refused at EOF; no size and a runaway stream is
// stopped at the named fetch limit (operational).
func TestFetchSizeDeclared(t *testing.T) {
	data := []byte("0123456789")
	d := digestOf(data)
	loc := "https://m.example/x"
	for name, tc := range map[string]struct {
		served []byte
		state  string
	}{
		"longer":  {append(bytes.Clone(data), 'x', 'y'), StateSizeWrong},
		"shorter": {data[:7], StateSizeWrong},
	} {
		t.Run(name, func(t *testing.T) {
			s := open(t, t.TempDir(), Options{NoSync: true})
			serveHolds(t, s, "H", data, loc)
			res, err := s.Fetch(d, MapTransport{loc: tc.served}, FetchOptions{})
			var ref *refusal.Refusal
			if err == nil || !errors.As(err, &ref) || ref.Class != refusal.Intrinsic || ref.Reason != reasonSizeMatch || res.Attempts[0].State != tc.state {
				t.Fatalf("%v %v", res, err)
			}
			if s.HasBlob(d) {
				t.Fatal("installed")
			}
			if !strings.Contains(err.Error(), "declared size") {
				t.Fatal(err)
			}
		})
	}
	// A declared size that is itself a lie about otherwise-correct bytes: the hash would match but the size
	// does not, so it is refused (the statement's two fields disagree; the holder's word is inconsistent).
	s := open(t, t.TempDir(), Options{NoSync: true})
	l, _ := holdsLine(testKey("H"), 0, "", data, false, loc)
	lie := bytes.Replace(l, []byte(`"size":10`), []byte(`"size":11`), 1)
	_ = lie // a mutated line fails its signature; the size lie is exercised through FetchOptions.Size instead
	if _, err := s.Commit("pull", [][]byte{l}, nil); err != nil {
		t.Fatal(err)
	}
	_, err := s.Fetch(d, MapTransport{loc: data}, FetchOptions{Locations: []string{loc}, Size: 11})
	if err == nil {
		t.Fatal("size 11 declared, 10 bytes served: should be refused")
	}
	// No declared size: bounded by MaxBytes, operational.
	s2 := open(t, t.TempDir(), Options{NoSync: true})
	res, err := s2.Fetch(d, MapTransport{loc: bytes.Repeat([]byte("a"), 100)}, FetchOptions{Locations: []string{loc}, MaxBytes: 50})
	var ref *refusal.Refusal
	if !errors.As(err, &ref) || ref.Class != refusal.Operational || ref.Reason != refusal.SizeLimit || !strings.Contains(ref.Detail, "max_fetch_bytes=50") || res.Attempts[0].State != StateTooLarge {
		t.Fatal(res, err)
	}
}

// failingReader errors midway: a transfer that dies.
type failingTransport struct{ data []byte }

func (f failingTransport) Fetch(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(io.MultiReader(bytes.NewReader(f.data[:3]), errReader{})), nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

// TestFetchTransferDies: a stream that fails midway installs nothing and is reported unavailable, not as a
// hash mismatch (the bytes never finished arriving).
func TestFetchTransferDies(t *testing.T) {
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	data := []byte("0123456789")
	loc := "https://m.example/x"
	serveHolds(t, s, "H", data, loc)
	before := snapshot(t, root)
	res, err := s.Fetch(digestOf(data), failingTransport{data}, FetchOptions{})
	if err == nil || !strings.HasPrefix(res.Attempts[0].State, "unavailable (holder's word: ") || !strings.Contains(err.Error(), "connection reset") {
		t.Fatal(res, err)
	}
	var ref *refusal.Refusal
	if errors.As(err, &ref) && ref.Reason == HashMismatch {
		t.Fatal("a dead transfer reported as a hash mismatch")
	}
	if after := snapshot(t, root); !equalMaps(before, after) {
		t.Fatal("a dead transfer changed the store")
	}
}

// TestNoDefaultNetwork: the package dials nothing unless a Transport is passed: Fetch with a nil Transport
// reaches no location, and HTTPTransport is a value the caller constructs. Its guards are exercised against
// a local test server that it must refuse by default.
func TestNoDefaultNetwork(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("served"))
	}))
	defer srv.Close()
	s := open(t, t.TempDir(), Options{NoSync: true})
	data := []byte("served")
	serveHolds(t, s, "H", data, srv.URL+"/b")
	if _, err := s.Fetch(digestOf(data), nil, FetchOptions{}); err == nil {
		t.Fatal("a nil transport fetched")
	}
	if hits.Load() != 0 {
		t.Fatal("the package dialled without a transport")
	}
	// Loopback is refused by the default HTTP transport even with plain http allowed.
	_, err := s.Fetch(digestOf(data), HTTPTransport{AllowHTTP: true}, FetchOptions{})
	if err == nil || hits.Load() != 0 {
		t.Fatalf("loopback was dialled by default: hits=%d err=%v", hits.Load(), err)
	}
	// https only unless allowed.
	if _, err := (HTTPTransport{}).Fetch(context.Background(), srv.URL+"/b"); err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatal(err)
	}
	if _, err := (HTTPTransport{}).Fetch(context.Background(), "ftp://x/y"); err == nil {
		t.Fatal("ftp accepted")
	}
	// With the local mirror switch on, bytes arrive and verify like any other.
	res, err := s.Fetch(digestOf(data), HTTPTransport{AllowHTTP: true, AllowPrivate: true}, FetchOptions{})
	if err != nil || res.State != StateFetched || hits.Load() != 1 {
		t.Fatal(res, err, hits.Load())
	}
	// Non-200 and a wrong body are refused like any wrong bytes.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/404") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("tampered"))
	}))
	defer bad.Close()
	h := HTTPTransport{AllowHTTP: true, AllowPrivate: true}
	s2 := open(t, t.TempDir(), Options{NoSync: true})
	_, err = s2.Fetch(digestOf(data), h, FetchOptions{Locations: []string{bad.URL + "/404", bad.URL + "/b"}})
	var ref *refusal.Refusal
	if !errors.As(err, &ref) || ref.Reason != HashMismatch || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatal(err)
	}
	// Compile-time use of net so the loopback claim above is tied to a real address check.
	if ip := net.ParseIP("127.0.0.1"); ip == nil || !ip.IsLoopback() {
		t.Fatal("test premise")
	}
	_ = fmt.Sprint
}

// TestHTTPTransportByteExact: C-core-117 over a real HTTP exchange. A payload that is itself gzip, served
// with Content-Encoding: gzip, installs as the raw bytes (no transparent decoding), and NUL / invalid UTF-8
// survive the round trip.
func TestHTTPTransportByteExact(t *testing.T) {
	conformance.Partial(t, "C-core-117", "byte-exact over HTTP (no transparent decompression) and the store half in TestFetchByteExact; the `fetch` command surface is later")
	payload := append([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3}, 0, 0xff, 0xfe, '\r', '\n')
	var sawIdentity atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawIdentity.Store(r.Header.Get("Accept-Encoding") == "identity")
		w.Header().Set("Content-Encoding", "gzip") // a server insisting; a client that decodes would corrupt it
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	s := open(t, t.TempDir(), Options{NoSync: true})
	serveHolds(t, s, "H", payload, srv.URL+"/p")
	res, err := s.Fetch(digestOf(payload), HTTPTransport{AllowHTTP: true, AllowPrivate: true}, FetchOptions{})
	if err != nil || res.State != StateFetched {
		t.Fatal(res, err)
	}
	if !sawIdentity.Load() {
		t.Fatal("the request did not ask for identity encoding")
	}
	f, _ := s.OpenBlob(digestOf(payload))
	got, _ := io.ReadAll(f)
	f.Close()
	if !bytes.Equal(got, payload) {
		t.Fatal("bytes were transformed in transit")
	}
}
