package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/store"
)

// fetch tests: every network path runs over loopback (httptest) only.

func shaB(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// runFetch runs one invocation with a transport factory wired, as the binary wires its own.
func runFetch(root string, f Fetcher, args ...string) result {
	var o, e bytes.Buffer
	code := Main(args, &Env{Stdout: &o, Stderr: &e, Getenv: func(string) string { return "" },
		Getwd: func() (string, error) { return root, nil }, Build: Build{Version: "test", Commit: "0000000"}, Fetch: f})
	return result{code, o.String(), e.String()}
}

// countingTransport records every location it is asked to dial.
type countingTransport struct {
	inner store.Transport
	n     *atomic.Int64
	seen  *[]string
}

func (c countingTransport) Fetch(ctx context.Context, loc string) (io.ReadCloser, error) {
	c.n.Add(1)
	*c.seen = append(*c.seen, loc)
	return c.inner.Fetch(ctx, loc)
}

func counting(inner store.Transport) (Fetcher, *atomic.Int64, *[]string) {
	n := &atomic.Int64{}
	seen := &[]string{}
	return func(FetchConfig) store.Transport { return countingTransport{inner, n, seen} }, n, seen
}

// holds signs a holds by key n for bytes b at locs, declaring the size unless size < 0.
func (w *world) holds(name, n string, b []byte, size int, locs ...string) string {
	c := obj("digest", shaB(b), "size", len(b))
	if size >= 0 && size != len(b) {
		c = obj("digest", shaB(b), "size", size)
	}
	body := obj("content", c)
	if len(locs) > 0 {
		body = obj("content", c, "locations", locs)
	}
	return w.sign(name, n, "holds", body)
}

func fetchRows(t *testing.T, r result) []*canon.Object {
	t.Helper()
	var out []*canon.Object
	for _, x := range jsonOf(t, r).Members["blobs"].(canon.Array) {
		out = append(out, x.(*canon.Object))
	}
	return out
}

func stateOf(o *canon.Object) string { s, _ := o.Members["state"].(canon.String); return string(s) }

func attemptsOf(o *canon.Object) []*canon.Object {
	var out []*canon.Object
	a, _ := o.Members["attempts"].(canon.Array)
	for _, x := range a {
		out = append(out, x.(*canon.Object))
	}
	return out
}

func blobBytes(t *testing.T, root, d string) []byte {
	t.Helper()
	return mustRead(t, filepath.Join(root, "blobs", "sha256", strings.TrimPrefix(d, "sha256:")))
}

// TestFetchBinaryOverHTTP: #64 as a regression through the command and a real HTTP transport on loopback, and
// C-core-117's command half. Payloads holding NUL, invalid UTF-8, CRLF only, every byte value, and nothing at all
// are served by a TLS server and by a plain one; every installed blob equals the served bytes exactly and hashes
// to its name. The server sends Content-Encoding gzip on one of them without compressing: the transport must not
// decode it (the body is the bytes). The statements directory is unchanged: fetch publishes no holds.
func TestFetchBinaryOverHTTP(t *testing.T) {
	conformance.Partial(t, "C-core-117", "the fetch command installs NUL, invalid UTF-8, CRLF-only, all-byte-values and empty payloads byte-exact over https and http on loopback; the one-byte-different refusal through the command is TestFetchMismatchExits")
	every := make([]byte, 256)
	for i := range every {
		every[i] = byte(i)
	}
	payloads := map[string][]byte{"nul": {0, 0, 'a', 0}, "utf8": {0xff, 0xfe, 0xc3, 0x28}, "crlf": []byte("\r\n\r\n"), "every": every, "empty": {}}
	mux := http.NewServeMux()
	for name, b := range payloads {
		b := b
		mux.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Accept-Encoding") != "identity" {
				http.Error(w, "want identity", 400)
				return
			}
			if len(b) == 4 && b[0] == 0 {
				w.Header().Set("Content-Encoding", "gzip") // a lie: the body is not gzip, and must arrive untouched
			}
			w.Write(b)
		})
	}
	tlsSrv := httptest.NewTLSServer(mux)
	defer tlsSrv.Close()
	plain := httptest.NewServer(mux)
	defer plain.Close()

	for _, mode := range []string{"https", "http"} {
		w := newWorld(t)
		var args []string
		for name, b := range payloads {
			base := tlsSrv.URL
			if mode == "http" {
				base = plain.URL
			}
			w.holds("H:"+name, "K1", b, len(b), base+"/"+name)
			args = append(args, shaB(b))
		}
		stmts := snapshot(t, filepath.Join(w.root, "statements"))
		var f Fetcher
		extra := []string{"--allow-private"}
		if mode == "https" {
			// the test server's certificate is trusted only by its own client; the scheme and timeout gates of the
			// command still sit in front of it
			f = func(c FetchConfig) store.Transport {
				return store.HTTPTransport{Client: tlsSrv.Client(), AllowHTTP: c.AllowHTTP, Timeout: c.Timeout, IdleTimeout: c.IdleTimeout}
			}
		} else {
			f = func(c FetchConfig) store.Transport {
				return store.HTTPTransport{AllowHTTP: c.AllowHTTP, AllowPrivate: c.AllowPrivate, Timeout: c.Timeout, IdleTimeout: c.IdleTimeout}
			}
			extra = append(extra, "--allow-http")
		}
		r := runFetch(w.root, f, append(append([]string{"fetch", "--json"}, extra...), args...)...)
		if r.code != 0 {
			t.Fatalf("%s: exit %d\n%s", mode, r.code, r.stdout)
		}
		for _, row := range fetchRows(t, r) {
			if stateOf(row) != store.StateFetched {
				t.Fatalf("%s: %s", mode, canon.Encode(row))
			}
		}
		for name, b := range payloads {
			if got := blobBytes(t, w.root, shaB(b)); !bytes.Equal(got, b) || shaB(got) != shaB(b) {
				t.Fatalf("%s %s: installed %x, served %x", mode, name, got, b)
			}
		}
		if snapshot(t, filepath.Join(w.root, "statements")) != stmts {
			t.Fatalf("%s: fetch changed the statements directory (published something)", mode)
		}
		// a second fetch dials nothing: every blob is held and re-hashed intact
		f2, n, _ := counting(store.MapTransport{})
		if r := runFetch(w.root, f2, append([]string{"fetch", "--json"}, args...)...); r.code != 0 || n.Load() != 0 {
			t.Fatalf("%s: refetch of held blobs: exit %d, dialled %d", mode, r.code, n.Load())
		}
	}
}

// TestFetchNetworkDefaults: the opt-ins. Without --allow-private a loopback server is refused at connect time
// (the address actually dialled), reported as the holder's word, exit 3, nothing installed; without
// --allow-http a plain http location is refused before the transport sees it; file: and ipfs: locations are
// refused before dialling under every flag. A server that stalls past --timeout is unavailable, exit 3.
func TestFetchNetworkDefaults(t *testing.T) {
	data := []byte("loopback bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
			return
		}
		w.Write(data)
	}))
	defer srv.Close()
	real := func(c FetchConfig) store.Transport {
		return store.HTTPTransport{AllowHTTP: c.AllowHTTP, AllowPrivate: c.AllowPrivate, Timeout: c.Timeout, IdleTimeout: c.IdleTimeout}
	}
	w := newWorld(t)
	w.holds("H", "K1", data, len(data), srv.URL+"/x")
	d := shaB(data)

	r := runFetch(w.root, real, "fetch", d, "--allow-http", "--json")
	rows := fetchRows(t, r)
	if r.code != 3 || stateOf(rows[0]) != "unavailable (holder's word)" || !strings.Contains(r.stdout, "refusing to connect") {
		t.Fatalf("loopback without --allow-private: %d %s", r.code, r.stdout)
	}
	if w.s.HasBlob(store.Digest(d)) {
		t.Fatal("installed after a refused dial")
	}

	f, n, _ := counting(store.MapTransport{})
	r = runFetch(w.root, f, "fetch", d, "--allow-private", "--json")
	if r.code != 3 || stateOf(fetchRows(t, r)[0]) != "unavailable (scheme not fetched)" || n.Load() != 0 {
		t.Fatalf("http without --allow-http: exit %d, dialled %d\n%s", r.code, n.Load(), r.stdout)
	}

	w2 := newWorld(t)
	w2.holds("H", "K1", data, len(data), "file:///etc/passwd", "ipfs://bafyexample", "/relative/path")
	f, n, _ = counting(store.MapTransport{"file:///etc/passwd": data, "ipfs://bafyexample": data, "/relative/path": data})
	r = runFetch(w2.root, f, "fetch", d, "--allow-http", "--allow-private", "--json")
	if r.code != 3 || n.Load() != 0 || w2.s.HasBlob(store.Digest(d)) {
		t.Fatalf("file:/ipfs:/relative: exit %d, dialled %d\n%s", r.code, n.Load(), r.stdout)
	}
	for _, a := range attemptsOf(fetchRows(t, r)[0]) {
		if stateOf(a) != "unavailable (scheme not fetched)" {
			t.Fatalf("%s", canon.Encode(a))
		}
	}

	w3 := newWorld(t)
	w3.holds("H", "K1", data, len(data), srv.URL+"/slow")
	start := time.Now()
	r = runFetch(w3.root, real, "fetch", d, "--allow-http", "--allow-private", "--timeout", "200ms", "--json")
	if r.code != 3 || time.Since(start) > 4*time.Second || stateOf(fetchRows(t, r)[0]) != "unavailable (holder's word)" {
		t.Fatalf("timeout: exit %d after %v\n%s", r.code, time.Since(start), r.stdout)
	}

	// the opt-ins together: fetched, exit 0
	r = runFetch(w.root, real, "fetch", d, "--allow-http", "--allow-private", "--json")
	if r.code != 0 || !bytes.Equal(blobBytes(t, w.root, d), data) {
		t.Fatalf("with both opt-ins: %d %s", r.code, r.stdout)
	}
}

// TestFetchMismatchExits: the exit rule. A blob whose only location serves other bytes is refused (intrinsic,
// hash mismatch, both hashes and the location named), nothing installed, exit 1. A wrong location followed by
// a good one: the mismatch is reported, the blob is fetched, exit 0. A declared size not met: size mismatch,
// exit 1. A declared size over --max-bytes: refused before dialling, exit 3. A held statement id fetches the
// blob it names; an id not held is exit 3. Mixed (one refused, one unreachable): 1 wins.
func TestFetchMismatchExits(t *testing.T) {
	good, bad := []byte("the right bytes"), []byte("the wrong bytes")
	w := newWorld(t)
	w.holds("H1", "K1", good, len(good), "https://a.example/x")
	stmts := snapshot(t, filepath.Join(w.root, "statements"))
	d := shaB(good)
	f, _, _ := counting(store.MapTransport{"https://a.example/x": bad})
	r := runFetch(w.root, f, "fetch", d, "--json")
	row := fetchRows(t, r)[0]
	at := attemptsOf(row)
	det := string(at[0].Members["detail"].(canon.String))
	if r.code != 1 || stateOf(row) != store.StateMismatch || at[0].Members["class"] != canon.String("intrinsic") ||
		!strings.Contains(det, d) || !strings.Contains(det, shaB(bad)) || !strings.Contains(det, "https://a.example/x") {
		t.Fatalf("mismatch: %d %s", r.code, r.stdout)
	}
	if w.s.HasBlob(store.Digest(d)) || w.s.HasBlob(store.Digest(shaB(bad))) {
		t.Fatal("bytes installed on a mismatch")
	}
	// the human surface says the same
	if h := runFetch(w.root, f, "fetch", d); h.code != 1 || !strings.Contains(h.stdout, store.StateMismatch) {
		t.Fatalf("human: %d %s", h.code, h.stdout)
	}

	// a second holds naming the wrong location first and a good one after: the mismatch is reported, exit 0
	// (locations are tried in statement-id order, then in the order a holds lists them)
	w.holds("H2", "K2", good, len(good), "https://a.example/x", "https://b.example/x")
	f, _, _ = counting(store.MapTransport{"https://a.example/x": bad, "https://b.example/x": good})
	r = runFetch(w.root, f, "fetch", d, "--json")
	row = fetchRows(t, r)[0]
	states := []string{}
	for _, a := range attemptsOf(row) {
		states = append(states, stateOf(a))
	}
	if r.code != 0 || stateOf(row) != store.StateFetched || !strings.Contains(strings.Join(states, ","), store.StateMismatch) {
		t.Fatalf("superseded mismatch: %d %v %s", r.code, states, r.stdout)
	}
	if snapshot(t, filepath.Join(w.root, "statements")) == stmts {
		t.Fatal("control: the H2 holds should be the only statements change")
	}
	stmts = snapshot(t, filepath.Join(w.root, "statements"))
	if r := runFetch(w.root, f, "fetch", d, "--json"); r.code != 0 || snapshot(t, filepath.Join(w.root, "statements")) != stmts {
		t.Fatal("a fetch changed the statements directory")
	}

	// size: a short stream against a declared size; a declared size over the limit is never dialled
	w2 := newWorld(t)
	short := []byte("short")
	w2.holds("H", "K1", short, len(short), "https://c.example/s")
	f, _, _ = counting(store.MapTransport{"https://c.example/s": short[:3]})
	if r := runFetch(w2.root, f, "fetch", shaB(short), "--json"); r.code != 1 || stateOf(fetchRows(t, r)[0]) != store.StateSizeWrong {
		t.Fatalf("size mismatch: %d %s", r.code, r.stdout)
	}
	f, n, _ := counting(store.MapTransport{"https://c.example/s": short})
	if r := runFetch(w2.root, f, "fetch", shaB(short), "--max-bytes", "4", "--json"); r.code != 3 || n.Load() != 0 ||
		stateOf(fetchRows(t, r)[0]) != store.StateTooLarge || !strings.Contains(r.stdout, "max_fetch_bytes=4") {
		t.Fatalf("limit: exit %d, dialled %d\n%s", r.code, n.Load(), r.stdout)
	}

	// an id: an authored statement's content; an id not held
	w3 := newWorld(t)
	w3.blob("x", []byte("x"))
	id := w3.authored("A", "K1", "x")
	os.Remove(filepath.Join(w3.root, "blobs", "sha256", strings.TrimPrefix(dig("x"), "sha256:")))
	w3.sign("H", "K1", "holds", obj("content", content("x"), "locations", []string{"https://d.example/x"}))
	f, _, _ = counting(store.MapTransport{"https://d.example/x": []byte("x")})
	r = runFetch(w3.root, f, "fetch", id, "--json")
	if row := fetchRows(t, r)[0]; r.code != 0 || stateOf(row) != store.StateFetched || row.Members["digest"] != canon.String(dig("x")) {
		t.Fatalf("by id: %d %s", r.code, r.stdout)
	}
	if r := runFetch(w3.root, f, "fetch", strings.Repeat("ab", 32), "--json"); r.code != 3 || stateOf(fetchRows(t, r)[0]) != "no statement held" {
		t.Fatalf("id not held: %d %s", r.code, r.stdout)
	}

	// mixed: one refused on a completed mismatch, one with no location: 1
	w.holds("H3", "K3", bad, len(bad)) // a holds naming no location
	f, _, _ = counting(store.MapTransport{"https://a.example/x": bad})
	w4 := newWorld(t)
	w4.holds("H1", "K1", good, len(good), "https://a.example/x")
	w4.holds("H3", "K3", bad, len(bad))
	r = runFetch(w4.root, f, "fetch", d, shaB(bad), "--json")
	rows := fetchRows(t, r)
	if r.code != 1 || stateOf(rows[0]) != store.StateMismatch || stateOf(rows[1]) != store.StateNotHeld {
		t.Fatalf("mixed: %d %s", r.code, r.stdout)
	}
}

// TestFetchNoTransport: a build with no transport dials nothing: a held blob is 0, anything else exit 3 with
// `unavailable (no transport in this build)` and the holder's locations listed, never fetched.
func TestFetchNoTransport(t *testing.T) {
	w := newWorld(t)
	w.blob("x", []byte("x"))
	data := []byte("elsewhere")
	w.holds("H", "K1", data, len(data), "https://e.example/y")
	if r := w.run("fetch", dig("x"), "--json"); r.code != 0 || stateOf(fetchRows(t, r)[0]) != "held here" {
		t.Fatalf("held: %d %s", r.code, r.stdout)
	}
	r := w.run("fetch", dig("x"), shaB(data), "--json")
	rows := fetchRows(t, r)
	if r.code != 3 || stateOf(rows[1]) != "unavailable (no transport in this build)" || !strings.Contains(r.stdout, "https://e.example/y") {
		t.Fatalf("no transport: %d %s", r.code, r.stdout)
	}
	// a blob no holds names a location for: unavailable (not held locally), with or without a transport
	if r := w.run("fetch", dig("nobody"), "--json"); r.code != 3 || stateOf(fetchRows(t, r)[0]) != store.StateNotHeld {
		t.Fatalf("no location: %d %s", r.code, r.stdout)
	}
	// a nil transport from the factory is the same as none
	if r := runFetch(w.root, func(FetchConfig) store.Transport { return nil }, "fetch", shaB(data), "--json"); r.code != 3 {
		t.Fatalf("nil factory: %d", r.code)
	}
}

// TestFetchCorruptReplaced: C-core-123's command half. A held blob whose file no longer hashes to its name is not
// reused: fetch reports the corrupt copy, replaces it with verified bytes from a holds, and moves the corrupt
// file to quarantine; with no location it is reported and left in place, exit 3.
func TestFetchCorruptReplaced(t *testing.T) {
	w := newWorld(t)
	data := []byte("intact")
	d := w.blob("v", data)
	p := filepath.Join(w.root, "blobs", "sha256", strings.TrimPrefix(d, "sha256:"))
	os.Chmod(p, 0o644)
	os.WriteFile(p, []byte("rotten"), 0o444)
	f, _, _ := counting(store.MapTransport{})
	r := runFetch(w.root, f, "fetch", d, "--json")
	if row := fetchRows(t, r)[0]; r.code != 3 || row.Members["local_copy"] != canon.String("stored copy corrupt") {
		t.Fatalf("corrupt, no location: %d %s", r.code, r.stdout)
	}
	if !bytes.Equal(mustRead(t, p), []byte("rotten")) {
		t.Fatal("the corrupt copy was touched with nothing to replace it")
	}
	w.holds("H", "K1", data, len(data), "https://f.example/v")
	f, _, _ = counting(store.MapTransport{"https://f.example/v": data})
	r = runFetch(w.root, f, "fetch", d, "--json")
	if row := fetchRows(t, r)[0]; r.code != 0 || stateOf(row) != store.StateFetched || row.Members["local_copy"] != canon.String("stored copy corrupt") {
		t.Fatalf("corrupt, refetched: %d %s", r.code, r.stdout)
	}
	if !bytes.Equal(mustRead(t, p), data) || !strings.Contains(r.stdout, "quarantine") {
		t.Fatalf("not replaced: %s", r.stdout)
	}
	q, _ := os.ReadDir(filepath.Join(w.root, "quarantine"))
	if len(q) == 0 {
		t.Fatal("nothing quarantined")
	}
}

// TestFetchDryRun: C-core-137's fetch half. fetch --dry-run over a store with a blob it would fetch, a corrupt
// copy it would replace (and quarantine), a location refused by scheme and one by size: it prints the plan and
// its side effects (which name the network, the cache and the quarantine, unlike pull's), dials nothing, and a
// before/after snapshot of the root is identical. pull --dry-run's declaration differs.
func TestFetchDryRun(t *testing.T) {
	conformance.Covers(t, "C-core-137")
	w := newWorld(t)
	far := []byte("far away")
	w.holds("H", "K1", far, len(far), "https://g.example/far", "ftp://g.example/far")
	big := []byte("too big for the limit")
	w.holds("H2", "K2", big, len(big), "https://g.example/big")
	data := []byte("intact")
	d := w.blob("v", data)
	p := filepath.Join(w.root, "blobs", "sha256", strings.TrimPrefix(d, "sha256:"))
	os.Chmod(p, 0o644)
	os.WriteFile(p, []byte("rotten"), 0o444)
	w.holds("H3", "K3", data, len(data), "https://g.example/v")
	before := snapshot(t, w.root)
	f, n, _ := counting(store.MapTransport{"https://g.example/far": far, "https://g.example/v": data, "https://g.example/big": big})
	r := runFetch(w.root, f, "fetch", "--dry-run", "--max-bytes", "10", shaB(far), shaB(big), d, "--json")
	if r.code != 0 || n.Load() != 0 || snapshot(t, w.root) != before {
		t.Fatalf("dry run: exit %d, dialled %d, changed %v\n%s", r.code, n.Load(), snapshot(t, w.root) != before, r.stdout)
	}
	o := jsonOf(t, r)
	se := string(o.Members["side_effects"].(canon.String))
	if se != fetchSideEffects || se == pullSideEffects || !strings.Contains(se, "no quarantine") || !strings.Contains(se, "nothing dialled") {
		t.Fatalf("side effects: %q", se)
	}
	rows := fetchRows(t, r)
	var got []string
	for _, row := range rows {
		got = append(got, stateOf(row))
		for _, a := range attemptsOf(row) {
			got = append(got, "  "+stateOf(a))
		}
	}
	want := []string{"would fetch (dry run)", "  would fetch (dry run)", "  unavailable (scheme not fetched)",
		"unavailable (size limit)", "  unavailable (size limit)",
		"would fetch (dry run)", "  would fetch (dry run)"}
	if strings.Join(got, "|") != strings.Join(want, "|") || rows[2].Members["local_copy"] != canon.String("stored copy corrupt") {
		t.Fatalf("plan:\n%s\nwant\n%s\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"), r.stdout)
	}
	// the same plan with no transport in the build says so, and still exits 0
	if r := w.run("fetch", "--dry-run", shaB(far), "--json"); r.code != 0 || stateOf(fetchRows(t, r)[0]) != "unavailable (no transport in this build)" {
		t.Fatalf("dry run, no transport: %d %s", r.code, r.stdout)
	}
}

// TestFetchInputsScopedToWhatIsHeld: C-core-120 through the commands. A synthesis whose three inputs are held only
// as external `holds`, one location reachable, one dead, one naming none: `fetch` lists each input as
// fetched-and-verified or unavailable (the holder's word, or not held locally) and says the result is scoped to
// what is held with no completeness claim; the derived result's own show/verify/explain print the scope footer
// and every inputs-summary line scoped "within statements you hold"; no surface says the inputs are complete.
func TestFetchInputsScopedToWhatIsHeld(t *testing.T) {
	conformance.Covers(t, "C-core-120")
	w := newWorld(t)
	w.blob("wf", []byte("wf"))
	w.workflow("K1", "wf", "bytes", "")
	w.holds("H:in0", "K3", []byte("in0"), 3, "https://h.example/in0")
	w.holds("H:in1", "K3", []byte("in1"), 3, "https://h.example/in1-dead")
	w.holds("H:in2", "K3", []byte("in2"), 3) // the holder's word only: no location
	w.blob("syn", []byte("syn"))
	w.authored("S", "K1", "syn", "type", "synthesis", "prov", []string{"wf", "in0", "in1", "in2"})
	f, _, _ := counting(store.MapTransport{"https://h.example/in0": []byte("in0")})
	r := runFetch(w.root, f, "fetch", shaB([]byte("in0")), shaB([]byte("in1")), shaB([]byte("in2")), "--json")
	rows := fetchRows(t, r)
	got := []string{stateOf(rows[0]), stateOf(rows[1]), stateOf(rows[2])}
	if r.code != 3 || got[0] != store.StateFetched || !strings.HasPrefix(got[1], "unavailable (holder's word") || got[2] != store.StateNotHeld {
		t.Fatalf("per-input states %v exit %d\n%s", got, r.code, r.stdout)
	}
	sum := string(jsonOf(t, r).Members["summary"].(canon.String))
	if !strings.Contains(sum, "1 of 3") || !strings.Contains(sum, "no completeness claim") {
		t.Fatalf("fetch summary: %q", sum)
	}
	d := dig("syn")
	for _, cmd := range []string{"show", "verify", "explain"} {
		o := w.run(cmd, d)
		if !strings.HasSuffix(o.stdout, "status scope: within statements you hold\n") {
			t.Fatalf("%s lacks the scope footer:\n%s", cmd, o.stdout)
		}
		for _, bad := range []string{"complete", "all inputs"} {
			if strings.Contains(strings.ReplaceAll(o.stdout, "no completeness claim", ""), bad) {
				t.Fatalf("%s makes a completeness claim (%q):\n%s", cmd, bad, o.stdout)
			}
		}
	}
	for _, line := range strings.Split(w.run("show", d).stdout, "\n") {
		if strings.Contains(line, "inputs summary:") && !strings.Contains(line, "within statements you hold") {
			t.Fatalf("inputs summary not scoped: %s", line)
		}
	}
}

// TestFetchHintThroughCommand: C-core-118 and C-core-119 through the commands. Two `holds` for one blob, the first
// location serving wrong bytes, the second the right ones. Before any fetch, show says the bytes are not held
// here and lists both holders (their word, nothing authenticated); fetch refuses the wrong bytes (hash mismatch,
// intrinsic), takes the second, and the blob is then held and verified, equal to a local one (show: held here);
// with only the lying location the hold is labelled unavailable (hash mismatch), the blob stays not held and the
// store is unchanged.
func TestFetchHintThroughCommand(t *testing.T) {
	conformance.Covers(t, "C-core-118", "C-core-119")
	good, bad := []byte("the real dataset bytes"), []byte("the evil dataset bytes")
	d := shaB(good)
	w := newWorld(t)
	h1 := w.holds("H1", "K1", good, len(good), "https://liar.example/blob")
	h2 := w.holds("H2", "K2", good, len(good), "https://honest.example/blob")
	before := w.run("show", d).stdout
	if !strings.Contains(before, "bytes: not held here") || !strings.Contains(before, w.signer("K1")) || !strings.Contains(before, w.signer("K2")) {
		t.Fatalf("before the fetch:\n%s", before)
	}
	// only the liar: refused, labelled, nothing installed
	w1 := newWorld(t)
	w1.holds("H1", "K1", good, len(good), "https://liar.example/blob")
	snap := snapshot(t, filepath.Join(w1.root, "blobs"))
	f, _, _ := counting(store.MapTransport{"https://liar.example/blob": bad})
	r := runFetch(w1.root, f, "fetch", d, "--json")
	row := fetchRows(t, r)[0]
	if r.code != 1 || stateOf(row) != store.StateMismatch || attemptsOf(row)[0].Members["class"] != canon.String("intrinsic") ||
		snapshot(t, filepath.Join(w1.root, "blobs")) != snap {
		t.Fatalf("liar only: %d %s", r.code, r.stdout)
	}
	if !strings.Contains(w1.run("show", d).stdout, "bytes: not held here") {
		t.Fatal("a refused fetch left the blob held")
	}
	// both: the liar is tried and refused, the honest one serves
	// locations are tried in statement-id order (TestFetchMismatchExits), so the liar is whichever holds sorts first
	liar, honest := "https://liar.example/blob", "https://honest.example/blob"
	if h2 < h1 {
		liar, honest = honest, liar
	}
	f, _, seen := counting(store.MapTransport{liar: bad, honest: good})
	r = runFetch(w.root, f, "fetch", d, "--json")
	row = fetchRows(t, r)[0]
	states := []string{}
	for _, a := range attemptsOf(row) {
		states = append(states, stateOf(a))
	}
	if r.code != 0 || stateOf(row) != store.StateFetched || len(states) != 2 || states[0] != store.StateMismatch || states[1] != store.StateFetched {
		t.Fatalf("both locations: %d %v (asked %v)\n%s", r.code, states, *seen, r.stdout)
	}
	if !bytes.Equal(blobBytes(t, w.root, d), good) {
		t.Fatal("the installed bytes are not the verified ones")
	}
	after := w.run("show", d).stdout
	if !strings.Contains(after, "bytes: held here") || !strings.Contains(after, w.signer("K1")) {
		t.Fatalf("after the fetch:\n%s", after)
	}
}
