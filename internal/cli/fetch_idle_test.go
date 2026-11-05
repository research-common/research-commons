package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/store"
)

func realTransport(c FetchConfig) store.Transport {
	return store.HTTPTransport{AllowHTTP: c.AllowHTTP, AllowPrivate: c.AllowPrivate, Timeout: c.Timeout, IdleTimeout: c.IdleTimeout}
}

// TestFetchIdleTimeout: the idle bound is measured on body progress. A server that sends half the body and then
// stalls past --idle-timeout fails the location (exit 3, nothing installed, the detail names idle_timeout); a
// server that never sends headers does the same; a server that trickles bytes, each within the idle bound, for
// far longer than the idle bound succeeds; and --timeout, when given, still caps the whole location.
func TestFetchIdleTimeout(t *testing.T) {
	data := []byte(strings.Repeat("0123456789", 10))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		switch r.URL.Path {
		case "/stall":
			w.Header().Set("Content-Length", "100")
			w.Write(data[:50])
			fl.Flush()
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		case "/noheaders":
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		case "/trickle": // 20 chunks, 50ms apart = 1s total, each gap well inside the 400ms idle bound
			for i := 0; i < len(data); i += 5 {
				w.Write(data[i : i+5])
				fl.Flush()
				time.Sleep(50 * time.Millisecond)
			}
		}
	}))
	defer srv.Close()
	d := shaB(data)
	run := func(path string, extra ...string) (result, *world) {
		w := newWorld(t)
		w.holds("H", "K1", data, len(data), srv.URL+path)
		args := append([]string{"fetch", d, "--allow-http", "--allow-private", "--json"}, extra...)
		return runFetch(w.root, realTransportFetcher, args...), w
	}

	for _, p := range []string{"/stall", "/noheaders"} {
		start := time.Now()
		r, w := run(p, "--idle-timeout", "300ms")
		if r.code != 3 || time.Since(start) > 5*time.Second || !strings.Contains(r.stdout, "idle_timeout") {
			t.Fatalf("%s: exit %d after %v\n%s", p, r.code, time.Since(start), r.stdout)
		}
		if w.s.HasBlob(store.Digest(d)) {
			t.Fatalf("%s: a stalled transfer installed a blob", p)
		}
	}

	start := time.Now()
	r, w := run("/trickle", "--idle-timeout", "400ms")
	if r.code != 0 || !w.s.HasBlob(store.Digest(d)) || time.Since(start) < 900*time.Millisecond {
		t.Fatalf("trickle within the idle bound: exit %d after %v\n%s", r.code, time.Since(start), r.stdout)
	}

	// the overall cap still applies to a transfer that makes progress
	r, w = run("/trickle", "--idle-timeout", "400ms", "--timeout", "300ms")
	if r.code != 3 || w.s.HasBlob(store.Digest(d)) {
		t.Fatalf("overall cap on a progressing transfer: exit %d\n%s", r.code, r.stdout)
	}
}

var realTransportFetcher Fetcher = realTransport

// TestFetchTimeoutDisclosure: the dry-run limits object names both bounds; the overall cap reads `none` when unset.
func TestFetchTimeoutDisclosure(t *testing.T) {
	data := []byte("x")
	w := newWorld(t)
	w.holds("H", "K1", data, len(data), "https://a.example/x")
	r := runFetch(w.root, realTransportFetcher, "fetch", shaB(data), "--dry-run", "--json")
	if !strings.Contains(r.stdout, `"timeout_per_location":"none"`) || !strings.Contains(r.stdout, `"idle_timeout":"1m0s"`) {
		t.Fatalf("default disclosure: %s", r.stdout)
	}
	r = runFetch(w.root, realTransportFetcher, "fetch", shaB(data), "--dry-run", "--json", "--timeout", "30m", "--idle-timeout", "5s")
	if !strings.Contains(r.stdout, `"timeout_per_location":"30m0s"`) || !strings.Contains(r.stdout, `"idle_timeout":"5s"`) {
		t.Fatalf("explicit disclosure: %s", r.stdout)
	}
}
