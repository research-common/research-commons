package otscal

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/research-common/research-commons/internal/btctime"
)

// upgradeCal is a loopback calendar answering GET /timestamp/<hex> with h.
type upgradeCal struct {
	srv    *httptest.Server
	hits   atomic.Int64
	method string
	path   string
	hdr    http.Header
}

func newUpgradeCal(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *upgradeCal {
	c := &upgradeCal{}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		c.method, c.path, c.hdr = r.Method, r.URL.Path, r.Header.Clone()
		h(w, r)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *upgradeCal) client(t *testing.T, allowPrivate bool) *Client {
	t.Helper()
	cs := &calServer{srv: c.srv}
	cl, err := New(c.srv.URL+"/", Config{AllowPrivate: allowPrivate, RootCAs: cs.pool()})
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

var commitment = []byte{0xAB, 0xCD, 0x01, 0x02}

// bitcoinAnswer is a bare completed timestamp: sha256 then a Bitcoin attestation at height 5.
func bitcoinAnswer() []byte {
	out := []byte{0x08, 0x00}
	out = append(out, btctime.TagBitcoin[:]...)
	return append(out, 0x01, 0x05)
}

// TestUpgrade: the request is GET /timestamp/<lowercase hex> with the protocol's Accept header; 200 returns the
// body unchanged; 404 is ErrPending, not a failure.
func TestUpgrade(t *testing.T) {
	c := newUpgradeCal(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/timestamp/abcd0102" {
			http.NotFound(w, r)
			return
		}
		w.Write(bitcoinAnswer())
	})
	body, err := c.client(t, true).Upgrade(commitment)
	if err != nil {
		t.Fatal(err)
	}
	if c.method != http.MethodGet || c.path != "/timestamp/abcd0102" || c.hdr.Get("Accept") != MediaType || !strings.HasPrefix(c.hdr.Get("User-Agent"), "research-commons") {
		t.Fatalf("request %s %s %v", c.method, c.path, c.hdr)
	}
	if !bytes.Equal(body, bitcoinAnswer()) {
		t.Fatalf("body %x", body)
	}
	// another commitment: the calendar answers 404, which is "still pending"
	if _, err := c.client(t, true).Upgrade([]byte{0x01}); !errors.Is(err, ErrPending) {
		t.Fatalf("404: %v, want ErrPending", err)
	}
}

// TestUpgradeFailures: every other status, an oversize or empty body, and the dial rules are the calendar's
// failure, named; none is ErrPending.
func TestUpgradeFailures(t *testing.T) {
	for _, c := range []struct {
		name, want string
		h          func(w http.ResponseWriter, r *http.Request)
	}{
		{"HTTP 500", "HTTP 500", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "down", 500) }},
		{"HTTP 400", "HTTP 400", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "bad", 400) }},
		{"oversize", "over 10000 bytes", func(w http.ResponseWriter, _ *http.Request) {
			w.Write(bytes.Repeat([]byte{0}, btctime.MaxUpgradeBytes+1))
		}},
		{"empty", "empty response", func(w http.ResponseWriter, _ *http.Request) {}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newUpgradeCal(t, c.h)
			b, err := s.client(t, true).Upgrade(commitment)
			if err == nil || b != nil || errors.Is(err, ErrPending) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v (%d bytes), want %q", err, len(b), c.want)
			}
		})
	}
	// exactly at the bound is returned whole (Merge judges it)
	s := newUpgradeCal(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(bytes.Repeat([]byte{0}, btctime.MaxUpgradeBytes))
	})
	if b, err := s.client(t, true).Upgrade(commitment); err != nil || len(b) != btctime.MaxUpgradeBytes {
		t.Fatalf("at the bound: %v %d", err, len(b))
	}
	// dial guard: loopback refused at connect time without AllowPrivate, before any request reaches the server
	g := newUpgradeCal(t, func(w http.ResponseWriter, _ *http.Request) { w.Write(bitcoinAnswer()) })
	if _, err := g.client(t, false).Upgrade(commitment); err == nil || !strings.Contains(err.Error(), "refusing to connect") || g.hits.Load() != 0 {
		t.Fatalf("loopback without AllowPrivate: %v (hits %d)", err, g.hits.Load())
	}
	// redirect to another origin refused
	r := newUpgradeCal(t, func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, g.srv.URL+req.URL.Path, http.StatusTemporaryRedirect)
	})
	before := g.hits.Load()
	if _, err := r.client(t, true).Upgrade(commitment); err == nil || !strings.Contains(err.Error(), "only to https on its own host") || g.hits.Load() != before {
		t.Fatalf("cross-origin redirect: %v", err)
	}
	if _, err := g.client(t, true).Upgrade(nil); err == nil {
		t.Fatal("empty commitment accepted")
	}
}
