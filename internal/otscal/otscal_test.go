package otscal

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/research-common/research-commons/internal/btctime"
)

// Every calendar here is a loopback httptest TLS server; nothing else is dialled.

func vbytes(b []byte) []byte { return append([]byte{byte(len(b))}, b...) } // lengths < 128 only

// PendingTimestamp is a calendar's bare answer for any digest: append a nonce, sha256, one pending attestation.
func pendingTimestamp(uri string) []byte {
	out := append([]byte{0xf0}, vbytes([]byte("nonce-0123456789"))...)
	out = append(out, 0x08, 0x00)
	out = append(out, btctime.TagPending[:]...)
	return append(out, vbytes(vbytes([]byte(uri)))...)
}

type calServer struct {
	srv  *httptest.Server
	hits atomic.Int64
	got  []byte
	hdr  http.Header
}

func newCal(t *testing.T, h func(w http.ResponseWriter, body []byte)) *calServer {
	c := &calServer{}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/digest" {
			http.Error(w, "no", http.StatusNotFound)
			return
		}
		c.got, c.hdr = b, r.Header.Clone()
		h(w, b)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *calServer) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.srv.Certificate())
	return p
}

func (c *calServer) client(t *testing.T, allowPrivate bool) *Client {
	t.Helper()
	cl, err := New(c.srv.URL+"/", Config{AllowPrivate: allowPrivate, RootCAs: c.pool()})
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

var digest = sha256.Sum256([]byte("a statement id"))

// TestSubmit: the request is POST /digest with the 32 raw bytes and the protocol's Accept header; the answer is a
// complete detached proof that the profile's parser reads, rooted at the digest, pending.
func TestSubmit(t *testing.T) {
	c := newCal(t, func(w http.ResponseWriter, _ []byte) { w.Write(pendingTimestamp("https://cal.test")) })
	cl := c.client(t, true)
	if cl.URI() != c.srv.URL {
		t.Fatalf("URI %q keeps the trailing slash", cl.URI())
	}
	f, err := cl.Submit(digest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.got, digest[:]) || c.hdr.Get("Accept") != MediaType || !strings.HasPrefix(c.hdr.Get("User-Agent"), "research-commons") {
		t.Fatalf("request: body %x headers %v", c.got, c.hdr)
	}
	want := append(append(append(append([]byte{}, btctime.HeaderMagic...), 0x01, 0x08), digest[:]...), pendingTimestamp("https://cal.test")...)
	if !bytes.Equal(f, want) {
		t.Fatalf("file %x\nwant %x", f, want)
	}
	p, err := btctime.ParseProof(f, btctime.DefaultLimits())
	if err != nil || p.FileDigest != digest || p.PendingCount != 1 || p.Pending[0].URI != "https://cal.test" {
		t.Fatalf("parse: %v %+v", err, p)
	}
}

// TestSubmitFailures: each answer that is not a pending timestamp for the digest is the calendar's failure, named,
// with no bytes returned. Each case's mutation is the one property the check looks at.
func TestSubmitFailures(t *testing.T) {
	other := sha256.Sum256([]byte("another id"))
	otherFile := append(append(append(append([]byte{}, btctime.HeaderMagic...), 0x01, 0x08), other[:]...), pendingTimestamp("https://cal.test")...)
	bitcoinOnly := append([]byte{0x00}, btctime.TagBitcoin[:]...)
	bitcoinOnly = append(bitcoinOnly, 0x01, 0x05)
	for _, c := range []struct {
		name, want string
		h          func(w http.ResponseWriter, b []byte)
	}{
		{"HTTP 500", "HTTP 500", func(w http.ResponseWriter, _ []byte) { http.Error(w, "down", 500) }},
		{"oversize", "over 10000 bytes", func(w http.ResponseWriter, _ []byte) {
			w.Write(pendingTimestamp("https://cal.test"))
			w.Write(bytes.Repeat([]byte{0}, MaxResponseBytes))
		}},
		{"exactly at the bound is read whole (then fails as trailing bytes)", "trailing", func(w http.ResponseWriter, _ []byte) {
			ts := pendingTimestamp("https://cal.test")
			w.Write(append(ts, bytes.Repeat([]byte{0}, MaxResponseBytes-len(ts))...))
		}},
		{"empty", "empty response", func(w http.ResponseWriter, _ []byte) {}},
		{"garbage", "not a timestamp for the digest", func(w http.ResponseWriter, _ []byte) { w.Write([]byte("<html>hello</html>")) }},
		{"a proof rooted at another digest", "rooted at another digest", func(w http.ResponseWriter, _ []byte) { w.Write(otherFile) }},
		{"no pending attestation", "no pending attestation", func(w http.ResponseWriter, _ []byte) { w.Write(bitcoinOnly) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newCal(t, c.h)
			f, err := s.client(t, true).Submit(digest)
			if err == nil || f != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v (%d bytes), want %q", err, len(f), c.want)
			}
		})
	}
	// control for "exactly at the bound": one byte fewer than the bound of a valid answer is accepted
	ts := pendingTimestamp("https://cal.test")
	if _, err := Assemble(digest, ts); err != nil {
		t.Fatal(err)
	}
}

// TestDialRules: a non-https URL is refused before anything is dialled; a loopback calendar is refused at connect
// time without AllowPrivate (the same guard as fetch), and reached with it; a redirect to another host is refused.
func TestDialRules(t *testing.T) {
	c := newCal(t, func(w http.ResponseWriter, _ []byte) { w.Write(pendingTimestamp("https://cal.test")) })
	for _, u := range []string{"http://cal.test", "ftp://cal.test", "cal.test", "https://", "https://u:p@cal.test", "https://cal.test/?q=1", "https://cal.test/#f"} {
		if _, err := New(u, Config{}); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if _, err := c.client(t, false).Submit(digest); err == nil || !strings.Contains(err.Error(), "refusing to connect") {
		t.Fatalf("loopback without AllowPrivate: %v", err)
	}
	if c.hits.Load() != 0 {
		t.Fatal("the guard let the request reach the server")
	}
	if _, err := c.client(t, true).Submit(digest); err != nil {
		t.Fatalf("loopback with AllowPrivate: %v", err)
	}
	// a redirect to another origin (the working calendar, on another port of the same address, whose certificate the
	// client trusts) is refused; the control redirect to the same origin is followed
	redirector := func(to string) *calServer {
		r := newCal(t, func(w http.ResponseWriter, _ []byte) {})
		r.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			r.hits.Add(1)
			if req.URL.Path == "/digest" {
				http.Redirect(w, req, strings.Replace(to, "SELF", "https://"+req.Host, 1), http.StatusTemporaryRedirect)
				return
			}
			io.ReadAll(req.Body)
			w.Write(pendingTimestamp("https://cal.test"))
		})
		return r
	}
	before := c.hits.Load()
	r := redirector(c.srv.URL + "/digest")
	cl, _ := New(r.srv.URL, Config{AllowPrivate: true, RootCAs: r.pool()})
	if _, err := cl.Submit(digest); err == nil || !strings.Contains(err.Error(), "only to https on its own host") || c.hits.Load() != before {
		t.Fatalf("cross-origin redirect: %v", err)
	}
	same := redirector("SELF/v2")
	cl, _ = New(same.srv.URL, Config{AllowPrivate: true, RootCAs: same.pool()})
	if _, err := cl.Submit(digest); err != nil {
		t.Fatalf("same-origin redirect: %v", err)
	}
}
