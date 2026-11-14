// Package otscal is an OpenTimestamps calendar client: the network half of stamping (bitcoin-time note §2 steps
// 3–4). It submits a stamped digest to a calendar and returns the calendar's pending proof as a complete
// `ots-detached-v1` file, checked by the profile's own parser before it is returned.
//
// It is the only package that dials a calendar. Nothing here runs unless the binary wires a Client into the
// command line (cmd/commons does, for `anchor stamp`); the command package and the bitcoin-time package import no
// network code. The dial rules are fetch's (internal/store): https only, no proxy, loopback, private, link-local,
// shared and other non-global addresses refused at connect time unless AllowPrivate names a local calendar or
// mirror, at most three redirects and only to https on the same host, a bounded response.
//
// A calendar's answer is untrusted (bitcoin-time note §3): it is parsed under the profile's limits, must root at
// the digest submitted and must carry at least one pending attestation; anything else is that calendar's
// failure, named, and nothing of it is kept. A pending proof grants nothing: it is the calendar's promise, and a
// reader shows it `pending`.
package otscal

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/store"
)

// MaxResponseBytes bounds a calendar's response body, as the reference client does (10 000 bytes). A longer
// response is the calendar's failure.
const MaxResponseBytes = 10000

// DefaultTimeout bounds one calendar's whole request (connect, TLS, response and body) when Config.Timeout is
// zero.
const DefaultTimeout = 10 * time.Second

// MediaType is the Accept header the OpenTimestamps calendar protocol uses.
const MediaType = "application/vnd.opentimestamps.v1"

// UserAgent names the tool to a calendar.
const UserAgent = "research-commons-otscal/1"

// Config is the author's choice for one stamping invocation.
type Config struct {
	// AllowPrivate lifts the refusal to connect to non-global addresses (a local calendar or mirror).
	AllowPrivate bool
	// Timeout bounds one calendar's whole request; zero means DefaultTimeout.
	Timeout time.Duration
	// RootCAs, when set, replaces the system roots (a test calendar's certificate); the dial and redirect rules are
	// unchanged.
	RootCAs *x509.CertPool
}

// Client submits to one calendar. It implements btctime.Calendar.
type Client struct {
	base string
	cfg  Config
}

// New returns a client for the calendar at base (an absolute https URL; a trailing slash is dropped). It refuses
// any other URL before anything is dialled.
func New(base string, cfg Config) (*Client, error) {
	if err := CheckURL(base); err != nil {
		return nil, err
	}
	return &Client{base: strings.TrimRight(base, "/"), cfg: cfg}, nil
}

// CheckURL reports whether base can name a calendar: an absolute https URL with a host, no user information,
// query or fragment.
func CheckURL(base string) error {
	u, err := url.Parse(base)
	switch {
	case err != nil:
		return fmt.Errorf("not an RFC 3986 URI: %v", err)
	case u.Scheme != "https":
		return fmt.Errorf("scheme %q: a calendar is reached over https only", u.Scheme)
	case u.Host == "" || u.Hostname() == "":
		return errors.New("no host")
	case u.User != nil:
		return errors.New("user information in a calendar URL is not sent")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return errors.New("a calendar URL carries no query or fragment")
	}
	return nil
}

// URI implements btctime.Calendar: the calendar URL as configured (without a trailing slash), the value recorded
// in the anchors statement's services.
func (c *Client) URI() string { return c.base }

func (c *Client) client() *http.Client {
	host := ""
	if u, err := url.Parse(c.base); err == nil {
		host = u.Host
	}
	timeout := c.cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	tr := &http.Transport{DialContext: store.GuardedDialer(c.cfg.AllowPrivate).DialContext, Proxy: nil, DisableCompression: true,
		TLSHandshakeTimeout: 15 * time.Second}
	if c.cfg.RootCAs != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: c.cfg.RootCAs, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects (limit 3)")
			}
			if req.URL.Scheme != "https" || req.URL.Host != host {
				return errors.New("redirect to " + req.URL.Scheme + "://" + req.URL.Host + " refused: a calendar may redirect only to https on its own host")
			}
			return nil
		},
	}
}

// Submit implements btctime.Calendar: POST <base>/digest with the 32 raw bytes, and the pending proof as a
// complete `ots-detached-v1` file (header, version, the sha256 file-hash operation, the digest, then the
// calendar's timestamp). The file is parsed with the profile's parser and must root at d and carry a pending
// attestation; otherwise the error says why and no bytes are returned.
func (c *Client) Submit(d [32]byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.base+"/digest", bytes.NewReader(d[:]))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", MediaType)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading the response: %w", err)
	}
	if len(body) > MaxResponseBytes {
		return nil, fmt.Errorf("response over %d bytes", MaxResponseBytes)
	}
	return Assemble(d, body)
}

// Assemble builds the detached proof file for digest d from a calendar's timestamp bytes and checks it: it must
// parse under the profile's default limits, root at d, and carry at least one pending attestation.
func Assemble(d [32]byte, timestamp []byte) ([]byte, error) {
	if len(timestamp) == 0 {
		return nil, errors.New("empty response")
	}
	// the protocol answers a bare timestamp; a complete file in its place is not one, and if it roots elsewhere it
	// is a proof for another digest (never re-rooted or kept)
	if bytes.HasPrefix(timestamp, btctime.HeaderMagic) {
		if p, err := btctime.ParseProof(timestamp, btctime.DefaultLimits()); err == nil && p.FileDigest != d {
			return nil, fmt.Errorf("the response is a proof rooted at another digest (%x), not a timestamp for the digest submitted", p.FileDigest[:])
		}
		return nil, errors.New("the response is a complete proof file, not the bare timestamp the calendar protocol answers")
	}
	f := make([]byte, 0, len(btctime.HeaderMagic)+2+32+len(timestamp))
	f = append(f, btctime.HeaderMagic...)
	f = append(f, 0x01, 0x08) // major version 1; file-hash operation sha256
	f = append(f, d[:]...)
	f = append(f, timestamp...)
	p, err := btctime.ParseProof(f, btctime.DefaultLimits())
	if err != nil {
		return nil, fmt.Errorf("the response is not a timestamp for the digest submitted: %v", err)
	}
	// unreachable while the root is the one written above; kept so a change to how the file is built cannot return a
	// proof for another digest
	if p.FileDigest != d {
		return nil, errors.New("the proof roots at another digest")
	}
	if p.PendingCount == 0 {
		return nil, errors.New("the response carries no pending attestation")
	}
	return f, nil
}
