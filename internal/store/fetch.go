package store

// External holds and fetch (storage note §9; claims-model §11 "byte-exact transport", "a download location is
// a hint").
//
// A `holds` statement may name locations. Those are the holder's word: this package never dereferences one
// except through a Transport the caller passes in, and no Transport is installed by default (the package
// dials nothing on its own). Fetch runs the install path of §2 with the statement's hash as the expectation,
// so the hash of the bytes actually written is the only thing that makes them a blob; a location that serves
// other bytes is refused (intrinsic, scoped to that fetch) and the next one is tried. Fetching never signs a
// `holds` of one's own (holding bytes and asserting that one serves them are different acts).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/research-common/research-commons/internal/refusal"
)

// Transport fetches the bytes behind one location. It returns a stream, not a verdict: the caller verifies.
// A location the transport cannot or will not reach (unsupported scheme, unreachable, refused, a stream that
// dies midway) is an error; the caller reports it as unavailable and tries the next location.
type Transport interface {
	Fetch(ctx context.Context, location string) (io.ReadCloser, error)
}

// DefaultMaxFetchBytes bounds a fetch that has no declared size (a documented limit, named in the refusal).
const DefaultMaxFetchBytes = 1 << 30

// Availability states, the vocabulary a command prints.
const (
	StateHeld        = "held locally (verified)"
	StateFetched     = "fetched-and-verified"
	StateNotHeld     = "unavailable (not held locally)"
	StateMismatch    = "unavailable (hash mismatch)"
	StateSizeWrong   = "unavailable (size mismatch)"
	StateTooLarge    = "unavailable (size limit)"
	StateCorrupt     = "stored copy corrupt"
	reasonSizeMatch  = "size mismatch"
	reasonFetchLimit = refusal.SizeLimit
)

// Holder is one key's current serving `holds` for a blob: what that key said, not a fact.
type Holder struct {
	Signer      string
	StatementID string
	Locations   []string
	// Size is the declared content.size, or -1.
	Size int64
}

// Availability is what the store can say about a blob before any fetch (C-core-119).
type Availability struct {
	Blob  Digest
	State string // StateHeld, StateCorrupt or StateNotHeld
	// Holders are the current serving holds of every key, in statement-id order. Every location in them is
	// the holder's word until a fetch verifies bytes.
	Holders []Holder
}

// Render is the text a command prints before fetching: the local state and, for each holder, "holder's
// word", never a claim that the bytes are there.
func (a Availability) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n", a.Blob, a.State)
	for _, h := range a.Holders {
		if len(h.Locations) == 0 {
			fmt.Fprintf(&b, "  holder's word: %s says it serves these bytes (statement %s), names no location\n", h.Signer, h.StatementID)
			continue
		}
		for _, l := range h.Locations {
			fmt.Fprintf(&b, "  holder's word: %s says it is at %s (statement %s); not fetched, not verified\n", h.Signer, l, h.StatementID)
		}
	}
	return b.String()
}

// Availability reports the local state of d and every current serving hold of it, without touching the
// network. A corrupt local copy is reported as such, never as held.
func (s *Store) Availability(d Digest) (Availability, error) {
	a := Availability{Blob: d, State: StateNotHeld}
	if _, ok := d.hex(); !ok {
		return a, refusal.Malformed("digest %q is not sha256: + 64 lowercase hex", d)
	}
	if s.HasBlob(d) {
		f, err := s.CheckBlob(d)
		if err != nil {
			return a, err
		}
		a.State = StateHeld
		if f != nil {
			a.State = StateCorrupt + " (" + f.Detail + ")"
		}
	}
	hs, err := s.servingHolds(d)
	if err != nil {
		return a, err
	}
	for _, h := range hs {
		a.Holders = append(a.Holders, Holder{Signer: h.signer, StatementID: h.id, Locations: h.locations, Size: h.size})
	}
	return a, nil
}

// servingHolds returns the current serving `holds` of every key for d, sorted by statement id.
func (s *Store) servingHolds(d Digest) ([]holdsEntry, error) {
	ri := s.newRefIndex(nil)
	if err := ri.refresh(); err != nil {
		return nil, err
	}
	hs := slices.Clone(ri.serving()[d])
	slices.SortFunc(hs, func(a, b holdsEntry) int { return strings.Compare(a.id, b.id) })
	return hs, nil
}

// FetchOptions configure a fetch.
type FetchOptions struct {
	Context context.Context
	// Locations, when set, are tried instead of the holders' (an explicit `--from`); the hash is still the only
	// authority. They are tried in the order given.
	Locations []string
	// Size is the expected size when no holder declares one; 0 means unknown.
	Size int64
	// MaxBytes bounds a fetch with no declared size; 0 means DefaultMaxFetchBytes.
	MaxBytes int64
	// Force fetches even when an intact local copy exists.
	Force bool
}

// Attempt is one location tried.
type Attempt struct {
	Location string
	// State is StateFetched, StateMismatch, StateSizeWrong, StateTooLarge or the holder's-word line
	// "unavailable (holder's word: <location>)".
	State string
	// Err is the refusal or transport error; nil when fetched.
	Err error
	// Holder names whose word the location was (statement id), "" for an explicit location.
	Holder string
}

// FetchResult is the outcome of one blob's fetch.
type FetchResult struct {
	Blob  Digest
	State string // StateHeld, StateFetched, or the last failure's state
	// Reinstalled is true when a corrupt local copy was replaced (the old one is in quarantine).
	Reinstalled bool
	Attempts    []Attempt
	Install     BlobResult
}

// FetchFailure is returned when no location produced the verified bytes. It unwraps to every attempt's
// error, so errors.As finds the intrinsic hash-mismatch refusal when a location served wrong bytes.
type FetchFailure struct {
	Blob     Digest
	Attempts []Attempt
	// Corrupt is true when a corrupt local copy was found first (and, with no source, left in place).
	Corrupt bool
}

func (e *FetchFailure) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "blob %s: not fetched", e.Blob)
	if e.Corrupt {
		b.WriteString("; the stored copy is corrupt and was not used")
	}
	if len(e.Attempts) == 0 {
		b.WriteString("; no hold names a location (unavailable (not held locally))")
	}
	for _, a := range e.Attempts {
		fmt.Fprintf(&b, "; %s: %s", a.Location, a.State)
		if a.Err != nil {
			fmt.Fprintf(&b, " (%v)", a.Err)
		}
	}
	return b.String()
}

func (e *FetchFailure) Unwrap() []error {
	var out []error
	for _, a := range e.Attempts {
		if a.Err != nil {
			out = append(out, a.Err)
		}
	}
	return out
}

// Fetch makes d a held, verified blob. An intact local copy is reused without touching the network (unless
// Force). A corrupt one is not reused: it is detected before use (C-core-123) and a fetch replaces it,
// moving the corrupt file to quarantine; with no location to fetch from the corrupt copy is left in place
// and the error says so. Each location is tried in order; the bytes of each are streamed through the
// exact-bytes install, so nothing is installed unless the whole hash matches, and a declared size is held
// to before the hash is relied on.
func (s *Store) Fetch(d Digest, tr Transport, opt FetchOptions) (*FetchResult, error) {
	if _, ok := d.hex(); !ok {
		return nil, refusal.Malformed("digest %q is not sha256: + 64 lowercase hex", d)
	}
	res := &FetchResult{Blob: d}
	corrupt := false
	if s.HasBlob(d) {
		f, err := s.CheckBlob(d)
		if err != nil {
			return res, err
		}
		if f == nil && !opt.Force {
			res.State = StateHeld
			return res, nil
		}
		corrupt = f != nil
	}
	type loc struct {
		url, holder string
		size        int64
	}
	var locs []loc
	if len(opt.Locations) > 0 {
		for _, l := range opt.Locations {
			locs = append(locs, loc{l, "", opt.Size})
		}
	} else {
		hs, err := s.servingHolds(d)
		if err != nil {
			return res, err
		}
		seen := map[string]bool{}
		for _, h := range hs {
			for _, l := range h.locations {
				if seen[l] {
					continue
				}
				seen[l] = true
				size := h.size
				if size < 0 {
					size = opt.Size
				}
				locs = append(locs, loc{l, h.id, size})
			}
		}
	}
	if tr == nil {
		return res, &FetchFailure{Blob: d, Corrupt: corrupt, Attempts: nil}
	}
	ctx := opt.Context
	if ctx == nil {
		ctx = context.Background()
	}
	max := opt.MaxBytes
	if max <= 0 {
		max = DefaultMaxFetchBytes
	}
	for _, l := range locs {
		a := Attempt{Location: l.url, Holder: l.holder}
		rc, err := tr.Fetch(ctx, l.url)
		if err != nil {
			a.State, a.Err = "unavailable (holder's word: "+l.url+")", err
			res.Attempts = append(res.Attempts, a)
			continue
		}
		vr := &verifyingReader{rc: rc, want: l.size, max: max}
		got, inst, ierr := s.InstallBlob(vr, d)
		rc.Close()
		switch {
		case ierr == nil:
			a.State = StateFetched
			res.Attempts = append(res.Attempts, a)
			res.State, res.Install = StateFetched, inst
			res.Reinstalled = inst == Replaced
			_ = got
			return res, nil
		case vr.sizeErr != nil:
			a.State, a.Err = vr.sizeState, &refusal.Refusal{Class: vr.sizeClass, Reason: vr.sizeReason,
				Detail: fmt.Sprintf("fetch of %s from %s: %s; nothing installed", d, l.url, vr.sizeErr)}
		default:
			var r *refusal.Refusal
			if errors.As(ierr, &r) && r.Reason == HashMismatch {
				a.State = StateMismatch
				a.Err = &refusal.Refusal{Class: r.Class, Reason: r.Reason,
					Detail: fmt.Sprintf("fetch of %s from %s: %s", d, l.url, r.Detail)}
			} else if vr.readErr != nil {
				a.State, a.Err = "unavailable (holder's word: "+l.url+")", fmt.Errorf("transfer failed midway: %w", vr.readErr)
			} else {
				return res, ierr // a store-side failure (disk, permissions) is not the location's fault
			}
		}
		res.Attempts = append(res.Attempts, a)
	}
	if len(res.Attempts) > 0 {
		res.State = res.Attempts[len(res.Attempts)-1].State
	} else {
		res.State = StateNotHeld
	}
	return res, &FetchFailure{Blob: d, Attempts: res.Attempts, Corrupt: corrupt}
}

// verifyingReader enforces the declared size on the stream before the install's hash decision: more bytes
// than declared cut the stream off at the declaration; fewer is refused at EOF. It records which, so the
// caller can name it.
type verifyingReader struct {
	rc   io.Reader
	want int64 // declared size, or 0 for unknown
	max  int64 // bound when want is 0
	n    int64

	sizeErr               error
	sizeClass             refusal.Class
	sizeReason, sizeState string
	readErr               error
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	if v.sizeErr != nil {
		return 0, v.sizeErr
	}
	limit := v.max
	if v.want > 0 {
		limit = v.want
	}
	// Allow one byte past the limit so an overlong stream is seen, but never hand it to the install.
	room := limit - v.n + 1
	if int64(len(p)) > room {
		p = p[:room]
	}
	n, err := v.rc.Read(p)
	if v.n+int64(n) > limit {
		keep := int(limit - v.n)
		v.n = limit + 1
		if v.want > 0 {
			v.sizeClass, v.sizeReason, v.sizeState = refusal.Intrinsic, reasonSizeMatch, StateSizeWrong
			v.sizeErr = fmt.Errorf("the stream runs past the declared size of %d bytes and was cut off there", v.want)
		} else {
			v.sizeClass, v.sizeReason, v.sizeState = refusal.Operational, reasonFetchLimit, StateTooLarge
			v.sizeErr = fmt.Errorf("the stream runs past the fetch limit max_fetch_bytes=%d (no size was declared)", v.max)
		}
		return keep, v.sizeErr
	}
	v.n += int64(n)
	if err == io.EOF && v.want > 0 && v.n != v.want {
		v.sizeClass, v.sizeReason, v.sizeState = refusal.Intrinsic, reasonSizeMatch, StateSizeWrong
		v.sizeErr = fmt.Errorf("delivered %d bytes, the declared size is %d", v.n, v.want)
		return n, v.sizeErr
	}
	if err != nil && err != io.EOF {
		v.readErr = err
	}
	return n, err
}

// FetchAll fetches several blobs (the inputs of an artifact) and reports each as fetched-and-verified or
// unavailable with the holder's word, never aggregating into "complete" (C-core-120). A failure of one
// blob does not stop the others.
func (s *Store) FetchAll(ds []Digest, tr Transport, opt FetchOptions) []*FetchResult {
	var out []*FetchResult
	for _, d := range ds {
		r, err := s.Fetch(d, tr, opt)
		if r == nil {
			r = &FetchResult{Blob: d, State: "refused"}
		}
		if err != nil && r.State == "" {
			r.State = "refused: " + err.Error()
		}
		out = append(out, r)
	}
	return out
}

// RenderFetch is the per-input listing: one line per blob and one per failed location, and a final line that
// scopes the claim to what is held.
func RenderFetch(rs []*FetchResult) string {
	var b strings.Builder
	held := 0
	for _, r := range rs {
		fmt.Fprintf(&b, "%s: %s\n", r.Blob, r.State)
		if r.State == StateHeld || r.State == StateFetched {
			held++
		}
		for _, a := range r.Attempts {
			if a.Err != nil {
				fmt.Fprintf(&b, "  %s: %s\n", a.Location, a.State)
			}
		}
	}
	fmt.Fprintf(&b, "%d of %d input(s) held and verified; anything derived from them is scoped to those, with no completeness claim\n", held, len(rs))
	return b.String()
}

// ---------------------------------------------------------------------------------------------------------
// Transports the caller may construct. None is used unless passed to Fetch.

// MapTransport serves locations from memory (tests, and callers that stage downloads themselves). A location
// absent from the map is unreachable.
type MapTransport map[string][]byte

// Fetch implements Transport.
func (m MapTransport) Fetch(_ context.Context, location string) (io.ReadCloser, error) {
	b, ok := m[location]
	if !ok {
		return nil, fmt.Errorf("%s: unreachable", location)
	}
	return io.NopCloser(strings.NewReader(string(b))), nil
}

// HTTPTransport fetches https locations (http only with AllowHTTP). It is a plain byte transfer: no
// decompression is applied on top of what the server sends as the body (Accept-Encoding is identity), no
// cookies, at most three redirects, none of which may leave https unless AllowHTTP is set. By default it
// refuses to connect to loopback, private, link-local and unspecified addresses, checked at connect time on
// the address actually dialled; AllowPrivate lifts that for a local mirror. Nothing here is used unless the
// caller passes the transport to Fetch.
type HTTPTransport struct {
	AllowHTTP    bool
	AllowPrivate bool
	// Client overrides the HTTP client (its Transport's dialing then is the caller's responsibility).
	Client *http.Client
	// Timeout bounds one request, zero means 60 s.
	Timeout time.Duration
}

func (h HTTPTransport) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	if !h.AllowPrivate {
		d.Control = func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
				return fmt.Errorf("refusing to connect to %s: loopback, private and link-local addresses are not fetched from by default", host)
			}
			return nil
		}
	}
	to := h.Timeout
	if to == 0 {
		to = 60 * time.Second
	}
	return &http.Client{
		Timeout:   to,
		Transport: &http.Transport{DialContext: d.DialContext, DisableCompression: true, Proxy: nil, TLSHandshakeTimeout: 15 * time.Second},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects (limit 3)")
			}
			if req.URL.Scheme != "https" && !h.AllowHTTP {
				return errors.New("redirect to a non-https location refused")
			}
			return nil
		},
	}
}

// Fetch implements Transport.
func (h HTTPTransport) Fetch(ctx context.Context, location string) (io.ReadCloser, error) {
	u, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("%s: not an RFC 3986 URI: %w", location, err)
	}
	if u.Scheme != "https" && !(h.AllowHTTP && u.Scheme == "http") {
		return nil, fmt.Errorf("%s: scheme %q is not fetched by this transport", location, u.Scheme)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := h.client().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: HTTP %d", location, resp.StatusCode)
	}
	return resp.Body, nil
}
