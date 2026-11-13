package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// fetch <digest|id>…: obtain blobs from the locations named by the `holds` statements this store holds (storage
// note §9; claims-model note §11 "byte-exact transport", "a download location is a hint"). Each blob goes
// through the store's exact-bytes install with the hash as the expectation: a declared size is held to before
// the hash is relied on, a location that serves other bytes is refused (intrinsic, both hashes and the
// location named, nothing installed) and the next location is tried, and an unreachable location is the
// holder's word, reported as such. Fetching never signs or commits anything: holding bytes and asserting that
// one serves them are different acts, so no `holds` is published.
//
// Invoking fetch is the reader's opt-in to dial. This package dials nothing: the transport comes from the
// binary (Env.Fetch), as the re-run bridge does. Only https is fetched by default (--allow-http adds http),
// loopback, private, link-local, shared (RFC 6598) and other non-global addresses are refused unless --allow-private names a local mirror, and
// every other scheme (file:, ipfs:, …) is refused before dialling: local copies are admitted through pull.

// FetchConfig is the reader's choice for one fetch invocation, passed to the transport factory.
type FetchConfig struct {
	AllowHTTP, AllowPrivate bool
	// Timeout is an optional cap on one whole location (connecting, response and body); zero means none.
	Timeout time.Duration
	// IdleTimeout bounds how long one location may make no progress (header wait, or between body bytes).
	IdleTimeout time.Duration
}

// Fetcher builds the transport a fetch dials through. The binary supplies one; tests supply fakes or a real
// transport over loopback. Nil in a build without network access: fetch then answers from what is held.
type Fetcher func(FetchConfig) store.Transport

// DefaultFetchIdleTimeout is the idle bound when --idle-timeout is not given (a documented limit).
const DefaultFetchIdleTimeout = 60 * time.Second

func init() {
	Register(&Command{Name: "fetch", Summary: "obtain blobs from the locations held `holds` statements name, verified by full hash; never publishes a holds",
		Args: []Arg{{Name: "digest|id", Shape: ShapeRef, Variadic: true}},
		Flags: []Flag{
			{Name: "allow-http", Help: "also fetch plain http locations (default: https only)"},
			{Name: "allow-private", Help: "allow loopback, private, link-local, shared (100.64.0.0/10) and other non-global addresses (a local mirror); refused by default, checked on the address actually dialled"},
			{Name: "idle-timeout", Value: "duration", Help: "give up on a location that makes no progress for this long: no response headers, or no body bytes (Go duration, e.g. 30s, 5m); default 60s. Connecting and the TLS handshake keep a fixed 15s bound", Check: positiveDuration},
			{Name: "timeout", Value: "duration", Help: "optional cap on one whole location, however much progress it makes (Go duration, e.g. 30m); default none (the idle timeout and max-bytes bound a transfer)", Check: positiveDuration},
			{Name: "max-bytes", Value: "n", Help: "the fetch limit max_fetch_bytes: a location whose declared size exceeds it is refused before dialling, and a stream with no declared size is cut off past it (default 1073741824)",
				Check: func(v string) error {
					if n, err := strconv.ParseInt(v, 10, 64); err != nil || n <= 0 {
						return errors.New("a positive number of bytes")
					}
					return nil
				}},
			{Name: "dry-run", Help: "print what would be fetched from where; dial nothing, install nothing (no fetch; no cache; no quarantine; no registry change)"},
		},
		Store: true,
		Help: "Each argument is a blob digest, or the id of a held statement whose content is fetched. A blob already held and intact is not fetched again; a corrupt held copy is replaced by a verified one (the corrupt file goes to quarantine). " +
			"Only https locations are fetched, and http with --allow-http; content-addressed networks (ipfs:), object-store schemes and file: are not fetched: admit a local copy with pull. The transport uses no proxy. " +
			"Exit 0 every blob is held and verified (a location that served wrong bytes before another served the right ones is reported, and still 0); 1 a blob was refused on a completed hash or size mismatch and no location served it; " +
			"3 a blob was not obtained without such a refusal (unreachable, no location named, a fetch limit, a scheme not fetched, no transport in this build, the statement not held); 2 did not start. A dry run exits 0 once the plan is made.",
		Run: fetchCmd})
}

func positiveDuration(v string) error {
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return errors.New("a positive duration such as 30s or 5m")
	}
	return nil
}

// fetchSideEffects is the dry run's declaration (claims-model note §13, C-core-137): unlike pull's, it names the
// network and the quarantine, because a real fetch dials and may move a corrupt copy aside.
const fetchSideEffects = "nothing dialled; no blob installed; no cache; no quarantine; no statement signed; no registry change"

// schemeErr is a location refused before dialling because of its scheme.
type schemeErr struct{ scheme string }

func (e schemeErr) Error() string {
	if e.scheme == "" {
		return "not an absolute URI with a scheme; refused before dialling"
	}
	return "scheme " + strconv.Quote(e.scheme) + " is not fetched (https only; --allow-http adds http; local copies go through pull); refused before dialling"
}

// uriScheme is the RFC 3986 scheme of a location, lowercased, or "" when it has none.
func uriScheme(loc string) string {
	s, _, ok := strings.Cut(loc, ":")
	if !ok || s == "" {
		return ""
	}
	for i, r := range s {
		alpha := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		if !alpha && (i == 0 || !(r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.')) {
			return ""
		}
	}
	return strings.ToLower(s)
}

func schemeAllowed(loc string, allowHTTP bool) error {
	switch sc := uriScheme(loc); sc {
	case "https":
		return nil
	case "http":
		if allowHTTP {
			return nil
		}
		return schemeErr{sc}
	default:
		return schemeErr{sc}
	}
}

// schemeGate refuses every scheme the reader did not allow before the injected transport sees the location, so
// the rule holds whatever transport the binary wires.
type schemeGate struct {
	inner     store.Transport
	allowHTTP bool
}

func (g schemeGate) Fetch(ctx context.Context, loc string) (io.ReadCloser, error) {
	if err := schemeAllowed(loc, g.allowHTTP); err != nil {
		return nil, err
	}
	return g.inner.Fetch(ctx, loc)
}

// timeoutGate bounds each location by the per-location timeout through its context, whatever the transport.
type timeoutGate struct {
	inner store.Transport
	d     time.Duration
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error { err := c.ReadCloser.Close(); c.cancel(); return err }

func (g timeoutGate) Fetch(ctx context.Context, loc string) (io.ReadCloser, error) {
	ctx, cancel := context.WithTimeout(ctx, g.d)
	rc, err := g.inner.Fetch(ctx, loc)
	if err != nil {
		cancel()
		return nil, err
	}
	return cancelOnClose{rc, cancel}, nil
}

// timeoutText is the overall cap as disclosed: "none" when unset.
func timeoutText(d time.Duration) string {
	if d <= 0 {
		return "none"
	}
	return d.String()
}

// fetchTarget is one argument resolved: the blob, and the statement it was named through ("" for a digest).
type fetchTarget struct {
	blob, via string
	// missing names why an id argument gave no blob ("" when it did).
	missing string
}

func fetchTargets(c *Ctx) ([]fetchTarget, error) {
	var stmts map[string][]byte
	var out []fetchTarget
	seen := map[string]bool{}
	for _, a := range c.Many["digest|id"] {
		t := fetchTarget{blob: a}
		if !isDigest(a) {
			if stmts == nil {
				var err error
				if stmts, err = c.Store.Statements(); err != nil {
					return nil, err
				}
			}
			t = fetchTarget{via: a}
			if line, ok := stmts[a]; !ok {
				t.missing = "no statement held"
			} else if st, err := wire.ReadStored(line); err != nil || contentOf(st) == "" || !isDigest(contentOf(st)) {
				t.missing = "names no blob"
			} else {
				t.blob = contentOf(st)
			}
		}
		key := t.blob + "|" + t.via
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out, nil
}

// blob states a fetch prints (closed vocabulary)
const (
	fsHeld        = "held here"
	fsFetched     = store.StateFetched
	fsMismatch    = store.StateMismatch
	fsSizeWrong   = store.StateSizeWrong
	fsTooLarge    = store.StateTooLarge
	fsNoLocation  = store.StateNotHeld
	fsHolderWord  = "unavailable (holder's word)"
	fsScheme      = "unavailable (scheme not fetched)"
	fsNoTransport = "unavailable (no transport in this build)"
	fsCorrupt     = "stored copy corrupt"
	fsNoStatement = "no statement held"
	fsWould       = "would fetch (dry run)"
)

func fetchCmd(c *Ctx) (*Obj, int, error) {
	targets, err := fetchTargets(c)
	if err != nil {
		return nil, 0, failed(err, "store", false, "run status, then fsck")
	}
	cfg := FetchConfig{IdleTimeout: DefaultFetchIdleTimeout}
	_, cfg.AllowHTTP = c.Flag("allow-http")
	_, cfg.AllowPrivate = c.Flag("allow-private")
	if v, ok := c.Flag("timeout"); ok {
		cfg.Timeout, _ = time.ParseDuration(v)
	}
	if v, ok := c.Flag("idle-timeout"); ok {
		cfg.IdleTimeout, _ = time.ParseDuration(v)
	}
	max := int64(store.DefaultMaxFetchBytes)
	if v, ok := c.Flag("max-bytes"); ok {
		max, _ = strconv.ParseInt(v, 10, 64)
	}
	_, dry := c.Flag("dry-run")
	if dry {
		return fetchPlan(c, targets, cfg, max)
	}
	var tr store.Transport
	if c.Env.Fetch != nil {
		if inner := c.Env.Fetch(cfg); inner != nil {
			tr = schemeGate{inner, cfg.AllowHTTP}
			if cfg.Timeout > 0 {
				tr = timeoutGate{tr, cfg.Timeout}
			}
		}
	}
	rows := listV{}
	held, refused, unobtained, installed, quarantined := 0, 0, 0, 0, 0
	for _, t := range targets {
		row := newObj()
		if t.blob != "" {
			row.set("digest", refV(t.blob))
		}
		if t.via != "" {
			row.set("via_statement", refV(t.via))
		}
		if t.missing != "" {
			row.set("state", tokV(tok(fsNoStatement)))
			if t.missing != "no statement held" {
				row.set("note", textV("the statement is held and names no blob"))
			}
			unobtained++
			rows = append(rows, row)
			continue
		}
		d := store.Digest(t.blob)
		if tr == nil {
			// no transport: answer from what is held, dial nothing
			av, err := c.Store.Availability(d)
			if err != nil {
				return nil, 0, failed(err, "blob "+t.blob, installed > 0, "run fsck")
			}
			switch {
			case av.State == store.StateHeld:
				row.set("state", tokV(tok(fsHeld)))
				held++
			default:
				if strings.HasPrefix(av.State, store.StateCorrupt) {
					row.set("local_copy", tokV(tok(fsCorrupt)))
				}
				pl := planRows(av, cfg, max, false)
				st := fsNoTransport
				if len(pl) == 0 {
					st = fsNoLocation // nothing to dial even with a transport
				}
				row.set("state", tokV(tok(st)))
				row.set("attempts", pl)
				unobtained++
			}
			rows = append(rows, row)
			continue
		}
		res, ferr := c.Store.Fetch(d, tr, store.FetchOptions{Context: context.Background(), MaxBytes: max})
		var ff *store.FetchFailure
		if ferr != nil && !errors.As(ferr, &ff) {
			return nil, 0, failed(ferr, "blob "+t.blob, installed > 0, "fetch again; a blob already installed is reused, not fetched twice")
		}
		row.set("attempts", attemptRows(res.Attempts))
		switch {
		case ferr == nil && res.State == store.StateHeld:
			row.set("state", tokV(tok(fsHeld)))
			held++
		case ferr == nil:
			row.set("state", tokV(tok(fsFetched)))
			row.set("install", textV(string(res.Install)))
			if res.Reinstalled {
				row.set("local_copy", tokV(tok(fsCorrupt)))
				row.set("note", textV("the corrupt stored copy was moved to quarantine and replaced by the verified bytes"))
				quarantined++
			}
			held++
			installed++
		default:
			if ff.Corrupt {
				row.set("local_copy", tokV(tok(fsCorrupt)))
				row.set("note", textV("the stored copy is corrupt and was not used; it stays in place until a location serves the verified bytes"))
			}
			st, wrong := failState(res.Attempts)
			row.set("state", tokV(tok(st)))
			if wrong {
				refused++
			} else {
				unobtained++
			}
		}
		rows = append(rows, row)
	}
	code := ExitOK
	switch {
	case refused > 0:
		code = ExitWrong
	case unobtained > 0:
		code = ExitCouldNot
	}
	o := newObj().set("blobs", rows)
	o.set("summary", textV(fmt.Sprintf("%d of %d held and verified; anything derived from them is scoped to those, with no completeness claim", held, len(targets))))
	if c.Env.Fetch == nil {
		o.set("note", textV("this build has no network transport: nothing was dialled; blobs already held were checked"))
	}
	se := fmt.Sprintf("%d blob(s) installed under blobs/ after a full-hash check", installed)
	if quarantined > 0 {
		se += fmt.Sprintf("; %d corrupt stored copy(ies) moved to quarantine", quarantined)
	}
	o.set("side_effects", textV(se+"; no statement signed or committed (no holds published); no registry change"))
	o.set("exit", intV(int64(code))).set("exit_name", textV(ExitName(code)))
	return o, code, nil
}

// failState is the blob state after every location failed: a completed mismatch (hash, or a declared size not
// met) is a refusal of the bytes and wins; otherwise the last attempt's state, else no location named.
func failState(as []store.Attempt) (string, bool) {
	for _, a := range as {
		if a.State == store.StateMismatch || a.State == store.StateSizeWrong {
			return a.State, true
		}
	}
	if len(as) == 0 {
		return fsNoLocation, false
	}
	return attemptState(as[len(as)-1]), false
}

func attemptState(a store.Attempt) string {
	var se schemeErr
	switch {
	case errors.As(a.Err, &se):
		return fsScheme
	case strings.HasPrefix(a.State, "unavailable (holder's word"):
		return fsHolderWord
	}
	return a.State
}

func attemptRows(as []store.Attempt) listV {
	l := listV{}
	for _, a := range as {
		r := newObj().set("location", peerV(a.Location)).set("state", tokV(tok(attemptState(a))))
		if a.Holder != "" {
			r.set("holds", refV(a.Holder))
		}
		var ref *refusal.Refusal
		if errors.As(a.Err, &ref) {
			r.set("class", tokV(tok(string(ref.Class)))).set("reason", textV(ref.Reason))
		}
		if a.Err != nil {
			// the detail quotes the location and transport text, which are peer-supplied
			r.set("detail", peerV(a.Err.Error()))
		}
		l = append(l, r)
	}
	return l
}

// planRows lists the locations the held holds name, with what a fetch would do before dialling: refuse the
// scheme, refuse a declared size over the limit, or dial. dial false marks every dialable row as not dialled.
func planRows(av store.Availability, cfg FetchConfig, max int64, dial bool) listV {
	l := listV{}
	seen := map[string]bool{}
	for _, h := range av.Holders {
		for _, loc := range h.Locations {
			if seen[loc] {
				continue
			}
			seen[loc] = true
			r := newObj().set("location", peerV(loc)).set("holds", refV(h.StatementID)).set("holder", refV(h.Signer))
			if h.Size >= 0 {
				r.set("declared_size", intV(h.Size))
			}
			switch err := schemeAllowed(loc, cfg.AllowHTTP); {
			case err != nil:
				r.set("state", tokV(tok(fsScheme))).set("detail", peerV(err.Error()))
			case h.Size > max:
				r.set("state", tokV(tok(fsTooLarge))).set("class", tokV(tok(string(refusal.Operational)))).
					set("detail", textV(fmt.Sprintf("the declared size exceeds the fetch limit max_fetch_bytes=%d; refused before dialling", max)))
			case dial:
				r.set("state", tokV(tok(fsWould)))
			default:
				r.set("state", tokV(tok(fsNoTransport)))
			}
			l = append(l, r)
		}
	}
	return l
}

func fetchPlan(c *Ctx, targets []fetchTarget, cfg FetchConfig, max int64) (*Obj, int, error) {
	rows := listV{}
	for _, t := range targets {
		row := newObj()
		if t.blob != "" {
			row.set("digest", refV(t.blob))
		}
		if t.via != "" {
			row.set("via_statement", refV(t.via))
		}
		if t.missing != "" {
			rows = append(rows, row.set("state", tokV(tok(fsNoStatement))))
			continue
		}
		av, err := c.Store.Availability(store.Digest(t.blob))
		if err != nil {
			return nil, 0, failed(err, "blob "+t.blob, false, "run fsck")
		}
		switch {
		case av.State == store.StateHeld:
			row.set("state", tokV(tok(fsHeld))).set("plan", textV("held and intact: nothing to fetch"))
		default:
			if strings.HasPrefix(av.State, store.StateCorrupt) {
				row.set("local_copy", tokV(tok(fsCorrupt))).set("plan", textV("the stored copy is corrupt: a verified fetch would replace it and move it to quarantine"))
			}
			pl := planRows(av, cfg, max, c.Env.Fetch != nil)
			st := fsNoLocation
			if len(pl) > 0 {
				st = fsWould
				if c.Env.Fetch == nil {
					st = fsNoTransport
				} else if !slices.ContainsFunc(pl, func(v value) bool { return v.(*Obj).get("state") == tokV(fsWould) }) {
					st = string(pl[len(pl)-1].(*Obj).get("state").(tokV))
				}
			}
			row.set("state", tokV(tok(st))).set("attempts", pl)
		}
		rows = append(rows, row)
	}
	o := newObj().set("blobs", rows).set("dry_run", boolV(true)).set("side_effects", textV(fetchSideEffects))
	o.set("timeout_per_location", textV(timeoutText(cfg.Timeout))).set("idle_timeout", textV(cfg.IdleTimeout.String())).set("max_fetch_bytes", intV(max))
	return o, ExitOK, nil
}
