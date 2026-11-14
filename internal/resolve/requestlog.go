package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/reqlog"
	"github.com/research-common/research-commons/internal/wire"
)

// The batch source referent (claims §5.3.1; wire §5 `observed`, source, `requests`): the referent pins a request
// log carried inside the captured content by its digest, format and count. The reader locates the log among the
// content's units (the blob itself, or a member of an archive, at any depth the scanner reads), reads it under the
// one dialect the format defines (reqlog.Format), and checks the pins against it: the count, the shared endpoint
// when one is pinned, and that every logged response is held in the same content. Every answer is a function of
// the content's bytes and the statement: no network, no clock.

// Request-log check outcomes. RequestLogOK: every pin holds. RequestLogFail: the log was read and a pin does not
// hold (checked and wrong). RequestLogUnchecked: the reader could not decide (content not held, a format it does
// not read, a limit, an unscanned unit). RequestLogUnpinned: the content was read in full and no unit hashes to
// the pinned log digest, so the referent pins nothing the capture carries (C-core-31).
const (
	RequestLogOK        = "ok"
	RequestLogFail      = "fail"
	RequestLogUnchecked = "unchecked"
	RequestLogUnpinned  = RefUnpinned
)

// RequestLog is the reader's check of a batch referent's request log.
type RequestLog struct {
	// Digest, Format, Count and Endpoint are the pins as signed (Endpoint "" when not pinned).
	Digest, Format string
	Count          int64
	Endpoint       string
	Outcome        string
	// Why says why the outcome is unchecked or unpinned.
	Why string
	// Unit is the content unit the log was found in ("" when not located).
	Unit string
	// Entries is the number of logged requests read; Endpoints the distinct endpoints, in first-logged order.
	Entries   int
	Endpoints []string
	// Held is how many logged responses are held in the content.
	Held int
	// Problems names each pin that does not hold: the count, the endpoint, and every response not held, by entry
	// index (1-based, the log's line) and endpoint.
	Problems []string
	// responses are the logged responses in log order, with the bytes of each one the content holds (nil when the
	// log is the whole content: the response is then a blob the reader may hold). A response layout reads them.
	responses []loggedResponse
	// nProblems counts every problem, named or only counted (Problems names at most maxNamedProblems responses).
	nProblems int
}

// loggedResponse is one logged request's response: its endpoint and digest as logged, and its bytes when the
// content holds them.
type loggedResponse struct {
	Endpoint, Digest string
	data             []byte
	// held: the content holds the response (data), or the log is the whole content and the reader holds it as a
	// blob (data nil: a layout reads it through the reader's blob bytes).
	held bool
}

// maxNamedProblems bounds the responses named one by one; the rest are counted.
const maxNamedProblems = 20

// String is the one-line display.
func (l *RequestLog) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (log %s, format %q, count %d", l.Outcome, shortDigest(l.Digest), l.Format, l.Count)
	if l.Unit != "" {
		fmt.Fprintf(&b, ", found at %s; %d entries, endpoint(s) %s, responses held %d/%d", l.Unit, l.Entries,
			strings.Join(l.Endpoints, ", "), l.Held, l.Entries)
	}
	b.WriteString(")")
	if l.Why != "" {
		b.WriteString(": " + l.Why)
	}
	return b.String()
}

// batchPins reads the `requests` member of a source referent; ok is false for any other referent.
func batchPins(st *wire.Statement) (*RequestLog, bool) {
	if str(st.Body, "class") != "source" {
		return nil, false
	}
	req := object(object(st.Body, "referent"), "requests")
	if req == nil {
		return nil, false
	}
	l := &RequestLog{Digest: str(req, "digest"), Format: str(req, "format"), Endpoint: str(req, "endpoint")}
	if v, ok := req.Get("count"); ok {
		if n, ok := v.(canon.Int); ok {
			l.Count = int64(n)
		}
	}
	return l, true
}

// WithObservedContent sets where the observation view reads captured content from (a batch referent's request
// log). Unset, it falls back to the edition-rule content reader (WithContent); with neither, a batch's log is
// `unchecked` (content not held).
func WithObservedContent(c ContentReader) Option { return func(r *Resolver) { r.obs.content = c } }

// requestLogOf is requestLog, computed once per statement for the resolver's snapshot.
func (r *Resolver) requestLogOf(st *wire.Statement, unpinned []string) *RequestLog {
	r.obs.logMu.Lock()
	if l, ok := r.obs.logs[st.ID]; ok {
		r.obs.logMu.Unlock()
		return l
	}
	r.obs.logMu.Unlock()
	l := r.requestLog(st, unpinned)
	r.obs.logMu.Lock()
	if r.obs.logs == nil {
		r.obs.logs = map[string]*RequestLog{}
	}
	r.obs.logs[st.ID] = l
	r.obs.logMu.Unlock()
	return l
}

// requestLog checks a batch referent against the content it names. nil for any other referent, and for a batch
// whose own pins are already unpinned (the schema named the missing member; nothing to locate).
func (r *Resolver) requestLog(st *wire.Statement, unpinned []string) *RequestLog {
	l, ok := batchPins(st)
	if !ok {
		return nil
	}
	for _, u := range unpinned {
		if strings.HasPrefix(u, "referent.requests") {
			return nil
		}
	}
	if l.Format != reqlog.Format {
		l.Outcome, l.Why = RequestLogUnchecked, fmt.Sprintf("request-log format %q is not one this reader reads (it reads %q)", l.Format, reqlog.Format)
		return l
	}
	d := contentDigest(st.Body)
	content := r.obs.content
	if content == nil {
		content = r.rules.content
	}
	if content == nil || d == "" {
		l.Outcome, l.Why = RequestLogUnchecked, "content not held"
		return l
	}
	units, held := content.Units(d)
	if !held {
		l.Outcome, l.Why = RequestLogUnchecked, "content not held"
		return l
	}
	// every unit's digest, and the units the scanner could not read
	have := map[string][]byte{}
	var unscanned []string
	var logUnit *ContentUnit
	for i := range units {
		u := &units[i]
		if u.Data == nil {
			unscanned = append(unscanned, u.Name+" ("+u.Unscanned+")")
			continue
		}
		h := sha256.Sum256(u.Data)
		ud := "sha256:" + hex.EncodeToString(h[:])
		if _, ok := have[ud]; !ok {
			have[ud] = u.Data
		}
		if ud == l.Digest && logUnit == nil {
			logUnit = u
		}
	}
	if logUnit == nil {
		if len(unscanned) > 0 {
			l.Outcome, l.Why = RequestLogUnchecked, "the log is not among the units read; unscanned: "+strings.Join(unscanned, ", ")
			return l
		}
		l.Outcome, l.Why = RequestLogUnpinned, "the log digest matches nothing in the content"
		return l
	}
	l.Unit = logUnit.Name
	// the log is the whole content (a plain blob, no archive): the responses are not inside it, so each is looked
	// up among the blobs the reader holds intact, and one not held there is unchecked, never wrong
	whole := len(units) == 1 && l.Digest == d
	entries, err := reqlog.Parse(logUnit.Data)
	if err != nil {
		var lim *reqlog.Limit
		if errors.As(err, &lim) {
			l.Outcome, l.Why = RequestLogUnchecked, err.Error()
			return l
		}
		l.Outcome, l.Why = RequestLogFail, err.Error()
		l.Problems, l.nProblems = append(l.Problems, err.Error()), 1
		return l
	}
	l.Entries = len(entries)
	if int64(len(entries)) != l.Count {
		l.Problems = append(l.Problems, fmt.Sprintf("count %d pinned, the log lists %d", l.Count, len(entries)))
	}
	missing, named, endpointBad := 0, 0, len(l.Problems) > 0
	for i, e := range entries {
		if !slices.Contains(l.Endpoints, e.Endpoint) {
			l.Endpoints = append(l.Endpoints, e.Endpoint)
		}
		if l.Endpoint != "" && e.Endpoint != l.Endpoint {
			endpointBad = true
			l.Problems = append(l.Problems, fmt.Sprintf("entry %d: endpoint %s, the referent pins %s for every request", i+1, strconv.Quote(e.Endpoint), strconv.Quote(l.Endpoint)))
		}
		data, inContent := have[e.ResponseDigest]
		held := inContent || (whole && r.obs.blobs.Has(e.ResponseDigest))
		l.responses = append(l.responses, loggedResponse{Endpoint: e.Endpoint, Digest: e.ResponseDigest, data: data, held: held})
		if held {
			l.Held++
			continue
		}
		missing++
		if named < maxNamedProblems {
			named++
			l.Problems = append(l.Problems, fmt.Sprintf("entry %d, endpoint %s: response %s not held in the content, mutated or missing", i+1, e.Endpoint, shortDigest(e.ResponseDigest)))
		}
	}
	l.nProblems = len(l.Problems) + missing - named
	if missing > named {
		l.Problems = append(l.Problems, fmt.Sprintf("%d more responses not held in the content", missing-named))
	}
	switch {
	case !endpointBad && missing > 0 && len(unscanned) > 0:
		// the only problems are responses not found, and some units were not read: they may be there
		l.Outcome, l.Why = RequestLogUnchecked, "responses not found among the units read; unscanned: "+strings.Join(unscanned, ", ")
	case !endpointBad && missing > 0 && whole:
		l.Outcome, l.Why = RequestLogUnchecked, "the log is the whole content and these responses are not held by this reader"
	case len(l.Problems) > 0:
		l.Outcome = RequestLogFail
	default:
		l.Outcome = RequestLogOK
	}
	return l
}

// requestLogLines are the display lines under the referent: the outcome, then each problem.
func (l *RequestLog) lines() []string {
	out := []string{"request log: " + l.String()}
	for _, p := range l.Problems {
		out = append(out, "  "+p)
	}
	return out
}
