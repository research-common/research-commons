// Package reqlog is the one request-log dialect the format defines, `rc-request-log/1` (wire-format note §5,
// source referent; claims-model note §5.3.1): the log a batch capture carries inside its content, one entry per
// request. The writer (`run --publish`) and the reader (the resolver's batch check) share this parser, so a log
// the tool writes is a log the tool reads.
//
// The layout is JSON Lines: UTF-8, one I-JSON object per line, each line ended by one line feed (no carriage
// return, no blank line, no byte order mark). Each object has exactly these members:
//
//   - `endpoint` string, non-empty: the endpoint requested (compared as the referent's `requests.endpoint` is);
//   - `parameters` object: the request's parameters, as the single-request referent pins them;
//   - `status` integer, 0 to 999: the status the source returned (an HTTP status for HTTP sources);
//   - `time` string: when the request was made, an RFC 3339 UTC instant in the format's spelling (wire §1.1);
//   - `response_digest` string: the sha256 digest of the response bytes (`sha256:` + 64 lowercase hex).
//
// The member set is closed, except that names beginning `x_` are extensions, kept and ignored, as in a signed
// body (wire §6). Any other member, a missing one or a wrong type makes the log malformed, named by line. Lines
// need not be canonical JSON: the log is pinned by the digest of its bytes, not re-encoded.
package reqlog

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/rctime"
)

// Format is the dialect's name, the value of `requests.format` that selects it.
const Format = "rc-request-log/1"

// Reader limits (documented in the wire-format note §5): a log past one of them is not read, and the check is
// `unchecked` naming the limit, never `ok`.
const (
	// MaxBytes is the largest log read: the content scanner's per-member limit.
	MaxBytes = 64 << 20
	// MaxEntries is the most entries read from one log.
	MaxEntries = 1_000_000
	// MaxLineBytes is the longest line, its line feed excluded: the single-statement bound.
	MaxLineBytes = 65536
)

// Limit names a reader limit a log exceeded.
type Limit struct{ Name string }

func (l *Limit) Error() string { return "reader limit " + l.Name }

// Malformed is a log that is not `rc-request-log/1`: Line is 1-based (0 for the log as a whole).
type Malformed struct {
	Line int
	Why  string
}

func (m *Malformed) Error() string {
	if m.Line == 0 {
		return "malformed request log: " + m.Why
	}
	return fmt.Sprintf("malformed request log: line %d: %s", m.Line, m.Why)
}

// Entry is one logged request.
type Entry struct {
	Endpoint       string
	Parameters     *canon.Object
	Status         int64
	Time           string
	ResponseDigest string
}

var reDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var members = []string{"endpoint", "parameters", "response_digest", "status", "time"}

// Parse reads a log. The error is a *Limit or a *Malformed.
func Parse(b []byte) ([]Entry, error) {
	if len(b) > MaxBytes {
		return nil, &Limit{Name: "request_log_bytes=" + strconv.Itoa(MaxBytes)}
	}
	if len(b) == 0 {
		return nil, &Malformed{Why: "empty (a log lists at least one request)"}
	}
	if b[len(b)-1] != '\n' {
		return nil, &Malformed{Why: "the last line is not ended by a line feed"}
	}
	var out []Entry
	rest := b
	for n := 1; len(rest) > 0; n++ {
		i := bytes.IndexByte(rest, '\n')
		line := rest[:i]
		rest = rest[i+1:]
		if n > MaxEntries {
			return nil, &Limit{Name: "request_log_entries=" + strconv.Itoa(MaxEntries)}
		}
		if len(line) > MaxLineBytes {
			return nil, &Limit{Name: "request_log_line_bytes=" + strconv.Itoa(MaxLineBytes)}
		}
		e, why := entry(line)
		if why != "" {
			return nil, &Malformed{Line: n, Why: why}
		}
		out = append(out, e)
	}
	return out, nil
}

func entry(line []byte) (Entry, string) {
	if len(line) == 0 {
		return Entry{}, "blank line"
	}
	if bytes.IndexByte(line, '\r') >= 0 {
		return Entry{}, "carriage return (lines end with a line feed only)"
	}
	v, err := canon.Parse(line)
	if err != nil {
		return Entry{}, err.Error()
	}
	o, ok := v.(*canon.Object)
	if !ok {
		return Entry{}, "not an object"
	}
	for _, k := range o.Keys {
		if !strings.HasPrefix(k, "x_") && !contains(members, k) {
			return Entry{}, "undefined member " + strconv.Quote(k)
		}
	}
	for _, k := range members {
		if _, ok := o.Get(k); !ok {
			return Entry{}, "missing " + k
		}
	}
	var e Entry
	ep, ok := o.Members["endpoint"].(canon.String)
	if !ok || ep == "" {
		return Entry{}, "endpoint is not a non-empty string"
	}
	e.Endpoint = string(ep)
	if e.Parameters, ok = o.Members["parameters"].(*canon.Object); !ok {
		return Entry{}, "parameters is not an object"
	}
	st, ok := o.Members["status"].(canon.Int)
	if !ok || st < 0 || st > 999 {
		return Entry{}, "status is not an integer 0 to 999"
	}
	e.Status = int64(st)
	ts, ok := o.Members["time"].(canon.String)
	if !ok {
		return Entry{}, "time is not a string"
	}
	if _, err := rctime.ParseUTC(string(ts)); err != nil {
		return Entry{}, "time: " + err.Error()
	}
	e.Time = string(ts)
	rd, ok := o.Members["response_digest"].(canon.String)
	if !ok || !reDigest.MatchString(string(rd)) {
		return Entry{}, "response_digest is not a content digest (sha256: + 64 lowercase hex)"
	}
	e.ResponseDigest = string(rd)
	return e, ""
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// Encode writes entries as a log: each entry one canonical JSON line.
func Encode(es []Entry) []byte {
	var b []byte
	for _, e := range es {
		params := e.Parameters
		if params == nil {
			params = &canon.Object{Members: map[string]canon.Value{}}
		}
		o := &canon.Object{Keys: append([]string(nil), members...), Members: map[string]canon.Value{
			"endpoint": canon.String(e.Endpoint), "parameters": params, "response_digest": canon.String(e.ResponseDigest),
			"status": canon.Int(e.Status), "time": canon.String(e.Time)}}
		b = append(b, canon.Encode(o)...)
		b = append(b, '\n')
	}
	return b
}

// SharedEndpoint is the endpoint every entry shares, "" when they differ (the referent's optional
// `requests.endpoint`), compared as written.
func SharedEndpoint(es []Entry) string {
	if len(es) == 0 {
		return ""
	}
	for _, e := range es[1:] {
		if e.Endpoint != es[0].Endpoint {
			return ""
		}
	}
	return es[0].Endpoint
}
