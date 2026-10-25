package store

// Bounded scans (storage note §8; C-core-130, C-core-131).
//
// Scanner walks an archive member by member (tar, tar.gz/gzip, zip; standard library only) under documented
// limits. Every unit it cannot examine is reported as `unscanned (<limit>=<value>)`; the enclosing result is
// then Incomplete, never Clean. A limit that stops the whole run (the total-bytes budget, nesting past the
// depth bound) is an operational refusal naming the limit, its value and the scope it cut, returned together
// with the partial result, which stays marked Incomplete.
//
// Detection of what to do with bytes is a hook (Inspector): the scanner decides what was and was not looked
// at, the Inspector decides what a member's bytes mean. KeyScan is an Inspector that looks for forbidden JSON
// keys and secret-shaped strings; its patterns and key names are configuration, with a conservative default
// set that is only a default (see DefaultSecretPatterns).

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/refusal"
)

// Limit names, as printed in `unscanned (<name>=<value>)` and in refusals.
const (
	LimitMemberBytes = "member_bytes"
	LimitTotalBytes  = "total_bytes"
	LimitMembers     = "members"
	LimitDepth       = "depth"
	LimitPathBytes   = "path_bytes"
	LimitRatio       = "expansion_ratio"
	LimitCompression = "compression" // not a number: the unsupported method
	LimitTruncated   = "truncated"
	LimitUnsupported = "format"
)

// Limits are the scan limits. They belong to the reader's policy and to its digest (§5.1, §8): Digest
// returns the canonical string a policy digest should include, and String is what `status --limits` prints.
// A zero field takes the default of DefaultLimits.
type Limits struct {
	// MemberBytes: the most uncompressed bytes read of one member; a larger member is unscanned.
	MemberBytes int64
	// TotalBytes: the most uncompressed bytes read in one scan (all members, all depths); reaching it stops the
	// run (operational refusal).
	TotalBytes int64
	// Members: the most members listed in one archive (per archive, nested archives counted separately); the
	// rest are unscanned as one range and the run stops at it (operational refusal).
	Members int
	// Depth: the deepest archive nesting examined (the outermost archive is depth 1). A nested archive past it
	// is unscanned; descending past it is the refusal when Strict, otherwise the member is unscanned and the
	// scan continues (both leave the result Incomplete).
	Depth int
	// PathBytes: the longest member name; a longer one is unscanned.
	PathBytes int
	// ExpansionRatio: the most uncompressed bytes per compressed byte for a compressed stream (a gzip member or
	// zip entry), checked while reading, so a decompression bomb stops at a bounded cost.
	ExpansionRatio int64
	// Strict makes hitting Depth a refusal rather than an `unscanned` member.
	Strict bool
}

// DefaultLimits are the defaults chosen here (size policy values are open question #9 of the storage note):
// members of 64 MiB, 512 MiB per scan, 10 000 members per archive, nesting 3, names of 1 024 bytes, expansion
// 200:1.
func DefaultLimits() Limits {
	return Limits{MemberBytes: 64 << 20, TotalBytes: 512 << 20, Members: 10000, Depth: 3, PathBytes: 1024, ExpansionRatio: 200}
}

func (l Limits) resolved() Limits {
	d := DefaultLimits()
	if l.MemberBytes <= 0 {
		l.MemberBytes = d.MemberBytes
	}
	if l.TotalBytes <= 0 {
		l.TotalBytes = d.TotalBytes
	}
	if l.Members <= 0 {
		l.Members = d.Members
	}
	if l.Depth <= 0 {
		l.Depth = d.Depth
	}
	if l.PathBytes <= 0 {
		l.PathBytes = d.PathBytes
	}
	if l.ExpansionRatio <= 0 {
		l.ExpansionRatio = d.ExpansionRatio
	}
	return l
}

// String is the `status --limits` line.
func (l Limits) String() string {
	l = l.resolved()
	return fmt.Sprintf("%s=%d %s=%d %s=%d %s=%d %s=%d %s=%d strict=%t", LimitMemberBytes, l.MemberBytes, LimitTotalBytes, l.TotalBytes,
		LimitMembers, l.Members, LimitDepth, l.Depth, LimitPathBytes, l.PathBytes, LimitRatio, l.ExpansionRatio, l.Strict)
}

// Digest is the canonical text a policy digest covers: a changed limit is a changed policy.
func (l Limits) Digest() string { return "scan-limits/1 " + l.String() }

// Inspector looks at the bytes of one member. It is called only with a member read in full within the limits.
// It returns findings (empty means nothing found in what it examined) and may return an error for an
// operational failure of its own, which stops the run.
type Inspector interface {
	Inspect(path string, data []byte) ([]ScanFinding, error)
}

// ScanFinding is what an Inspector found in a member.
type ScanFinding struct {
	Path   string
	Rule   string
	Detail string
}

// Member outcomes.
const (
	MemberScanned   = "scanned"
	MemberUnscanned = "unscanned"
	MemberSkipped   = "not a file" // directories, links, devices: nothing to read
)

// MemberResult is one unit of a scan.
type MemberResult struct {
	Path   string // full path, nested archives joined with "!/"
	Depth  int
	Status string
	// Limit and Value name the limit when Status is unscanned: `unscanned (member_bytes=67108864)`.
	Limit, Value string
	// Detail says why, for a human.
	Detail string
}

// Label is the text of an unscanned member.
func (m MemberResult) Label() string {
	if m.Status != MemberUnscanned {
		return m.Status
	}
	return fmt.Sprintf("unscanned (%s=%s)", m.Limit, m.Value)
}

// ScanResult is the outcome of one scan.
type ScanResult struct {
	Members  []MemberResult
	Findings []ScanFinding
	// Complete is true only when every member was examined, nothing stopped the run and no unit was
	// unscanned. A result that is not complete is Incomplete; there is no third state called clean.
	Complete bool
	// Stopped is the operational refusal that ended the run early, if any (also returned as the error).
	Stopped *refusal.Refusal
	// BytesRead is the uncompressed bytes read.
	BytesRead int64
	Limits    Limits
}

// Unscanned returns the members that were not examined.
func (r *ScanResult) Unscanned() []MemberResult {
	var out []MemberResult
	for _, m := range r.Members {
		if m.Status == MemberUnscanned {
			out = append(out, m)
		}
	}
	return out
}

// Verdict is the one word a result may be summarised by: "findings" when an Inspector found something (in what
// was scanned), otherwise "clean" only if Complete, otherwise "incomplete". Findings and incompleteness are
// both reported when both hold (Render).
func (r *ScanResult) Verdict() string {
	switch {
	case len(r.Findings) > 0:
		return "findings"
	case r.Complete:
		return "clean"
	}
	return "incomplete"
}

// Render is the text a command prints. "clean" appears only for a complete scan with no finding.
func (r *ScanResult) Render() string {
	var b strings.Builder
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "found: %s: %s: %s\n", f.Path, f.Rule, f.Detail)
	}
	for _, m := range r.Members {
		if m.Status == MemberUnscanned {
			fmt.Fprintf(&b, "%s: %s\n", m.Path, m.Label())
		}
	}
	if r.Stopped != nil {
		fmt.Fprintf(&b, "stopped: %s\n", r.Stopped)
	}
	n := 0
	for _, m := range r.Members {
		if m.Status == MemberScanned {
			n++
		}
	}
	switch r.Verdict() {
	case "clean":
		fmt.Fprintf(&b, "clean: %d member(s) scanned, none unscanned\n", n)
	default:
		if !r.Complete {
			fmt.Fprintf(&b, "incomplete: %d member(s) scanned, %d unscanned; this is not a clean result\n", n, len(r.Unscanned()))
		}
	}
	return b.String()
}

// ReaderPolicyRefusal is what a release policy that requires a clean scan returns for an incomplete result:
// reader policy, naming every unscanned unit, and saying it is not corruption (C-core-131, I4, I8).
func (r *ScanResult) RequireClean() error {
	if r.Complete && len(r.Findings) == 0 {
		return nil
	}
	var names []string
	for _, m := range r.Unscanned() {
		names = append(names, m.Path+" "+m.Label())
	}
	if len(r.Findings) > 0 && len(names) == 0 {
		return &refusal.Refusal{Class: refusal.Policy, Reason: "scan findings", Detail: fmt.Sprintf("%d finding(s); first: %s: %s", len(r.Findings), r.Findings[0].Path, r.Findings[0].Rule)}
	}
	d := "this reader's policy requires a clean scan and the scan is incomplete (not a statement about the archive's contents): " + strings.Join(names, "; ")
	if r.Stopped != nil {
		d += "; the run stopped: " + r.Stopped.Detail
	}
	return &refusal.Refusal{Class: refusal.Policy, Reason: "incomplete scan", Detail: d}
}

// Scanner scans archives under Limits with an Inspector (nil: only enumerate and bound, find nothing).
type Scanner struct {
	Limits Limits
	Inspector
}

type scanRun struct {
	sc  *Scanner
	lim Limits
	res *ScanResult
}

// Scan scans one archive given as bytes (the format is detected from the leading bytes; name is for
// messages and nested paths). On an operational refusal it returns the partial result and the refusal.
func (sc *Scanner) Scan(name string, data []byte) (*ScanResult, error) {
	lim := sc.Limits.resolved()
	run := &scanRun{sc: sc, lim: lim, res: &ScanResult{Limits: lim}}
	err := run.archive(name, data, 1)
	run.res.Complete = err == nil && run.res.Stopped == nil && len(run.res.Unscanned()) == 0
	if err != nil {
		var r *refusal.Refusal
		if errors.As(err, &r) {
			run.res.Stopped = r
		}
		return run.res, err
	}
	return run.res, nil
}

func (r *scanRun) stop(limit string, value any, scope string) error {
	return &refusal.Refusal{Class: refusal.Operational, Reason: refusal.SizeLimit,
		Detail: fmt.Sprintf("scan limit %s=%v reached; %s; results so far are incomplete", limit, value, scope)}
}

func (r *scanRun) unscanned(path string, depth int, limit string, value any, detail string) {
	r.res.Members = append(r.res.Members, MemberResult{Path: path, Depth: depth, Status: MemberUnscanned,
		Limit: limit, Value: fmt.Sprint(value), Detail: detail})
}

func (r *scanRun) scanned(path string, depth int) {
	r.res.Members = append(r.res.Members, MemberResult{Path: path, Depth: depth, Status: MemberScanned})
}

// readBounded reads at most member_bytes of rd (and what is left of the total budget), checking the
// expansion ratio against compressedLen when it is known (> 0). It returns the bytes, and the limit that cut
// the read, if any.
func (r *scanRun) readBounded(rd io.Reader, compressedLen int64) (data []byte, limit string, value any, err error) {
	max := r.lim.MemberBytes
	if budget := r.lim.TotalBytes - r.res.BytesRead; budget < max {
		max = budget
	}
	data, err = io.ReadAll(io.LimitReader(rd, max+1))
	if err != nil {
		// A truncated stream (unexpected EOF) or a corrupt one: not readable to the end.
		return data, "", nil, err
	}
	if int64(len(data)) > max {
		if r.lim.TotalBytes-r.res.BytesRead <= r.lim.MemberBytes && int64(len(data)) > r.lim.TotalBytes-r.res.BytesRead {
			return data[:max], LimitTotalBytes, r.lim.TotalBytes, nil
		}
		return data[:max], LimitMemberBytes, r.lim.MemberBytes, nil
	}
	if compressedLen > 0 && int64(len(data)) > compressedLen*r.lim.ExpansionRatio && int64(len(data)) > 1<<20 {
		return data, LimitRatio, r.lim.ExpansionRatio, nil
	}
	return data, "", nil, nil
}

// archive scans data as an archive at the given depth.
func (r *scanRun) archive(path string, data []byte, depth int) error {
	switch kind := sniff(data); kind {
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			r.unscanned(path, depth, LimitTruncated, "gzip header", "gzip stream does not start: "+err.Error())
			return nil
		}
		zr.Multistream(false)
		inner, limit, val, err := r.readBounded(zr, int64(len(data)))
		if err != nil {
			r.unscanned(path, depth, LimitTruncated, "gzip", "gzip stream is truncated or corrupt: "+err.Error())
			return nil
		}
		r.res.BytesRead += int64(len(inner))
		if limit != "" {
			if limit == LimitTotalBytes {
				r.unscanned(path, depth, limit, val, "decompressed stream cut at the scan's byte budget")
				return r.stop(limit, val, "scope: "+path+" and everything after it in this scan")
			}
			r.unscanned(path, depth, limit, val, "decompressed stream over the limit")
			return nil
		}
		// gzip wraps either a tar or one file.
		if sniff(inner) == "tar" {
			return r.tarArchive(path, inner, depth)
		}
		return r.leaf(strings.TrimSuffix(path, ".gz"), inner, depth)
	case "zip":
		return r.zipArchive(path, data, depth)
	case "tar":
		return r.tarArchive(path, data, depth)
	default:
		if depth == 1 {
			r.unscanned(path, depth, LimitUnsupported, "unrecognised archive format", "not a tar, gzip or zip archive")
			return nil
		}
		return r.leaf(path, data, depth)
	}
}

// sniff recognises the formats this scanner can walk, from their magic bytes only.
func sniff(b []byte) string {
	switch {
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		return "gzip"
	case len(b) >= 4 && b[0] == 'P' && b[1] == 'K' && (b[2] == 3 || b[2] == 5) && (b[3] == 4 || b[3] == 6):
		return "zip"
	case len(b) >= 262 && string(b[257:262]) == "ustar":
		return "tar"
	}
	return ""
}

// isCompressedOther names compression the scanner has no reader for, so a member in it is unscanned with the
// method named rather than inspected as opaque bytes.
func isCompressedOther(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte{0xfd, '7', 'z', 'X', 'Z', 0}):
		return "xz"
	case bytes.HasPrefix(b, []byte{'B', 'Z', 'h'}):
		return "bzip2"
	case bytes.HasPrefix(b, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return "zstd"
	case bytes.HasPrefix(b, []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}):
		return "7z"
	case bytes.HasPrefix(b, []byte{'R', 'a', 'r', '!', 0x1a, 0x07}):
		return "rar"
	case bytes.HasPrefix(b, []byte{0x04, 0x22, 0x4d, 0x18}):
		return "lz4"
	}
	return ""
}

// leaf handles a file member's bytes: nested archive (depth rule) or inspect.
func (r *scanRun) leaf(path string, data []byte, depth int) error {
	if m := isCompressedOther(data); m != "" {
		r.unscanned(path, depth, LimitCompression, m, "compression this scanner cannot read: "+m)
		return nil
	}
	if k := sniff(data); k != "" && depth > 0 {
		// A nested archive.
		if depth+1 > r.lim.Depth {
			if r.lim.Strict {
				r.unscanned(path, depth, LimitDepth, r.lim.Depth, "nested archive past the depth bound")
				return r.stop(LimitDepth, r.lim.Depth, "scope: "+path+" and what it contains (nesting level "+fmt.Sprint(depth+1)+")")
			}
			r.unscanned(path, depth, LimitDepth, r.lim.Depth, "nested archive past the depth bound; its members were not examined")
			return nil
		}
		return r.archive(path, data, depth+1)
	}
	if r.sc.Inspector != nil {
		fs, err := r.sc.Inspector.Inspect(path, data)
		if err != nil {
			return err
		}
		r.res.Findings = append(r.res.Findings, fs...)
	}
	r.scanned(path, depth)
	return nil
}

func (r *scanRun) member(path string, depth int, rd io.Reader, size int64, compressed int64) error {
	if size > r.lim.MemberBytes {
		r.unscanned(path, depth, LimitMemberBytes, r.lim.MemberBytes, fmt.Sprintf("member declares %d bytes", size))
		return nil
	}
	data, limit, val, err := r.readBounded(rd, compressed)
	if err != nil {
		r.unscanned(path, depth, LimitTruncated, "member", "member is truncated or corrupt: "+err.Error())
		return nil
	}
	r.res.BytesRead += int64(len(data))
	switch limit {
	case LimitTotalBytes:
		r.unscanned(path, depth, limit, val, "read cut at the scan's byte budget")
		return r.stop(limit, val, "scope: "+path+" and every member after it in this scan")
	case "":
	default:
		r.unscanned(path, depth, limit, val, "member over the limit")
		return nil
	}
	return r.leaf(path, data, depth)
}

func (r *scanRun) tarArchive(path string, data []byte, depth int) error {
	tr := tar.NewReader(bufio.NewReader(bytes.NewReader(data)))
	for n := 0; ; n++ {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			r.unscanned(path+"!/<after member "+fmt.Sprint(n)+">", depth, LimitTruncated, "tar", "tar stream is truncated or corrupt after "+fmt.Sprint(n)+" member(s): "+err.Error())
			return nil
		}
		if n >= r.lim.Members {
			r.unscanned(path+"!/<members from "+fmt.Sprint(n+1)+" on>", depth, LimitMembers, r.lim.Members, "more members than the limit; the rest were not listed")
			return r.stop(LimitMembers, r.lim.Members, "scope: "+path+", every member after the first "+fmt.Sprint(r.lim.Members))
		}
		p := path + "!/" + h.Name
		if len(h.Name) > r.lim.PathBytes {
			r.unscanned(path+"!/<name of "+fmt.Sprint(len(h.Name))+" bytes>", depth, LimitPathBytes, r.lim.PathBytes, "member name over the limit")
			continue
		}
		if h.Typeflag != tar.TypeReg {
			r.res.Members = append(r.res.Members, MemberResult{Path: p, Depth: depth, Status: MemberSkipped})
			continue
		}
		if err := r.member(p, depth, tr, h.Size, 0); err != nil {
			return err
		}
	}
}

func (r *scanRun) zipArchive(path string, data []byte, depth int) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		r.unscanned(path, depth, LimitTruncated, "zip directory", "zip central directory unreadable (truncated or corrupt): "+err.Error())
		return nil
	}
	for n, f := range zr.File {
		if n >= r.lim.Members {
			r.unscanned(path+"!/<members from "+fmt.Sprint(n+1)+" on>", depth, LimitMembers, r.lim.Members, "more members than the limit; the rest were not listed")
			return r.stop(LimitMembers, r.lim.Members, "scope: "+path+", every member after the first "+fmt.Sprint(r.lim.Members))
		}
		p := path + "!/" + f.Name
		if len(f.Name) > r.lim.PathBytes {
			r.unscanned(path+"!/<name of "+fmt.Sprint(len(f.Name))+" bytes>", depth, LimitPathBytes, r.lim.PathBytes, "member name over the limit")
			continue
		}
		if f.FileInfo().IsDir() || !f.Mode().IsRegular() {
			r.res.Members = append(r.res.Members, MemberResult{Path: p, Depth: depth, Status: MemberSkipped})
			continue
		}
		if f.Method != zip.Store && f.Method != zip.Deflate {
			r.unscanned(p, depth, LimitCompression, fmt.Sprintf("zip method %d", f.Method), "compression method this scanner cannot read")
			continue
		}
		size := int64(f.UncompressedSize64)
		if f.UncompressedSize64 > uint64(1<<62) {
			size = 1 << 62
		}
		rc, err := f.Open()
		if err != nil {
			r.unscanned(p, depth, LimitUnsupported, "zip entry", "entry cannot be opened: "+err.Error())
			continue
		}
		var comp int64
		if f.Method == zip.Deflate {
			comp = int64(f.CompressedSize64)
			if comp == 0 {
				comp = 1
			}
		}
		err = r.member(p, depth, rc, size, comp)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------
// KeyScan: the optional forbidden-key and secret-shape Inspector.

// SecretPattern is one named regular expression.
type SecretPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// DefaultSecretPatterns are a conservative default, a starting point and not a policy: callers pass their own
// (KeyScan.Patterns) and the reader's policy should digest whichever it uses. They look for the shapes of
// private-key blocks, bearer-style tokens and cloud access key ids, and for long hex runs only when they
// are the value of a key whose name says key/secret.
func DefaultSecretPatterns() []SecretPattern {
	return []SecretPattern{
		{"private-key-block", regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`)},
		{"aws-access-key-id", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
		{"bearer-token", regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/-]{20,}=*`)},
		{"keyed-secret", regexp.MustCompile(`(?i)"[a-z0-9_.-]*(?:secret|private[_-]?key|seed|passphrase)[a-z0-9_.-]*"\s*:\s*"[^"]{8,}"`)},
	}
}

// DefaultForbiddenKeys are JSON member names a published dataset member should not carry. A default only.
var DefaultForbiddenKeys = []string{"private_key", "secret", "seed", "password", "passphrase", "api_key", "access_token"}

// KeyScan inspects a member for secret-shaped strings and, when the member is JSON-like text, for
// forbidden member names (a textual match on `"<name>":`, case-insensitive: it never parses JSON, because
// the only JSON parser of the module is for received statements). A member that is not valid UTF-8 text is
// searched as bytes with the same patterns. Size is the scanner's concern (member_bytes): an Inspector sees
// only members that were read in full.
type KeyScan struct {
	Patterns      []SecretPattern // nil means DefaultSecretPatterns()
	ForbiddenKeys []string        // nil means DefaultForbiddenKeys; empty non-nil means none
}

// Inspect implements Inspector. Findings never include the matched secret, only its pattern name and offset.
func (k KeyScan) Inspect(path string, data []byte) ([]ScanFinding, error) {
	ps := k.Patterns
	if ps == nil {
		ps = DefaultSecretPatterns()
	}
	keys := k.ForbiddenKeys
	if keys == nil {
		keys = DefaultForbiddenKeys
	}
	var out []ScanFinding
	for _, p := range ps {
		if loc := p.Pattern.FindIndex(data); loc != nil {
			out = append(out, ScanFinding{Path: path, Rule: "secret-pattern:" + p.Name, Detail: fmt.Sprintf("matches at byte offset %d (value not shown)", loc[0])})
		}
	}
	lower := bytes.ToLower(data)
	for _, name := range keys {
		needle := []byte(`"` + strings.ToLower(name) + `"`)
		for from := 0; ; {
			i := bytes.Index(lower[from:], needle)
			if i < 0 {
				break
			}
			j := from + i + len(needle)
			rest := bytes.TrimLeft(lower[j:], " \t\r\n")
			if len(rest) > 0 && rest[0] == ':' {
				out = append(out, ScanFinding{Path: path, Rule: "forbidden-key:" + name, Detail: fmt.Sprintf("member name at byte offset %d", from+i)})
				break
			}
			from = j
		}
	}
	slices.SortFunc(out, func(a, b ScanFinding) int { return strings.Compare(a.Rule, b.Rule) })
	return out, nil
}
