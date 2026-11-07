package gate

import (
	"bufio"
	"fmt"
	"io"
	"sync"

	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/store"
)

// ScanUnits returns the content units of one blob for edition rules that read content (storage note §8,
// C-core-95). An archive (tar, gzip, zip) is walked by the store's scanner under lim: each member read in
// full is a unit named by its path ("<name>!/<member>", nested archives joined the same way), and each member
// the scanner could not examine (an unsupported compression, a limit) is a unit carrying its limit, so a rule
// over it is `unchecked`, never `ok`. A blob in a compression the scanner cannot read is one unscanned unit.
// Any other blob is one unit with its bytes, as before. Directories and links inside an archive are no unit.
func ScanUnits(name string, data []byte, lim store.Limits) []resolve.ContentUnit {
	if m := store.Compression(data); m != "" {
		return []resolve.ContentUnit{{Name: name, Unscanned: store.LimitCompression + "=" + m}}
	}
	if store.ArchiveFormat(data) == "" {
		return []resolve.ContentUnit{{Name: name, Data: data}}
	}
	col := &collector{}
	res, err := (&store.Scanner{Limits: lim, Inspector: col}).Scan(name, data)
	out, unscanned := pairUnits(res.Members, col.data)
	if err != nil && !unscanned {
		// A stop always records the unit it cut; this is the guard for one that did not.
		out = append(out, resolve.ContentUnit{Name: name, Unscanned: "incomplete scan: " + err.Error()})
	}
	return out
}

// ScanReader is ScanUnits over a reader. It peeks at the leading bytes: an archive or a compressed blob is
// read to store.MaxArchiveFileBytes(lim) (past it, one unscanned unit naming total_bytes); any other blob is
// read to plainMax (past it, one unscanned unit labelled plainLabel). Memory is bounded by those reads plus
// the members the scanner keeps, which its total_bytes limit bounds.
func ScanReader(name string, r io.Reader, lim store.Limits, plainMax int64, plainLabel string) ([]resolve.ContentUnit, error) {
	br := bufio.NewReaderSize(r, 512)
	head, err := br.Peek(512)
	if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
		return nil, err
	}
	max, label := plainMax, plainLabel
	if store.ArchiveFormat(head) != "" || store.Compression(head) != "" {
		max = store.MaxArchiveFileBytes(lim)
		label = fmt.Sprintf("%s=%d", store.LimitTotalBytes, max)
	}
	b, err := io.ReadAll(io.LimitReader(br, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return []resolve.ContentUnit{{Name: name, Unscanned: label}}, nil
	}
	return ScanUnits(name, b, lim), nil
}

// unpaired is the unscanned label of a member the scanner reports as read whose bytes cannot be paired with it.
const unpaired = "internal: member bytes not paired"

// pairUnits pairs the scanner's members with the bytes the collector kept, in scan order: one collected entry per
// scanned member. The scanner records a member as scanned only after inspecting it, so the counts agree by
// construction. If they ever did not, no pairing can be trusted (bytes could sit under another member's name), so
// every scanned member becomes an unscanned unit naming it: a rule over them is `unchecked`, never `ok`, and no
// member is dropped. unscanned reports whether any unit is unscanned.
func pairUnits(members []store.MemberResult, data [][]byte) (out []resolve.ContentUnit, unscanned bool) {
	scanned := 0
	for _, m := range members {
		if m.Status == store.MemberScanned {
			scanned++
		}
	}
	aligned, k := scanned == len(data), 0
	for _, m := range members {
		switch {
		case m.Status == store.MemberScanned && aligned:
			out = append(out, resolve.ContentUnit{Name: m.Path, Data: data[k]})
			k++
		case m.Status == store.MemberScanned:
			unscanned = true
			out = append(out, resolve.ContentUnit{Name: m.Path, Unscanned: unpaired})
		case m.Status == store.MemberUnscanned:
			unscanned = true
			out = append(out, resolve.ContentUnit{Name: m.Path, Unscanned: m.Limit + "=" + m.Value})
		}
	}
	return out, unscanned
}

// collector keeps the bytes of each member the scanner reads in full, in scan order.
type collector struct{ data [][]byte }

func (c *collector) Inspect(_ string, b []byte) ([]store.ScanFinding, error) {
	c.data = append(c.data, b)
	return nil, nil
}

// MemoContent remembers a content reader's answers for the length of one resolver run, so a blob an edition's
// rules read once per rule and member is enumerated once (the scan of an archive is the cost: ScanUnits walks it
// each call). The answer for a digest is a function of the blob's bytes and the scan limits, so remembering it
// changes no result, only the work.
//
// Memory is bounded: the units kept (their member bytes) never exceed maxKept in total, the byte budget of one
// scan (store.Limits.TotalBytes) when maxKept < 1. An answer that would pass the bound is returned and not kept
// (its next call rescans, as before), and an answer that was not held is never kept. Units are shared between
// callers: a reader of a unit must not modify its Data.
type MemoContent struct {
	inner   resolve.ContentReader
	maxKept int64

	mu   sync.Mutex
	m    map[string][]resolve.ContentUnit
	kept int64
}

// NewMemoContent wraps inner. maxKept < 1 means the default scan budget (store.DefaultLimits().TotalBytes).
func NewMemoContent(inner resolve.ContentReader, maxKept int64) *MemoContent {
	if maxKept < 1 {
		maxKept = store.DefaultLimits().TotalBytes
	}
	return &MemoContent{inner: inner, maxKept: maxKept, m: map[string][]resolve.ContentUnit{}}
}

// Units is the wrapped reader's answer, from memory when this digest was answered before and kept.
func (c *MemoContent) Units(digest string) ([]resolve.ContentUnit, bool) {
	c.mu.Lock()
	if us, ok := c.m[digest]; ok {
		c.mu.Unlock()
		return append([]resolve.ContentUnit(nil), us...), true
	}
	c.mu.Unlock()
	us, held := c.inner.Units(digest)
	if !held {
		return nil, false
	}
	var size int64
	for _, u := range us {
		size += int64(len(u.Data)+len(u.Name)+len(u.Unscanned)) + 64
	}
	c.mu.Lock()
	if _, ok := c.m[digest]; !ok && c.kept+size <= c.maxKept {
		c.m[digest] = append([]resolve.ContentUnit(nil), us...)
		c.kept += size
	}
	c.mu.Unlock()
	return us, true
}
