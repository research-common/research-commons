package gate

import (
	"bufio"
	"fmt"
	"io"

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
