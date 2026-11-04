package store

// Archive ingest (storage note §8; C-core-04 delivery (c)).
//
// ReadArchive lists the members of a tar archive, plain or gzip-compressed, so that a caller can judge them as
// one package exactly as it judges a directory tree. It walks the archive under the scan Limits (members,
// total_bytes, path_bytes, expansion_ratio), and it never extracts: no member name is ever used as a filesystem
// path. A member is a name, a type and bytes; where admitted bytes go is decided by whoever judges them (for a
// pull, the gate installs them by digest or statement id, never by the member's name). Nested archives are not
// descended: a member's bytes are data, whatever they look like.
//
// The per-member read bound is the caller's (Limits.MemberBytes): a member larger than it is read to the bound
// plus one byte, exactly as a directory tree's file is, so the judge refuses it with its own size limit and
// the result is the same for both deliveries. A limit that stops the run (members, total_bytes, the
// expansion ratio of the gzip stream) or an archive that is truncated or corrupt is an operational refusal
// naming the limit and the scope it cut; the members read so far are returned beside it, the scan record is
// incomplete, and they must not be judged as the whole package.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/research-common/research-commons/internal/refusal"
)

// MemberType is what an archive member is. Only a regular file carries bytes.
type MemberType string

const (
	TypeFile    MemberType = "file"
	TypeSymlink MemberType = "symlink"
	// TypeOther is every member that is neither a regular file nor a symbolic link: a hard link, a character or
	// block device, a fifo, a sparse or contiguous file, an unknown type flag.
	TypeOther MemberType = "other"
)

// Archive ingest formats, as IngestFormat names them.
const (
	FormatTar     = "tar"
	FormatTarGzip = "tar+gzip"
)

// Reasons of the archive refusals. Each refuses the archive whole: no member of it is judged.
const (
	// ReasonTruncatedArchive (operational): the archive cannot be read to its end.
	ReasonTruncatedArchive = "truncated archive"
	// ReasonMalformedArchive (intrinsic): the archive reads, but not as one package every reader agrees on (two
	// members with one name, bytes after the end).
	ReasonMalformedArchive = "malformed archive"
)

// ArchiveMember is one member of an archive read for ingest.
type ArchiveMember struct {
	// Name is the member name as the archive carries it, with one leading "./" removed (what `tar -C dir .`
	// writes before every name); never otherwise cleaned or joined. A name over path_bytes is replaced by
	// "<name of N bytes>".
	Name string
	Type MemberType
	// Data is the member's bytes; nil for a member that is not a regular file, a member the caller skipped, or
	// one whose name is over path_bytes. A member larger than the read bound carries the bound plus one byte.
	Data []byte
	// Skipped: the caller's skip function selected the member; it was counted and its bytes were not read.
	Skipped bool
}

// Archive is a read archive: its format, its members in archive order and the record of the walk.
type Archive struct {
	Format  string
	Members []ArchiveMember
	Scan    *ScanResult
}

// IngestFormat names what the leading bytes of a file are: FormatTar, FormatTarGzip, "gzip" (a gzip stream that
// does not start with a tar), "zip", the name of a compression this module has no reader for (xz, bzip2, zstd,
// 7z, rar, lz4), or "" (none of these). head should hold at least the first 64 KiB of the file, or all of it.
func IngestFormat(head []byte) string {
	switch sniff(head) {
	case "tar":
		return FormatTar
	case "zip":
		return "zip"
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(head))
		if err != nil {
			return "gzip"
		}
		zr.Multistream(false)
		inner := make([]byte, 512)
		n, _ := io.ReadFull(zr, inner)
		if sniff(inner[:n]) == "tar" {
			return FormatTarGzip
		}
		if n < 262 {
			// too short to show a tar header: a small gzip of something else, or a tar.gz cut off (or corrupt)
			// before its first header. A stream that does not decode to its trailer is the latter, and reading it
			// as an archive reports it as not read to its end, rather than as a file of another format.
			if _, err := io.Copy(io.Discard, zr); err != nil {
				return FormatTarGzip
			}
		}
		return "gzip"
	}
	return isCompressedOther(head)
}

// MaxArchiveFileBytes bounds the size of an archive file read for ingest: the total_bytes budget plus what a tar
// can spend outside member data under the members limit (per member a header, an extended or long-name header
// and padding, under 4 KiB) and one closing record. A larger file cannot be read within the limits.
func MaxArchiveFileBytes(lim Limits) int64 {
	lim = lim.resolved()
	return lim.TotalBytes + int64(lim.Members)*4096 + 10240
}

// ReadArchive reads a tar archive, plain or gzip-compressed, for ingest under lim. skip, when not nil, selects
// members whose bytes are not read (they are listed, Skipped, and counted against the members limit). On a
// run-level stop it returns the partial archive and an operational refusal; the partial Scan is not Complete.
func ReadArchive(data []byte, lim Limits, skip func(name string) bool) (*Archive, error) {
	run := &scanRun{sc: &Scanner{Limits: lim}, lim: lim.resolved()}
	run.res = &ScanResult{Limits: run.lim}
	a := &Archive{Scan: run.res}
	err := run.ingest(a, data, skip)
	run.res.Complete = err == nil && len(run.res.Unscanned()) == 0
	var r *refusal.Refusal
	if errors.As(err, &r) {
		run.res.Stopped = r
	}
	return a, err
}

func (r *scanRun) ingest(a *Archive, data []byte, skip func(string) bool) error {
	switch f := IngestFormat(data); f {
	case FormatTar:
		a.Format = f
		return r.ingestTar(a, data, skip)
	case FormatTarGzip:
		a.Format = f
		br := bytes.NewReader(data)
		zr, err := gzip.NewReader(br)
		if err != nil {
			return truncated("gzip header", err)
		}
		zr.Multistream(false)
		// The gzip stream is the container, not a member: its decompressed size is bounded by what a plain tar
		// may be (MaxArchiveFileBytes) and by the expansion ratio, checked as it is read.
		max := MaxArchiveFileBytes(r.lim)
		lr := &ratioReader{r: io.LimitReader(zr, max+1), in: int64(len(data)), ratio: r.lim.ExpansionRatio}
		inner, err := io.ReadAll(lr)
		switch {
		case lr.over:
			r.unscanned("<gzip stream>", 1, LimitRatio, r.lim.ExpansionRatio, "decompressed stream past the expansion ratio")
			return r.stop(LimitRatio, r.lim.ExpansionRatio, "scope: the whole archive (its decompressed tar was not read to the end)")
		case err != nil:
			return truncated("gzip stream", err)
		case int64(len(inner)) > max:
			r.unscanned("<gzip stream>", 1, LimitTotalBytes, r.lim.TotalBytes, "decompressed stream larger than the scan's byte budget allows")
			return r.stop(LimitTotalBytes, r.lim.TotalBytes, "scope: the whole archive (its decompressed tar was not read to the end)")
		}
		if err := trailing("gzip stream", data[len(data)-br.Len():]); err != nil {
			return err
		}
		return r.ingestTar(a, inner, skip)
	}
	return errors.New("store: ReadArchive reads a tar archive, plain or gzip-compressed")
}

// ratioReader stops a decompression bomb while it is read: past 1 MiB, more than ratio bytes out per byte in
// sets over and ends the stream.
type ratioReader struct {
	r       io.Reader
	in, out int64
	ratio   int64
	over    bool
}

func (x *ratioReader) Read(p []byte) (int, error) {
	if x.over {
		return 0, io.EOF
	}
	n, err := x.r.Read(p)
	x.out += int64(n)
	if x.out > 1<<20 && x.out > x.in*x.ratio {
		x.over = true
		return n, io.EOF
	}
	return n, err
}

// trailing refuses bytes after the end of a container that are not zero padding. Readers disagree about them
// (a second gzip member is more data to gunzip and nothing to a single-member reader; data after a tar's end
// is ignored by most tar readers and read by some), so one archive could be two packages to two readers; this
// reader refuses it as malformed rather than pick one.
func trailing(what string, rest []byte) error {
	for i, b := range rest {
		if b != 0 {
			return &refusal.Refusal{Class: refusal.Intrinsic, Reason: ReasonMalformedArchive,
				Detail: fmt.Sprintf("%d byte(s) after the end of the %s, not zero padding (first non-zero at offset %d after the end); readers disagree about such bytes, so the archive is refused whole", len(rest), what, i)}
		}
	}
	return nil
}

func truncated(what string, err error) error {
	return &refusal.Refusal{Class: refusal.Operational, Reason: ReasonTruncatedArchive,
		Detail: fmt.Sprintf("the %s is truncated or corrupt (%v); the archive was not read to its end", what, err)}
}

func (r *scanRun) ingestTar(a *Archive, data []byte, skip func(string) bool) error {
	br := bytes.NewReader(data)
	tr := tar.NewReader(br)
	seen := map[string]bool{}
	for n := 0; ; n++ {
		h, err := tr.Next()
		if err == io.EOF {
			return trailing("tar archive", data[len(data)-br.Len():])
		}
		if err != nil {
			r.unscanned(fmt.Sprintf("<after member %d>", n), 1, LimitTruncated, "tar", "tar stream is truncated or corrupt: "+err.Error())
			return truncated(fmt.Sprintf("tar stream after %d member(s)", n), err)
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			n-- // archive-wide metadata (`git archive` records its commit here), not a member
			continue
		}
		if n >= r.lim.Members {
			r.unscanned(fmt.Sprintf("<members from %d on>", n+1), 1, LimitMembers, r.lim.Members, "more members than the limit; the rest were not listed")
			return r.stop(LimitMembers, r.lim.Members, fmt.Sprintf("scope: every member after the first %d", r.lim.Members))
		}
		name := strings.TrimPrefix(h.Name, "./")
		if h.Typeflag == tar.TypeDir || name == "" {
			// a directory carries nothing (a tree's directories are not objects either); the caller's skip function
			// still sees it, with its trailing slash, so a skipped directory is listed even when it is empty
			r.res.Members = append(r.res.Members, MemberResult{Path: name, Depth: 1, Status: MemberSkipped})
			if name != "" && skip != nil && skip(name) {
				a.Members = append(a.Members, ArchiveMember{Name: name, Type: TypeOther, Skipped: true})
			}
			continue
		}
		if seen[name] {
			// A tar may carry one name twice (an appended update); extraction keeps the last, a listing shows both,
			// and a judge that read either would answer for bytes another reader never sees. A tree cannot hold one
			// path twice, so neither can a package.
			return &refusal.Refusal{Class: refusal.Intrinsic, Reason: ReasonMalformedArchive,
				Detail: fmt.Sprintf("two members named %q; a package holds each path once, so the archive is refused whole", name)}
		}
		seen[name] = true
		m := ArchiveMember{Name: name, Type: TypeOther}
		switch {
		case h.Typeflag == tar.TypeReg && !sparse(h): // archive/tar reports the legacy '\x00' regular type as TypeReg
			m.Type = TypeFile
		case h.Typeflag == tar.TypeSymlink:
			m.Type = TypeSymlink
		}
		if len(name) > r.lim.PathBytes {
			// listed under a placeholder name with no bytes, so the judge refuses it as a path outside the package
			// layout (no layout path is this long); the name itself is not carried
			m.Name, m.Type = fmt.Sprintf("<name of %d bytes>", len(name)), TypeFile
			r.unscanned(m.Name, 1, LimitPathBytes, r.lim.PathBytes, "member name over the limit")
			a.Members = append(a.Members, m)
			continue
		}
		if m.Type != TypeFile {
			r.res.Members = append(r.res.Members, MemberResult{Path: name, Depth: 1, Status: MemberSkipped})
			a.Members = append(a.Members, m)
			continue
		}
		if skip != nil && skip(name) {
			m.Skipped = true
			r.res.Members = append(r.res.Members, MemberResult{Path: name, Depth: 1, Status: MemberSkipped, Detail: "skipped by the caller"})
			a.Members = append(a.Members, m)
			continue
		}
		want := h.Size
		if want < 0 {
			return truncated(fmt.Sprintf("member %q header", name), errors.New("negative size"))
		}
		over := want > r.lim.MemberBytes
		if over {
			want = r.lim.MemberBytes + 1
		}
		if r.res.BytesRead+want > r.lim.TotalBytes {
			r.unscanned(name, 1, LimitTotalBytes, r.lim.TotalBytes, "read would pass the scan's byte budget")
			return r.stop(LimitTotalBytes, r.lim.TotalBytes, fmt.Sprintf("scope: member %q and every member after it", name))
		}
		b := make([]byte, want)
		if _, err := io.ReadFull(tr, b); err != nil {
			r.unscanned(name, 1, LimitTruncated, "member", "member is truncated or corrupt: "+err.Error())
			return truncated(fmt.Sprintf("member %q", name), err)
		}
		r.res.BytesRead += want
		m.Data = b
		if over {
			r.unscanned(name, 1, LimitMemberBytes, r.lim.MemberBytes, fmt.Sprintf("member declares %d bytes; read to the bound plus one", h.Size))
		} else {
			r.scanned(name, 1)
		}
		a.Members = append(a.Members, m)
	}
}

// sparse reports a member stored as a sparse file (GNU or PAX sparse records). archive/tar expands it, but the
// bytes a reader sees then depend on the reader's sparse support, and no package producer writes one: it is
// listed as TypeOther, so the judge refuses it as a non-regular file.
func sparse(h *tar.Header) bool {
	for k := range h.PAXRecords {
		if strings.HasPrefix(k, "GNU.sparse.") {
			return true
		}
	}
	return false
}
