package wire

import "github.com/research-common/research-commons/internal/canon"

// LineReader reads one received line. Read, *Reader, *IdentityReader and *DualReader implement it.
type LineReader interface {
	Read(line []byte) (*Statement, error)
}

// ReadFunc adapts a function to LineReader.
type ReadFunc func(line []byte) (*Statement, error)

// Read calls f.
func (f ReadFunc) Read(line []byte) (*Statement, error) { return f(line) }

// DualReader is the dual-major reader (fixed-root identity profile, docs/DESIGN-notes-fixed-root-identity.md §2.4),
// the reader every production path reads stored and received lines with (ReadStored). It dispatches each line by
// its rc major and nothing else:
//
//   - an rc/1 line, and any line whose major is neither 1 nor CandidateMajor, goes through Read unchanged: the same
//     refusals, the same statuses, the same ids. An rc/1 envelope `x_actor_v1` is not read; an rc/1 `crit` naming
//     `x_identity_v1` is unsupported, exactly as Read says.
//   - an rc/2 line goes through IdentityReader: verified, its marker and actor read, a verified line that breaks a
//     candidate rule held as Invalid.
//
// A line whose rc cannot be read at all is Read's to refuse. The dispatch never looks at anything but the major,
// so an rc/1 corpus reads byte for byte as under Read. Major stays 1: it is Read's major and the major this tool's
// writer signs bare-key statements in (WriterMajor), not the set of majors its reader reads (ReaderMajors).
type DualReader struct {
	id *IdentityReader
}

// NewDualReader returns the candidate dual-major reader.
func NewDualReader() *DualReader { return &DualReader{id: NewIdentityReader()} }

// Read parses one received line. See DualReader.
func (r *DualReader) Read(line []byte) (*Statement, error) {
	st, err := Read(line)
	switch {
	case err == nil && st.RC != "rc/2":
		return st, nil
	case err == nil:
		return r.id.Read(line)
	case candidateMajorLine(line):
		// Read refused an rc/2 line on its other-major linkage contract; the candidate reader decides it.
		return r.id.Read(line)
	}
	return nil, err
}

// ReaderMajors are the format majors the production reader (ReadStored) verifies and interprets: rc/1, and rc/2
// under the fixed-root identity profile. The writer signs both too, each statement in its WriterMajor.
var ReaderMajors = []int{Major, CandidateMajor}

var stored = NewDualReader()

// StoredReader is the production line reader as a LineReader (ReadStored).
var StoredReader LineReader = ReadFunc(ReadStored)

// ReadStored is the production line reader: every statement a store installs, a gate admits or a view resolves is
// read through it. It is the dual-major reader: rc/1 exactly as Read, rc/2 verified under the identity profile (a
// bad rc/2 signature is refused, as an rc/1 one is), any other major Read's unverified linkage path. Read stays
// the rc/1-only reader the differential tests compare against.
func ReadStored(line []byte) (*Statement, error) { return stored.Read(line) }

// CandidateMajorLine reports whether line is a JSON object whose rc is rc/2: the cheap test a reader uses to tell
// whether a held set carries any identity-profile evidence before admitting it.
func CandidateMajorLine(line []byte) bool { return candidateMajorLine(line) }

// candidateMajorLine reports whether line parses as an object whose rc names CandidateMajor. Anything else
// (unparseable, over the size bound, another major) is not dispatched to the candidate reader.
func candidateMajorLine(line []byte) bool {
	if len(line) > MaxLine {
		return false
	}
	v, err := canon.Parse(line)
	if err != nil {
		return false
	}
	o, ok := v.(*canon.Object)
	if !ok {
		return false
	}
	rc, ok := o.Members["rc"].(canon.String)
	return ok && string(rc) == "rc/2"
}
