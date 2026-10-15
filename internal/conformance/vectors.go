package conformance

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/research-common/research-commons/internal/canon"
)

// VectorsPath is the normative vectors file of wire-format note §9, relative to the repo root.
const VectorsPath = "docs/DESIGN-notes-wire-format.vectors.json"

// Vector is one entry of the vectors file, positive or negative. Fields absent from an entry are zero.
type Vector struct {
	Name, Title, Expect string

	// positive vectors (and N6–N13, NE13): a signed string with a signature
	SignedString string
	Bytes        int64
	ID, Sig      string

	// N1–N5: bytes delivered as a stored log line
	Delivered       string
	DeliveredSHA256 string
	DeliveredBytes  int64
	Log             string // N5: the log the line is delivered into

	// NE1–NE12: raw Ed25519 cases
	PublicKey, MessageHex, PinnedStep string
}

// Vectors is the parsed vectors file.
type Vectors struct {
	EIP191Address string
	Positive      []Vector
	Equivalent    struct{ Of, Canonical, V01, HighS string }
	Negative      []Vector
	Ed25519Seed   string
	Ed25519Public string
	Ed25519Signer string
	EdPositive    []Vector
	EdNegative    []Vector
}

// LoadVectors reads the vectors file with the module's own strict parser (never encoding/json).
func LoadVectors() (*Vectors, error) {
	root, err := RepoRoot()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(root, VectorsPath))
	if err != nil {
		return nil, err
	}
	v, err := canon.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("vectors file: %w", err)
	}
	d := &decoder{}
	top := d.obj(v)
	out := &Vectors{}
	out.EIP191Address = d.str(d.obj(d.get(top, "key")), "address")
	for _, e := range d.arr(d.get(top, "positive")) {
		out.Positive = append(out.Positive, d.vector(e))
	}
	eq := d.obj(d.get(top, "equivalent_encodings"))
	out.Equivalent.Of, out.Equivalent.Canonical = d.str(eq, "of"), d.str(eq, "canonical")
	out.Equivalent.V01, out.Equivalent.HighS = d.str(eq, "v_0_1"), d.str(eq, "high_s")
	for _, e := range d.arr(d.get(top, "negative")) {
		out.Negative = append(out.Negative, d.vector(e))
	}
	ed := d.obj(d.get(top, "ed25519"))
	k := d.obj(d.get(ed, "key"))
	out.Ed25519Seed, out.Ed25519Public, out.Ed25519Signer = d.str(k, "seed"), d.str(k, "public"), d.str(k, "signer")
	for _, e := range d.arr(d.get(ed, "positive")) {
		out.EdPositive = append(out.EdPositive, d.vector(e))
	}
	for _, e := range d.arr(d.get(ed, "negative")) {
		out.EdNegative = append(out.EdNegative, d.vector(e))
	}
	if d.err != nil {
		return nil, fmt.Errorf("vectors file: %w", d.err)
	}
	return out, nil
}

type decoder struct{ err error }

func (d *decoder) fail(f string, a ...any) {
	if d.err == nil {
		d.err = fmt.Errorf(f, a...)
	}
}

func (d *decoder) obj(v canon.Value) *canon.Object {
	o, ok := v.(*canon.Object)
	if !ok {
		d.fail("expected object")
		return &canon.Object{Members: map[string]canon.Value{}}
	}
	return o
}

func (d *decoder) arr(v canon.Value) canon.Array {
	a, ok := v.(canon.Array)
	if !ok {
		d.fail("expected array")
	}
	return a
}

func (d *decoder) get(o *canon.Object, k string) canon.Value {
	v, ok := o.Get(k)
	if !ok {
		d.fail("missing %q", k)
	}
	return v
}

func (d *decoder) str(o *canon.Object, k string) string {
	v, ok := o.Get(k)
	if !ok {
		return ""
	}
	s, ok := v.(canon.String)
	if !ok {
		d.fail("%q is not a string", k)
	}
	return string(s)
}

func (d *decoder) int(o *canon.Object, k string) int64 {
	v, ok := o.Get(k)
	if !ok {
		return 0
	}
	n, ok := v.(canon.Int)
	if !ok {
		d.fail("%q is not an integer", k)
	}
	return int64(n)
}

func (d *decoder) vector(v canon.Value) Vector {
	o := d.obj(v)
	x := Vector{
		Name: d.str(o, "name"), Title: d.str(o, "title"), Expect: d.str(o, "expect"),
		SignedString: d.str(o, "signed_string"), Bytes: d.int(o, "bytes"), ID: d.str(o, "id"), Sig: d.str(o, "sig"),
		Delivered: d.str(o, "delivered"), DeliveredSHA256: d.str(o, "delivered_sha256"),
		DeliveredBytes: d.int(o, "delivered_bytes"), Log: d.str(o, "log"),
		PublicKey: d.str(o, "public_key"), MessageHex: d.str(o, "message_hex"), PinnedStep: d.str(o, "pinned_rule_refuses_at"),
	}
	if vv, ok := o.Get("verify"); ok {
		vo := d.obj(vv)
		x.SignedString, x.Sig = d.str(vo, "signed_string"), d.str(vo, "sig")
	}
	return x
}
