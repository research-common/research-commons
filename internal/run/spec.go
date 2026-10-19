package run

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
)

// The workflow spec (execution note §1): a blob whose bytes are canonical JSON. The spec pins the computation;
// the replication mode, comparator and environment_match are the author's, on the workflow's `authored`
// statement, never here (§1 rule 2).
//
// The note fixes the fields and their meaning but no wire encoding for the spec blob. This file reads the
// field names of the §1 table as top-level members, with these encodings (provisional until the wire note
// fixes them):
//
//	code         digest (the executable bytes, staged as the input named "code")
//	inputs       object: name → full content digest; any other string (a tag, a URL, a path) is unpinned
//	interpreter  string: the runtime name and version constraint
//	image        object: reference string, digest (an OCI digest)
//	parameters   object (free; hashed with the spec)
//	env          object: name → string (the declared environment, §6)
//	network      "none", or {"required": [endpoint, ...]}
//	resources    object of integers: cpus (milli-CPUs), memory and disk (bytes), pids, wall_time (milliseconds)
//	outputs      object: name → relative file name inside the output directory
//	declared_deps any (carried verbatim into the environment record)

var reDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// IsDigest reports whether s is a full content digest (wire §8).
func IsDigest(s string) bool { return reDigest.MatchString(s) }

// Digest is the content digest of b.
func Digest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Input is one named input of a spec.
type Input struct {
	Name string
	// Ref is the value as written: a digest when pinned, anything else when not.
	Ref string
}

// Pinned reports whether the input is named by a full content hash (§1: provenance is the pair (workflow hash,
// input hashes)).
func (i Input) Pinned() bool { return IsDigest(i.Ref) }

// Output is one declared output: its name and its relative file name in the output directory.
type Output struct{ Name, File string }

// Image is a spec's image pin.
type Image struct{ Reference, Digest string }

// Resources is a resource profile, a set of caps or a reader ceiling: cap name → value. A cap that is absent
// is undeclared (spec) or unlimited by this source (ceiling).
type Resources map[string]int64

// CapNames lists the caps in display order (§2.2).
var CapNames = []string{CapCPUs, CapMemory, CapPids, CapDisk, CapWallTime}

// Spec is a parsed workflow spec.
type Spec struct {
	// Digest is the spec blob's digest: the workflow hash in provenance.
	Digest      string
	Code        string
	Inputs      []Input // sorted by name (the key order of the spec object)
	Interpreter string
	Image       *Image // nil when the spec pins none
	Parameters  *canon.Object
	Env         map[string]string
	// Network is nil for `none`; otherwise the endpoints a `required` network declares.
	Network   []string
	Resources Resources
	Outputs   []Output // sorted by name
	Deps      canon.Value
	// Ignored names fields found in the spec that belong on the workflow's `authored` statement (§1 rule 2):
	// shown as `replication: declared in spec body, ignored`, never read.
	Ignored []string
}

// statementOnly are the fields that live on the workflow's `authored` statement, never in the spec (§1 rule 2).
var statementOnly = []string{"comparator", "environment_match", "replication"}

func malformedWorkflow(format string, args ...any) *refusal.Refusal {
	r := refusal.Malformed(format, args...)
	r.Reason = "malformed workflow"
	return r
}

// ParseSpec reads a spec blob. It refuses (intrinsic: malformed workflow) a spec whose pins are incomplete for
// any run: no code, no interpreter, no outputs (§1 table, "if missing: refuse"), or a field of the wrong type.
// An unpinned input is not refused here: partial provenance is disclosed, not forbidden (§1 rule 1).
func ParseSpec(b []byte) (*Spec, error) {
	v, err := canon.Parse(b)
	if err != nil {
		return nil, err
	}
	o, ok := v.(*canon.Object)
	if !ok {
		return nil, malformedWorkflow("spec is not an object")
	}
	s := &Spec{Digest: Digest(b), Env: map[string]string{}, Resources: Resources{}}
	str := func(k string, required bool) (string, error) {
		x, ok := o.Get(k)
		if !ok {
			if required {
				return "", malformedWorkflow("spec.%s is missing", k)
			}
			return "", nil
		}
		y, ok := x.(canon.String)
		if !ok {
			return "", malformedWorkflow("spec.%s is not a string", k)
		}
		return string(y), nil
	}
	if s.Code, err = str("code", true); err != nil {
		return nil, err
	}
	if !IsDigest(s.Code) {
		return nil, malformedWorkflow("spec.code is not a content digest")
	}
	if s.Interpreter, err = str("interpreter", true); err != nil {
		return nil, err
	}
	if s.Interpreter == "" {
		return nil, malformedWorkflow("spec.interpreter is empty")
	}
	if s.Inputs, err = namedStrings(o, "inputs", false); err != nil {
		return nil, err
	}
	outs, err := namedStrings(o, "outputs", true)
	if err != nil {
		return nil, err
	}
	if len(outs) == 0 {
		return nil, malformedWorkflow("spec.outputs is empty")
	}
	for _, x := range outs {
		s.Outputs = append(s.Outputs, Output{Name: x.Name, File: x.Ref})
	}
	if x, ok := o.Get("image"); ok {
		io, ok := x.(*canon.Object)
		if !ok {
			return nil, malformedWorkflow("spec.image is not an object")
		}
		ref, _ := io.Get("reference")
		dg, _ := io.Get("digest")
		rs, ok1 := ref.(canon.String)
		ds, ok2 := dg.(canon.String)
		if !ok1 || !ok2 {
			return nil, malformedWorkflow("spec.image needs reference and digest strings (an image is pinned by reference and per-platform manifest digest)")
		}
		if !IsDigest(string(ds)) {
			return nil, malformedWorkflow("spec.image.digest is not an OCI digest (sha256: + 64 lowercase hex)")
		}
		s.Image = &Image{Reference: string(rs), Digest: string(ds)}
	}
	if x, ok := o.Get("parameters"); ok {
		po, ok := x.(*canon.Object)
		if !ok {
			return nil, malformedWorkflow("spec.parameters is not an object")
		}
		s.Parameters = po
	}
	if env, err := namedStrings(o, "env", false); err != nil {
		return nil, err
	} else {
		for _, e := range env {
			s.Env[e.Name] = e.Ref
		}
	}
	if x, ok := o.Get("network"); ok {
		switch n := x.(type) {
		case canon.String:
			if n != "none" {
				return nil, malformedWorkflow("spec.network is neither \"none\" nor {\"required\": [...]}")
			}
		case *canon.Object:
			rq, ok := n.Get("required")
			arr, ok2 := rq.(canon.Array)
			if !ok || !ok2 {
				return nil, malformedWorkflow("spec.network.required is not a list of endpoints")
			}
			s.Network = []string{}
			for _, e := range arr {
				es, ok := e.(canon.String)
				if !ok {
					return nil, malformedWorkflow("spec.network.required holds a non-string")
				}
				s.Network = append(s.Network, string(es))
			}
		default:
			return nil, malformedWorkflow("spec.network is neither \"none\" nor {\"required\": [...]}")
		}
	}
	if x, ok := o.Get("resources"); ok {
		ro, ok := x.(*canon.Object)
		if !ok {
			return nil, malformedWorkflow("spec.resources is not an object")
		}
		for _, k := range ro.Keys {
			n, ok := ro.Members[k].(canon.Int)
			if !ok || n < 0 {
				return nil, malformedWorkflow("spec.resources.%s is not a non-negative integer", k)
			}
			if knownCap(k) {
				s.Resources[k] = int64(n)
			}
		}
	}
	if x, ok := o.Get("declared_deps"); ok {
		s.Deps = x
	}
	for _, k := range statementOnly {
		if _, ok := o.Get(k); ok {
			s.Ignored = append(s.Ignored, k)
		}
	}
	return s, nil
}

func knownCap(k string) bool {
	for _, c := range CapNames {
		if c == k {
			return true
		}
	}
	return false
}

// namedStrings reads an object of name → string, sorted by name.
func namedStrings(o *canon.Object, k string, required bool) ([]Input, error) {
	x, ok := o.Get(k)
	if !ok {
		if required {
			return nil, malformedWorkflow("spec.%s is missing", k)
		}
		return nil, nil
	}
	m, ok := x.(*canon.Object)
	if !ok {
		return nil, malformedWorkflow("spec.%s is not an object", k)
	}
	var out []Input
	for _, name := range m.Keys {
		v, ok := m.Members[name].(canon.String)
		if !ok {
			return nil, malformedWorkflow("spec.%s.%s is not a string", k, strconv.Quote(name))
		}
		out = append(out, Input{Name: name, Ref: string(v)})
	}
	sort.Slice(out, func(i, j int) bool { return canon.CompareKeys(out[i].Name, out[j].Name) < 0 })
	return out, nil
}

// Unpinned lists the inputs named by anything but a full content hash, as "name (ref)". A run of such a spec
// has partial provenance: it joins no derivation group and `verify` exits 4 naming the input (§1 rule 1).
func (s *Spec) Unpinned() []string {
	var out []string
	for _, in := range s.Inputs {
		if !in.Pinned() {
			out = append(out, in.Name+" ("+strconv.Quote(in.Ref)+")")
		}
	}
	return out
}

// InputDigests are the pinned inputs' digests in spec order: the `inputs` of a provenance block.
func (s *Spec) InputDigests() []string {
	var out []string
	for _, in := range s.Inputs {
		if in.Pinned() {
			out = append(out, in.Ref)
		}
	}
	return out
}

// Acquisition reports whether the spec declares a network requirement: its outputs are observations, never
// derivations (§1 rule 3).
func (s *Spec) Acquisition() bool { return s.Network != nil }

// IgnoredDisplay is what a surface shows for fields found in the spec that belong on the statement.
func (s *Spec) IgnoredDisplay() []string {
	var out []string
	for _, k := range s.Ignored {
		out = append(out, k+": declared in spec body, ignored")
	}
	return out
}
