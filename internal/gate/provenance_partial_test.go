package gate

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
)

// TestProvenancePartialAtEveryGate: wire §5 says every R field of a listed kind is checked at every gate by the
// one validation core, and `provenance_partial` (workflow R, inputs R, unpinned R, supplied O, environment O) is a
// listed field of `authored`. Each wrong shape is signed validly (the signature and the canonical form pass,
// which is what makes the schema the thing that refuses) and delivered to pull, hub check, push and the
// pre-pin check: each refuses it intrinsic, malformed statement, naming the member and scoping the object, and
// the well-formed control beside it is admitted at all four, so the refusal is the field's and not the fixture's.
func TestProvenancePartialAtEveryGate(t *testing.T) {
	d := func(n string) string { return blobDigest([]byte(n)) }
	partial := func(kv ...any) *canon.Object {
		base := []any{"workflow", d("wf"), "inputs", []string{d("in")}, "unpinned", []string{"tag:latest"}}
		m := map[string]any{}
		var order []string
		for i := 0; i < len(base); i += 2 {
			m[base[i].(string)] = base[i+1]
			order = append(order, base[i].(string))
		}
		for i := 0; i < len(kv); i += 2 {
			if _, ok := m[kv[i].(string)]; !ok {
				order = append(order, kv[i].(string))
			}
			m[kv[i].(string)] = kv[i+1]
		}
		var args []any
		for _, k := range order {
			if m[k] != nil {
				args = append(args, k, m[k])
			}
		}
		return obj(args...)
	}
	cases := []struct {
		name   string
		v      canon.Value // the provenance_partial value
		detail string      // "" = admitted
	}{
		{"control: required members", partial(), ""},
		{"control: supplied and environment", partial("supplied", canon.Value(obj("tag:latest", d("bytes"))),
			"environment", canon.Value(obj("platform", "linux/amd64"))), ""},
		{"not an object", canon.Int(5), "body.provenance_partial is not an object"},
		{"workflow missing", partial("workflow", nil), "body.provenance_partial.workflow is missing"},
		{"bad digest in inputs", partial("inputs", []string{d("in"), "sha256:zz"}), "body.provenance_partial.inputs[1] is not a content digest"},
		{"non-string in unpinned", partial("unpinned", canon.Array{canon.String("a"), canon.Int(3)}), "body.provenance_partial.unpinned[1] is not a string"},
		{"non-digest in supplied", partial("supplied", canon.Value(obj("tag:latest", "bytes"))), "body.provenance_partial.supplied.tag:latest is not a content digest"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			id := w.authored("A", []byte("x"), "provenance_partial", c.v)
			pkg := Package{Objects: []Object{w.object(id)}}
			for _, g := range gates {
				rep := mustAdmit(t, g, pkg, MemHeld{}, nil, Options{})
				if c.detail == "" {
					wantAdmitted(t, rep, w.path(id))
					continue
				}
				r := wantRefused(t, rep, w.path(id), refusal.Intrinsic, refusal.MalformedStatement)
				if !strings.Contains(r.Refusal.Detail, c.detail) {
					t.Fatalf("%s: detail %q lacks %q", g, r.Refusal.Detail, c.detail)
				}
			}
		})
	}
}
