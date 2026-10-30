// Package fixture generates abstract statement sets for property tests (CONFORMANCE.md §Properties).
//
// A fixture is abstract: keys are names ("A", "B"), blobs are names ("X", "W"), times are integers. Keeping
// it abstract lets the same fixture language describe resolver inputs written by hand or by another tool (a
// reference model, for instance) without any of them owning keys. Concretizing a fixture into signed
// statements is the job of the layer under test (it owns keys and encodings).
//
// Every fixture comes from a seed. A failing property prints the seed and a shrunk fixture as canonical JSON,
// so the failure can be replayed exactly and read by hand.
package fixture

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

// Statement is one abstract statement. Only the fields its kind uses are set.
type Statement struct {
	Kind   string
	Signer string
	Seq    int
	Blob   string
	Prov   *Provenance
	Fields map[string]string
	// Label names the statement across shrinking and renumbering ("s0", "s1", ...); Of names the earlier
	// statement (by Label) that corroborates, retracts, refutes or an edition entry refers to. A label that no
	// longer exists (a shrunk fixture) is a reference to a statement the reader does not hold.
	Label, Of string
	// Time is the signer-asserted ts as seconds after a fixed epoch.
	Time int
}

// Provenance names a workflow blob and input blobs.
type Provenance struct {
	Workflow string
	Inputs   []string
}

// Fixture is a statement set. Order is delivery order; properties permute it.
type Fixture struct {
	Seed       uint64
	Statements []Statement
}

// Options bound what Gen draws from.
type Options struct {
	Keys, Blobs, MaxStatements int
	Kinds                      []string
	// Extended draws the fields the later views read: an observation's class and a corroboration's verdict,
	// and the Of reference of the kinds that name another statement. It consumes randomness only for the kinds
	// it adds, so the fixtures of Default are unchanged by this option existing.
	Extended bool
}

// Default draws from three keys, four blobs and the kinds the wire layer reads today.
var Default = Options{Keys: 3, Blobs: 4, MaxStatements: 12, Kinds: []string{"authored", "holds", "describes", "observed"}}

// Extended draws every statement kind the resolver reads: the Default kinds plus editions of one resource,
// corroborations, retractions and refutations that name an earlier statement, anchors and reproductions.
var Extended = Options{Keys: 4, Blobs: 4, MaxStatements: 12, Extended: true,
	Kinds: []string{"authored", "holds", "describes", "observed", "observed", "edition", "corroborates", "retracts", "refutes", "anchors", "reproduced"}}

// Gen draws one fixture from seed. Each signer's statements carry consecutive seq from 0, so every fixture
// is a set of well-formed per-key logs; a property that needs gaps or forks builds them from this.
func Gen(seed uint64, o Options) Fixture {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	n := 1 + r.IntN(o.MaxStatements)
	seq := map[string]int{}
	f := Fixture{Seed: seed}
	for i := 0; i < n; i++ {
		signer := string(rune('A' + r.IntN(o.Keys)))
		s := Statement{
			Kind:   o.Kinds[r.IntN(len(o.Kinds))],
			Signer: signer,
			Seq:    seq[signer],
			Blob:   blob(r, o),
			Time:   seq[signer]*60 + r.IntN(60),
			Label:  fmt.Sprint("s", i),
		}
		seq[signer]++
		if o.Extended {
			switch s.Kind {
			case "corroborates", "retracts", "refutes", "reproduced", "edition":
				if i > 0 {
					s.Of = fmt.Sprint("s", r.IntN(i))
				}
			}
			switch s.Kind {
			case "corroborates":
				s.Fields = map[string]string{"verdict": []string{"supports", "contradicts", "inconclusive"}[r.IntN(3)]}
			case "observed":
				s.Fields = map[string]string{"class": []string{"exact-bytes", "source", "none-yet"}[r.IntN(3)],
					"licence": []string{"CC0-1.0", "MIT"}[r.IntN(2)]}
			}
		}
		if s.Kind == "authored" && r.IntN(2) == 0 {
			s.Prov = &Provenance{Workflow: "W", Inputs: []string{blob(r, o)}}
		}
		if s.Fields == nil && (s.Kind == "authored" || s.Kind == "observed") {
			s.Fields = map[string]string{"licence": []string{"CC0-1.0", "CC-BY-4.0", "MIT"}[r.IntN(3)]}
		}
		f.Statements = append(f.Statements, s)
	}
	return f
}

func blob(r *rand.Rand, o Options) string { return string(rune('X' - o.Blobs + 1 + r.IntN(o.Blobs))) }

// Permute returns the statements in a seeded random order.
func (f Fixture) Permute(seed uint64) []Statement {
	r := rand.New(rand.NewPCG(seed, 1))
	out := slices.Clone(f.Statements)
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// JSON renders the fixture in canonical JSON (for failure reports and for sharing fixtures outside Go).
func (f Fixture) JSON() string {
	stmts := canon.Array{}
	for _, s := range f.Statements {
		o := obj("kind", canon.String(s.Kind), "signer", canon.String(s.Signer), "seq", canon.Int(s.Seq), "time", canon.Int(s.Time))
		if s.Blob != "" {
			set(o, "blob", canon.String(s.Blob))
		}
		if s.Label != "" {
			set(o, "label", canon.String(s.Label))
		}
		if s.Of != "" {
			set(o, "of", canon.String(s.Of))
		}
		if s.Prov != nil {
			in := canon.Array{}
			for _, x := range s.Prov.Inputs {
				in = append(in, canon.String(x))
			}
			set(o, "provenance", obj("workflow", canon.String(s.Prov.Workflow), "inputs", in))
		}
		if len(s.Fields) > 0 {
			fo := obj()
			for k, v := range s.Fields {
				set(fo, k, canon.String(v))
			}
			set(o, "fields", fo)
		}
		stmts = append(stmts, o)
	}
	return string(canon.Encode(obj("seed", canon.Int(int64(f.Seed&canon.MaxInt)), "statements", stmts)))
}

func obj(kv ...any) *canon.Object {
	o := &canon.Object{Members: map[string]canon.Value{}}
	for i := 0; i < len(kv); i += 2 {
		set(o, kv[i].(string), kv[i+1].(canon.Value))
	}
	return o
}

func set(o *canon.Object, k string, v canon.Value) {
	if _, ok := o.Members[k]; !ok {
		o.Keys = append(o.Keys, k)
	}
	o.Members[k] = v
}

// Check runs prop over n seeds starting at base. On the first failure it shrinks the fixture (dropping one
// statement at a time while prop still fails, then renumbering seq per signer) and reports the seed and the
// shrunk fixture. prop returns "" when the property holds, else a description of the violation.
func Check(t *testing.T, base uint64, n int, o Options, prop func(Fixture) string) {
	t.Helper()
	for i := 0; i < n; i++ {
		seed := base + uint64(i)
		f := Gen(seed, o)
		if msg := prop(f); msg != "" {
			small, smallMsg := shrink(f, prop, msg)
			t.Fatalf("property failed for seed %d: %s\nshrunk (%d of %d statements): %s\nshrunk failure: %s",
				seed, msg, len(small.Statements), len(f.Statements), small.JSON(), smallMsg)
		}
	}
}

func shrink(f Fixture, prop func(Fixture) string, msg string) (Fixture, string) {
	for changed := true; changed; {
		changed = false
		for i := range f.Statements {
			c := Fixture{Seed: f.Seed, Statements: renumber(slices.Delete(slices.Clone(f.Statements), i, i+1))}
			if len(c.Statements) == 0 {
				continue
			}
			if m := prop(c); m != "" {
				f, msg, changed = c, m, true
				break
			}
		}
	}
	return f, msg
}

func renumber(s []Statement) []Statement {
	seq := map[string]int{}
	for i := range s {
		s[i].Seq = seq[s[i].Signer]
		seq[s[i].Signer]++
	}
	return s
}

// String is a short form for logs.
func (s Statement) String() string {
	return fmt.Sprintf("%s/%d %s %s", s.Signer, s.Seq, s.Kind, s.Blob)
}
