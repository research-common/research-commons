package resolve

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

const unsupportedMarker = "x_resolver_test_unknown"

// signDraft uses real signatures and the normal wire/log ingestion path, not a
// hand-built Placed or a mutation of the resolver's validity flags. All keys are
// deterministic synthetic test keys from testKey.
func signDraft(w *world, name, by string, d wire.Draft) string {
	w.t.Helper()
	d.Seq, d.Prev = w.seq[by], w.head[by]
	d.TS = fmt.Sprintf("2026-10-16T02:%02d:%02dZ", d.Seq/60%60, d.Seq%60)
	line, id := wire.Sign(d, w.key(by))
	w.head[by], w.seq[by] = id, d.Seq+1
	w.lines = append(w.lines, line)
	w.ids[name], w.by[id] = id, by
	if d.Kind == "edition" {
		w.eid[id] = EditionID(d.Body)
	}
	return id
}

func signCritical(w *world, name, by, kind string, body *canon.Object) string {
	w.t.Helper()
	body.Keys = append(body.Keys, unsupportedMarker)
	body.Members[unsupportedMarker] = canon.Bool(true)
	id := signDraft(w, name, by, wire.Draft{Kind: kind, Crit: []string{unsupportedMarker}, Body: body})
	st, err := wire.Read(w.lines[len(w.lines)-1])
	if err != nil || !st.Verified || st.Status != wire.Unsupported || st.ID != id {
		w.t.Fatalf("fixture did not reach verified unsupported boundary: statement=%+v err=%v", st, err)
	}
	return id
}

func requireRetained(t *testing.T, r *Resolver, id string, status wire.Status, verified, chained bool) *Placed {
	t.Helper()
	p, ok := r.Statement(id)
	if !ok || p.St.Status != status || p.St.Verified != verified || p.Chained != chained || p.Evaluable || p.Counts() {
		t.Fatalf("retained statement %s: %+v; want %s verified=%t chained=%t, never evaluable/counting", keylog.Short(id), p, status, verified, chained)
	}
	return p
}

func TestUnsupportedEditionBodies(t *testing.T) {
	cases := []struct {
		name   string
		fields func(genesis string) *canon.Object
	}{
		{"contents_string", func(g string) *canon.Object {
			return obj("resource", g, "predecessors", []string{g}, "contents", "not an object")
		}},
		{"contents_null", func(g string) *canon.Object {
			return obj("resource", g, "predecessors", []string{g}, "contents", canon.Null{})
		}},
		{"contents_array", func(g string) *canon.Object {
			return obj("resource", g, "predecessors", []string{g}, "contents", canon.Array{})
		}},
		{"members_string", func(g string) *canon.Object {
			return obj("resource", g, "predecessors", []string{g}, "contents", obj("members", "not an array"))
		}},
		{"members_null", func(g string) *canon.Object {
			return obj("resource", g, "predecessors", []string{g}, "contents", obj("members", canon.Null{}))
		}},
		{"members_object", func(g string) *canon.Object {
			return obj("resource", g, "predecessors", []string{g}, "contents", obj("members", obj()))
		}},
		{"predecessors_string", func(g string) *canon.Object { return obj("resource", g, "predecessors", g, "contents", obj()) }},
		{"predecessors_null", func(g string) *canon.Object {
			return obj("resource", g, "predecessors", canon.Null{}, "contents", obj())
		}},
		{"predecessors_number_item", func(g string) *canon.Object {
			return obj("resource", g, "predecessors", canon.Array{canon.Int(1)}, "contents", obj())
		}},
		{"authority_wrong_types", func(g string) *canon.Object {
			return obj("resource", g, "predecessors", []string{g}, "contents", obj("controllers", 1, "rule", "not a rule"))
		}},
		{"missing_fields", func(g string) *canon.Object { return obj("resource", g) }},
		{"apparently_valid_fields", func(g string) *canon.Object {
			return obj("resource", g, "predecessors", []string{g}, "contents", obj("members", canon.Array{obj("content", dig("untrusted"), "role", "member")}))
		}},
	}
	for _, by := range []string{"A", "BB"} { // Ed25519 and EIP-191
		for _, tc := range cases {
			for _, chained := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%s/chained=%t", by, tc.name, chained), func(t *testing.T) {
					// Recover only to report every failing input in the red run. A panic
					// is a failure, never an expected/passing outcome.
					defer func() {
						if v := recover(); v != nil {
							t.Errorf("resolver panicked on verified unsupported body: %v", v)
						}
					}()
					w := newWorld(t)
					g := w.genesis("G", "owner", 0, by)
					w.authored("before", by, "before")
					body := tc.fields(g)
					id := signCritical(w, "bad", by, "edition", body)
					// Without crit, the same malformed body must hit the schema
					// boundary. Do not accidentally test a schema-validated fixture.
					plain, _ := wire.Sign(wire.Draft{Kind: "edition", TS: "2026-10-16T02:00:00Z", Body: body}, w.key(by))
					_, err := wire.Read(plain)
					if (err == nil) != (tc.name == "apparently_valid_fields") {
						t.Fatalf("unexpected schema result without crit: %v", err)
					}
					order := []int{0, 1, 2}
					if !chained {
						order = []int{0, 2}
					}
					r := w.store(order)
					p := requireRetained(t, r, id, wire.Unsupported, true, chained)
					if !bytes.Equal(p.St.Line(), w.lines[2]) {
						t.Fatal("retained signed bytes changed")
					}
					res, ok := r.Resource(g)
					if !ok {
						t.Fatal("valid genesis did not resolve")
					}
					e := editionOf(t, res, id)
					state, why := Unauthorized, "unsupported"
					if !chained {
						state, why = Detached, "detached"
					}
					if e.State != state || res.Current != g || len(e.Approvals) != 1 || e.Approvals[0].Counted || e.Approvals[0].Doubted || e.Approvals[0].Why != why {
						t.Fatalf("unsupported approval changed authority: %s", res.Render())
					}
					if len(e.Predecessors) != 0 || len(e.Members) != 0 || len(e.Controllers) != 0 || e.K != 0 {
						t.Fatalf("unsupported body was interpreted: predecessors=%v members=%v controllers=%v k=%d", e.Predecessors, e.Members, e.Controllers, e.K)
					}
					if !strings.Contains(res.Render(), keylog.Short(id)) || !strings.Contains(res.Render(), "not counted: "+why) {
						t.Fatal("unsupported evidence lost from resource display")
					}
				})
			}
		}
	}
}

func TestUnsupportedMajorAuthorship(t *testing.T) {
	for _, chained := range []bool{false, true} {
		t.Run(fmt.Sprintf("chained=%t", chained), func(t *testing.T) {
			defer func() {
				if v := recover(); v != nil {
					t.Errorf("resolver panicked on retained unknown-major authored: %v", v)
				}
			}()
			w := newWorld(t)
			good := w.authored("good", "A", "X", "licence", "CC0-1.0")
			before := w.store(nil).Artifact(dig("X"))
			id := signDraft(w, "other-major", "BB", wire.Draft{RC: "rc/2", Kind: "authored", Body: obj("content", contentOf("X"), "provenance", 1)})
			if chained {
				w.sign("vouch", "BB", "holds", obj("content", contentOf("other")))
			}
			r := w.store(nil)
			if chained {
				p := requireRetained(t, r, id, wire.Unsupported, false, true)
				if p.St.Body != nil {
					t.Fatal("fixture unexpectedly decoded another major's body")
				}
			} else {
				// Unvouched unknown-major lines are retained by the log, not
				// placed in the resolver's index. Preserve that existing boundary.
				v := r.logs.Log(w.signer("BB")).View()
				if len(v.Retained) != 1 || v.Retained[0].ID != id || !bytes.Equal(v.Retained[0].Line(), w.lines[1]) {
					t.Fatal("unvouched evidence was not retained")
				}
				if _, ok := r.Statement(id); ok {
					t.Fatal("unvouched evidence was placed")
				}
			}
			a := r.Artifact(dig("X"))
			if a.Outcome() != before.Outcome() || a.Grade != before.Grade || !slices.Equal(a.Claims[0].Current, []string{good}) {
				t.Fatalf("unknown major changed authorship: %s", a.Render())
			}
			code, _ := r.Verify(dig("X"))
			if code != 0 {
				t.Fatalf("verify = %d", code)
			}
		})
	}
}
