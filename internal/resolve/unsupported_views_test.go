package resolve

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

func TestUnsupportedEditionSharedBody(t *testing.T) {
	w := newWorld(t)
	g := w.genesis("G", "owner", 2, "A", "BB")
	body := w.editionBody(g, []string{g}, []string{"X"})
	unsupported := signCritical(w, "unsupported", "A", "edition", body)
	// Identical body, but no critical marker in this approval's envelope. The
	// ordinary x_ field is noncritical and has no authority semantics here.
	valid := w.sign("valid", "BB", "edition", body)
	check := func(res *Resource, state EditionState, counted int) {
		t.Helper()
		e := editionOf(t, res, unsupported)
		if e.ID != w.ed(valid) || e.State != state || len(e.Members) != 1 || !slices.Equal(e.Predecessors, []string{g}) {
			t.Fatalf("mixed approvals lost valid body semantics: %s", res.Render())
		}
		n := 0
		for _, a := range e.Approvals {
			if a.Counted {
				n++
			}
			if a.Statement == unsupported && (a.Counted || a.Doubted || a.Why != "unsupported") {
				t.Fatalf("unsupported co-approval counted: %+v", a)
			}
		}
		if n != counted {
			t.Fatalf("counted %d, want %d", n, counted)
		}
	}
	everyOrder(t, w, g, func(res *Resource) {
		check(res, Pending, 1)
		wantCurrent(t, res, g)
	})
	w.sign("valid-A", "A", "edition", body)
	everyOrder(t, w, g, func(res *Resource) {
		check(res, Authorized, 2)
		wantCurrent(t, res, valid)
	})
	// A critical withdrawal from the legitimate controller is still opaque and
	// cannot withdraw an otherwise valid approval or change the current edition.
	withdrawal := signCritical(w, "withdrawal", "A", "withdraw_approval", obj("resource", g, "edition", w.ed(valid)))
	r := w.store(nil)
	requireRetained(t, r, withdrawal, wire.Unsupported, true, true)
	res, _ := r.Resource(g)
	check(res, Authorized, 2)
	wantCurrent(t, res, valid)
	for _, a := range editionOf(t, res, valid).Approvals {
		if a.Withdrawn != "" {
			t.Fatal("unsupported withdrawal took effect")
		}
	}
}

func TestUnsupportedEditionCannotAuthorizeSuccessor(t *testing.T) {
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A")
	bad := signCritical(w, "unsupported-control-change", "A", "edition", w.editionBody(g, []string{g}, []string{"X"},
		"controllers", w.controllers("BB"), "rule", obj("any_one", true)))
	next := w.edition("attempt", "BB", g, []string{bad}, []string{"Y"})
	everyOrder(t, w, g, func(res *Resource) {
		wantState(t, res, bad, Unauthorized, "not counted: unsupported")
		wantState(t, res, next, Orphan, "is not an edition")
		wantCurrent(t, res, g)
		if e := editionOf(t, res, bad); e.K != 0 || len(e.Controllers) != 0 || len(e.Members) != 0 || len(e.Predecessors) != 0 {
			t.Fatal("unsupported control change supplied interpreted fields")
		}
	})
}

func TestUnsupportedWellFormedDetachedProposal(t *testing.T) {
	w := newWorld(t)
	g := w.genesis("G", "owner", 0, "A")
	w.authored("missing-prev", "A", "X")
	id := w.edition("detached", "A", g, []string{g}, []string{"X"})
	r := w.store([]int{0, 2})
	requireRetained(t, r, id, wire.Valid, true, false)
	res, _ := r.Resource(g)
	e := editionOf(t, res, id)
	if e.State != Detached || len(e.Members) != 1 || !slices.Equal(e.Predecessors, []string{g}) || res.Current != g {
		t.Fatalf("well-formed detached display changed: %s", res.Render())
	}
	res, _ = w.store(nil).Resource(g)
	wantState(t, res, id, Authorized, "authorized under")
	wantCurrent(t, res, id)
}

type unsupportedTimeTrap struct{ t *testing.T }

func (v unsupportedTimeTrap) Verify(*wire.Statement) Bound {
	v.t.Fatal("unsupported anchor reached the time verifier")
	return Bound{}
}

func TestUnsupportedResolverNonInterference(t *testing.T) {
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A")
	ed := w.edition("edition", "A", g, []string{g}, []string{"X"})
	w.workflow("A", "WF", "bytes", "")
	claim := w.authored("claim", "A", "X", "prov", []string{"WF"}, "licence", "CC0-1.0")
	w.authored("replication", "BB", "X", "prov", []string{"WF"}, "licence", "CC0-1.0")
	before := w.store(nil).Artifact(dig("X"))
	baselineResource, _ := w.store(nil).Resource(g)
	cases := []struct {
		kind string
		body *canon.Object
	}{
		{"authored", obj("content", contentOf("X"), "provenance", 1, "licence", "MIT")},
		{"authored", obj("content", "not an object", "provenance", canon.Null{})},
		{"holds", obj("content", contentOf("X"), "locations", "not a list")},
		{"reproduced", obj("content", contentOf("X"), "of", claim, "provenance", false)},
		{"describes", obj("about", false)},
		{"refutes", obj("of", claim, "evidence", canon.Array{})},
		{"retracts", obj("of", claim)},
		{"anchors", obj("covered", w.head["A"], "proof", 1, "proof_format", false)},
		{"observed", obj("content", contentOf("X"), "class", 1, "referent", false)},
		{"corroborates", obj("of", claim, "verdict", "contradicts", "cohort", false)},
		{"withdraw_approval", obj("resource", g, "edition", w.ed(ed))},
		{"genesis", obj("controllers", 1, "rule", false, "type", "collection")},
		// These are regression assertions only: key-event rules are not changed.
		{"revoke_key", obj("reason", "key_compromise")},
		{"rotate_key", obj("successor", w.signer("BB"))},
	}
	var unsupported []string
	for _, tc := range cases {
		unsupported = append(unsupported, signCritical(w, tc.kind, "A", tc.kind, tc.body))
	}
	unknown := w.sign("unknown", "A", "future_kind", obj("resource", g, "content", contentOf("X"),
		"contents", false, "predecessors", 1, "provenance", "not an object"))
	unknownCritical := signCritical(w, "unknown-critical", "A", "future_kind", obj("resource", g, "content", contentOf("X")))
	unsupported = append(unsupported, unknownCritical)
	// Include reverse delivery and duplicates: retained evidence never becomes
	// authority merely because ingestion order or multiplicity changes.
	reverse, duplicate := []int{}, []int{}
	for i := range w.lines {
		reverse = append(reverse, len(w.lines)-1-i)
		duplicate = append(duplicate, i, i)
	}
	for _, order := range [][]int{nil, reverse, duplicate} {
		r := w.store(order, WithTimeVerifier(unsupportedTimeTrap{t}))
		for _, id := range unsupported {
			requireRetained(t, r, id, wire.Unsupported, true, true)
		}
		requireRetained(t, r, unknown, wire.UnknownKind, true, true)
		if _, ok := r.Resource(w.ids["genesis"]); ok {
			t.Fatal("unsupported genesis resolved")
		}
		res, _ := r.Resource(g)
		if res.Render() != baselineResource.Render() {
			t.Fatalf("unsupported non-editions changed resource: %s", res.Render())
		}
		a := r.Artifact(dig("X"))
		if a.Outcome() != before.Outcome() || a.Grade != before.Grade || len(a.Group.Runs) != len(before.Group.Runs) || len(a.Holders) != 0 || len(a.Held) != 0 {
			t.Fatalf("unsupported statements changed artifact: %s", a.Render())
		}
		if len(a.NotCounted) != 1 || a.NotCounted[0].Statement != unsupported[0] || a.NotCounted[0].Why != "unsupported" {
			t.Fatalf("unsupported authored evidence lost: %+v", a.NotCounted)
		}
		if !strings.Contains(a.Render(), "authored "+keylog.Short(unsupported[0])) {
			t.Fatal("unsupported authored not displayed")
		}
		for _, c := range a.Claims {
			if c.Bound.Quality != NoBound {
				t.Fatal("unsupported anchor supplied a bound")
			}
		}
		code, _ := r.Verify(dig("X"))
		if code != 0 || a.Grade.Tier != "T0" {
			t.Fatalf("known-valid derivation no longer passes: %s", a.Render())
		}
	}
}

func TestUnsupportedEditionUnassociatedBodies(t *testing.T) {
	for _, resource := range []canon.Value{canon.Null{}, canon.Int(1), canon.Array{}, obj()} {
		w := newWorld(t)
		g := w.genesis("G", "A", 0, "A")
		id := signCritical(w, "unassociated", "A", "edition", obj("resource", resource, "contents", false, "predecessors", false))
		r := w.store(nil)
		requireRetained(t, r, id, wire.Unsupported, true, true)
		res, _ := r.Resource(g)
		if len(res.Editions) != 0 || res.Current != g {
			t.Fatalf("non-string resource associated: %s", res.Render())
		}
	}
}

// unknownAlgorithmKey signs with a synthetic test key while declaring an algorithm
// the reader does not implement; the resulting line must stay unverified here.
type unknownAlgorithmKey struct{ wire.Key }

func (unknownAlgorithmKey) Alg() string { return "resolver-test-unknown" }

func TestUnsupportedUnverifiedEdition(t *testing.T) {
	for _, major := range []bool{false, true} {
		name := "unknown_algorithm"
		if major {
			name = "unknown_major"
		}
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			g := w.genesis("G", "A", 0, "BB")
			d := wire.Draft{Kind: "edition", Body: obj("resource", g, "contents", false, "predecessors", 1)}
			key := w.key("BB")
			if major {
				d.RC = "rc/2"
			} else {
				w.keys["BB"] = unknownAlgorithmKey{key}
			}
			id := signDraft(w, "unverified", "BB", d)
			w.keys["BB"] = key
			w.sign("vouch", "BB", "holds", obj("content", contentOf("other")))
			r := w.store(nil)
			requireRetained(t, r, id, wire.Unsupported, false, true)
			res, _ := r.Resource(g)
			if major {
				if len(res.Editions) != 0 {
					t.Fatal("unknown major supplied a resource association")
				}
			} else {
				e := editionOf(t, res, id)
				if e.State != Unauthorized || len(e.Members) != 0 || len(e.Predecessors) != 0 || e.Approvals[0].Counted {
					t.Fatalf("vouched unknown algorithm supplied authority: %s", res.Render())
				}
			}
			wantCurrent(t, res, g)
			valid := w.edition("valid", "BB", g, []string{g}, []string{"X"})
			res, _ = w.store(nil).Resource(g)
			wantState(t, res, valid, Authorized, "authorized under")
			wantCurrent(t, res, valid)
		})
	}
}
