package wire

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// TestIdentitySetsSorted: every set the profile defines is sorted by canonical encoding and duplicate-free, and the
// reader holds an unsorted list invalid even though each entry is well formed and no entry repeats: permissions (the
// JCS text of each entry), a target set (digests or ids) and amends. The sorted twin of each case reads valid, so the
// order is the one thing the negative changes.
func TestIdentitySetsSorted(t *testing.T) {
	conformance.Partial(t, "C-id-37", "canonical set order: an unsorted permissions list, target set or amends reads invalid on a verified rc/2 line; tamper and criticality are the signed vectors'")
	d1, d2 := "sha256:"+strings.Repeat("1a", 32), "sha256:"+strings.Repeat("2b", 32)
	pAuth := body("kind", "authored", "targets", body("any_content", canon.Bool(true)), "amend", canon.Bool(false))
	pHolds := body("kind", "holds", "targets", body("contents", arr(s(d1))))
	grant := func(perms canon.Array) *canon.Object {
		return body("identity", tID, "delegate", body("key", "ed25519:"+strings.Repeat("2b", 32), "inception", tID2), "permissions", perms)
	}
	holdsOn := func(ds ...string) canon.Array {
		var a canon.Array
		for _, d := range ds {
			a = append(a, s(d))
		}
		return arr(body("kind", "holds", "targets", body("contents", a)))
	}
	stmts := func(ids ...string) canon.Array {
		var a canon.Array
		for _, id := range ids {
			a = append(a, s(id))
		}
		return arr(body("kind", "reproduced", "targets", body("statements", a)))
	}
	claim := body("content", content("ab", 10), "type", "dataset")
	actor := body("identity", tID, "grant", tID2)
	for _, c := range []struct {
		name, kind string
		b, marker  *canon.Object
		actor      *canon.Object
		want       Status
		why        string
	}{
		{"permissions sorted", "identity_grant", grant(arr(pAuth, pHolds)), body(), nil, Valid, ""},
		{"permissions unsorted", "identity_grant", grant(arr(pHolds, pAuth)), body(), nil, Invalid, "body.permissions is not sorted"},
		{"permissions duplicate", "identity_grant", grant(arr(pAuth, pAuth)), body(), nil, Invalid, "body.permissions is not sorted"},
		{"targets.contents sorted", "identity_grant", grant(holdsOn(d1, d2)), body(), nil, Valid, ""},
		{"targets.contents unsorted", "identity_grant", grant(holdsOn(d2, d1)), body(), nil, Invalid, "targets.contents is a set and is not sorted"},
		{"targets.statements unsorted", "identity_grant", grant(stmts(tID2, tID)), body(), nil, Invalid, "targets.statements is a set and is not sorted"},
		{"amends sorted", "authored", claim, body("amends", arr(s(tID), s(tID2))), actor, Valid, ""},
		{"amends unsorted", "authored", claim, body("amends", arr(s(tID2), s(tID))), actor, Invalid, "amends is a set and is not sorted"},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := rc2Read(t, c.kind, c.b, c.marker, c.actor)
			if st.Status != c.want || !strings.Contains(st.Why, c.why) {
				t.Fatalf("read %s (%q), want %s containing %q", st.Status, st.Why, c.want, c.why)
			}
		})
	}
}
