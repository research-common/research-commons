package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

// pullActors is a test-only policy.ActorEligibility keyed by statement id (no production implementation exists).
type pullActors map[string]string

func (a pullActors) Eligible(st *wire.Statement) (string, string, []string) {
	if s, ok := a[st.ID]; ok {
		return pullIdentity, s, nil
	}
	return "", policy.ActorDenied, []string{"no_identity_actor"}
}

const pullIdentity = "4444444444444444444444444444444444444444444444444444444444444444"

// TestPullGateTrustFloorSeam: the pull gate's trust floor asks the statement-level question
// (policy.AdmitStatement), so an `{identity: I}` admission entry admits what the actor hook calls eligible for I
// and refuses a denied, undecided or bare statement by the same worker key. With no hook (every production
// reader today) it reads unknown and refuses, exactly as the key floor did.
func TestPullGateTrustFloorSeam(t *testing.T) {
	p, err := policy.Parse([]byte(`{"version":"reader-policy-v1","selections":[],"trust":[{"principal":{"identity":"` + pullIdentity + `"},"purposes":["admission"],"targets":{"any_content":true}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld(t)
	// statements are signed here and never committed: the gate hook reads one statement, not a store
	sts := map[string]*wire.Statement{}
	prev := ""
	for i, name := range []string{"eligible", "denied", "undecided", "bare"} {
		line, id := wire.Sign(wire.Draft{Kind: "authored", Seq: int64(i), Prev: prev, TS: "2026-10-16T02:00:00Z",
			Body: obj("content", canon.Value(content("k")), "type", "dataset", "licence", name)}, w.key("W"))
		prev = id
		st, err := wire.Read(line)
		if err != nil {
			t.Fatal(err)
		}
		sts[name] = st
	}
	read := func(name string) *wire.Statement { return sts[strings.TrimPrefix(name, "A:")] }
	actors := pullActors{sts["eligible"].ID: policy.ActorEligible, sts["denied"].ID: policy.ActorDenied, sts["undecided"].ID: policy.ActorUnknown}
	with := trustFloor{p: p, floor: policy.FloorRefuse, actors: actors}
	if rf := with.CheckStatement(read("A:eligible")); rf != nil {
		t.Fatalf("eligible statement refused: %v", rf)
	}
	for _, name := range []string{"A:denied", "A:undecided", "A:bare"} {
		rf := with.CheckStatement(read(name))
		if rf == nil || rf.Reason != policy.TrustFloorReason || !strings.Contains(rf.Detail, "this object") {
			t.Errorf("%s: %v", name, rf)
		}
	}
	// no hook: unknown, refused with the signer's objects as scope, exactly as before
	without := trustFloor{p: p, floor: policy.FloorRefuse}
	for _, name := range []string{"A:eligible", "A:bare"} {
		rf := without.CheckStatement(read(name))
		if rf == nil || !strings.Contains(rf.Detail, "objects signed by "+w.signer("W")) || !strings.Contains(rf.Detail, "identity profile is not active") {
			t.Errorf("no hook, %s: %v", name, rf)
		}
	}
}
