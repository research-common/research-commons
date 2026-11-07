package policy

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/wire"
)

// fakeActors is a test-only ActorEligibility: it answers by statement id and counts its calls. It is not an
// evaluator: it reads no grant, no root and no log. No production code implements the hook.
type fakeActors struct {
	by    map[string]actorAnswer
	calls []string
}

type actorAnswer struct {
	id, state string
	why       []string
}

func (f *fakeActors) Eligible(st *wire.Statement) (string, string, []string) {
	f.calls = append(f.calls, st.ID)
	if a, ok := f.by[st.ID]; ok {
		return a.id, a.state, a.why
	}
	// a statement the evaluator holds no actor for is a bare-key statement: no identity, definitely not eligible
	return "", ActorDenied, []string{"no_identity_actor"}
}

const (
	idJ = "7777777777777777777777777777777777777777777777777777777777777777"
	kW  = "ed25519:8888888888888888888888888888888888888888888888888888888888888888"
)

func stmt(id, signer string) *wire.Statement { return &wire.Statement{ID: id, Signer: signer} }

// TestTrustsPrincipal: a typed principal is matched by its own kind of entry only; Trusts(key) is the key
// principal; an identity entry never trusts a key and a key entry never trusts an identity; the answer does no
// authority evaluation.
func TestTrustsPrincipal(t *testing.T) {
	p, err := Parse([]byte(sortedDoc(nil, []string{
		trustOf(`{"identity":"`+idI+`"}`, `"corroboration"`, `{"contents":["`+dA+`"]}`),
		trustOf(`{"key":"`+kEd+`"}`, `"attestation"`, `{"any_content":true}`)})))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		pr               Principal
		purpose, content string
		want             TrustState
	}{
		{Principal{Identity: idI}, PurposeCorroboration, dA, Trusted},
		{Principal{Identity: idI}, PurposeCorroboration, dB, NotTrusted}, // the target is the content judged
		{Principal{Identity: idI}, PurposeAttestation, dA, NotTrusted},   // a purpose matches only itself
		{Principal{Identity: idI}, PurposeAdmission, dA, Unconfigured},
		{Principal{Identity: idJ}, PurposeCorroboration, dA, NotTrusted}, // another identity
		{Principal{Key: kEd}, PurposeAttestation, dA, Trusted},
		{Principal{Key: kEd}, PurposeCorroboration, dA, Unknown}, // only an identity entry names it: no key is read as I
		{Principal{Key: kW}, PurposeCorroboration, dA, Unknown},
		{Principal{Key: kW}, PurposeCorroboration, dB, NotTrusted},
		{Principal{Identity: idI}, PurposeCorroboration, "", NotTrusted}, // explicit contents never cover no content
	} {
		a := p.TrustsPrincipal(c.pr, c.purpose, c.content)
		if a.State != c.want {
			t.Errorf("%s %s %.12s: %s, want %s", c.pr, c.purpose, c.content, a.State, c.want)
		}
		if c.pr.Key != "" {
			if b := p.Trusts(c.pr.Key, c.purpose, c.content); b.State != a.State || b.Key != c.pr.Key {
				t.Errorf("Trusts(%s) differs from TrustsPrincipal: %+v vs %+v", c.pr.Key, b, a)
			}
		}
	}
	var none *Policy
	if a := none.TrustsPrincipal(Principal{Identity: idI}, PurposeCorroboration, dA); a.State != Unconfigured {
		t.Fatalf("no policy: %+v", a)
	}
}

// TestTrustsStatementThroughActors: C-id-33's boundaries and the identity half of the trust vocabulary, with a
// test-only evaluator. An `{identity: I}` entry trusts a statement the evaluator calls eligible for I; never one
// it calls denied or cannot decide; never a bare statement by the same worker key; purposes and content targets
// stay separate and the evaluator is only asked when an identity entry could decide the answer.
func TestTrustsStatementThroughActors(t *testing.T) {
	conformance.Partial(t, "C-id-33", "the trust seam routes identity entries through a test-only actor evaluator (purpose and target separation, no key read as I, no remote policy installation); the real evaluator adapter and the received-policy-injection half need the identitymodel adapter")
	p, err := Parse([]byte(sortedDoc(nil, []string{
		trustOf(`{"identity":"`+idI+`"}`, `"corroboration"`, `{"contents":["`+dA+`"]}`),
		trustOf(`{"key":"`+kEth+`"}`, `"attestation"`, `{"any_content":true}`)})))
	if err != nil {
		t.Fatal(err)
	}
	fa := &fakeActors{by: map[string]actorAnswer{
		"elig":     {idI, ActorEligible, []string{"grant G"}},
		"deny":     {idI, ActorDenied, []string{"grant G is cut"}},
		"unk":      {idI, ActorUnknown, []string{"grant G not held"}},
		"other":    {idJ, ActorEligible, nil},
		"nameless": {"", ActorEligible, nil},
		"junk":     {idI, "maybe", nil},
	}}
	ask := func(id string, signer, purpose, content string, actors ActorEligibility) Answer {
		return p.TrustsStatement(stmt(id, signer), purpose, content, actors)
	}

	// eligible for I → trusted as I, citing the policy and the identity
	a := ask("elig", kW, PurposeCorroboration, dA, fa)
	if a.State != Trusted || a.Principal.Identity != idI || a.Policy != p.Digest || !strings.Contains(a.String(), "as identity") {
		t.Fatalf("eligible: %+v %s", a, a)
	}
	// denied, unknown, junk state, no identity named: none is trusted, each says which
	for id, want := range map[string]TrustState{"deny": NotTrusted, "unk": UnknownActor, "junk": UnknownActor, "nameless": UnknownActor, "other": NotTrusted} {
		if a := ask(id, kW, PurposeCorroboration, dA, fa); a.State != want || a.Trusted() || a.Key != kW || len(a.Why) == 0 {
			t.Errorf("%s: %+v, want %s", id, a, want)
		}
	}
	// a bare statement by the same worker key (the evaluator knows no actor for it) is not I's
	if a := ask("bare", kW, PurposeCorroboration, dA, fa); a.State != NotTrusted || a.Trusted() {
		t.Fatalf("bare worker-key statement: %+v", a)
	}
	// ...and the identity entry never turns the key itself into a trusted key
	if a := p.Trusts(kW, PurposeCorroboration, dA); a.State != Unknown || a.Trusted() {
		t.Fatalf("key alone: %+v", a)
	}
	// a purpose matches only itself, and the target is the content judged
	fa.calls = nil
	for _, c := range []struct{ purpose, content string }{{PurposeAttestation, dA}, {PurposeAdmission, dA}, {PurposeCorroboration, dB}, {PurposeCorroboration, ""}} {
		if a := ask("elig", kW, c.purpose, c.content, fa); a.Trusted() {
			t.Errorf("%s over %.12s: trusted: %+v", c.purpose, c.content, a)
		}
	}
	if len(fa.calls) != 0 {
		t.Fatalf("the evaluator was asked %v about a purpose or content no identity entry covers", fa.calls)
	}
	// a key entry that matches answers first: the evaluator is not asked
	if a := ask("elig", kEth, PurposeAttestation, dA, fa); a.State != Trusted || len(fa.calls) != 0 {
		t.Fatalf("key entry: %+v calls %v", a, fa.calls)
	}
	// no evaluator: exactly Trusts, the identity profile is not active
	for _, id := range []string{"elig", "deny", "unk", "bare"} {
		got, want := ask(id, kW, PurposeCorroboration, dA, nil), p.Trusts(kW, PurposeCorroboration, dA)
		if got.State != Unknown || got.Key != want.Key || got.Entry != want.Entry || !strings.Contains(got.String(), "identity profile is not active") {
			t.Errorf("no evaluator, %s: %+v", id, got)
		}
	}
	// a configured policy with nobody named for the purpose never reaches the evaluator
	if a := ask("elig", kW, PurposeAdmission, dA, fa); a.State != Unconfigured {
		t.Fatalf("unconfigured: %+v", a)
	}
}

// TestAdmitStatementThroughActors: C-core-111/113 over identities (their key halves are covered at pull). The pull gate's statement-level admission. Identity entries decide through
// the evaluator; without one the floor reads unknown and refuses, exactly as Admit does; scope names the object
// when the answer rests on a statement's actor.
func TestAdmitStatementThroughActors(t *testing.T) {
	p, err := Parse([]byte(sortedDoc(nil, []string{trustOf(`{"identity":"`+idI+`"}`, `"admission"`, `{"any_content":true}`)})))
	if err != nil {
		t.Fatal(err)
	}
	fa := &fakeActors{by: map[string]actorAnswer{"elig": {idI, ActorEligible, nil}, "deny": {idI, ActorDenied, nil}}}
	if a := p.AdmitStatement(stmt("elig", kW), dA, FloorRefuse, fa); !a.Admitted || a.Refusal != nil || a.Label != "" {
		t.Fatalf("eligible: %+v", a)
	}
	a := p.AdmitStatement(stmt("deny", kW), dA, FloorRefuse, fa)
	if a.Admitted || a.Refusal == nil || a.Refusal.Reason != TrustFloorReason || !strings.Contains(a.Refusal.Detail, "scope: this object, signed by "+kW) {
		t.Fatalf("denied: %+v %v", a, a.Refusal)
	}
	if a := p.AdmitStatement(stmt("bare", kW), dA, FloorLabel, fa); !a.Admitted || !strings.Contains(a.Label, "below the reader's trust floor") {
		t.Fatalf("bare, label: %+v", a)
	}
	// no evaluator: unknown, refused as the key floor refuses; the scope is the signer's objects, as in Admit
	n := p.AdmitStatement(stmt("elig", kW), dA, FloorRefuse, nil)
	m := p.Admit(kW, dA, FloorRefuse)
	if n.Admitted || n.Refusal == nil || n.Refusal.Detail != m.Refusal.Detail || n.Answer.State != Unknown {
		t.Fatalf("no evaluator: %+v vs Admit %+v", n, m)
	}
	// unknown actor refuses (not admitted) and says so
	fa.by["unk"] = actorAnswer{idI, ActorUnknown, []string{"grant not held"}}
	if a := p.AdmitStatement(stmt("unk", kW), dA, FloorRefuse, fa); a.Admitted || a.Answer.State != UnknownActor || !slices.Contains(a.Answer.Why, "grant not held") {
		t.Fatalf("unknown: %+v", a)
	}
}
