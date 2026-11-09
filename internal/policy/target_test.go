package policy

import (
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/wire"
)

func bodyOf(t *testing.T, s string) *canon.Object {
	t.Helper()
	v, err := canon.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v.(*canon.Object)
}

// TestTargetReference: identity profile §6 "Targets apply to the content being judged, not an incidental digest;
// unresolved target references remain unknown" (R5SEAM-F2). A statement that reaches its content through a
// reference is judged by the referenced statement's content when it is held; when it is not held and a `contents`
// entry for the purpose could match the principal, the answer is UnknownTarget: never trusted, never not trusted.
// An any_content entry and a principal no entry names keep their content-free answers, and a statement that names
// its content directly is answered exactly as TrustsStatement.
func TestTargetReference(t *testing.T) {
	conformance.Partial(t, "C-id-33", "trust targets apply to the content being judged: a reference followed one hop to the held statement's content, an unresolved reference reads unknown (never trusted, never not trusted) for key and identity contents entries; the pull trust floor reads it through the package and the store")
	const dB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	const ref = "9999999999999999999999999999999999999999999999999999999999999999"
	p, err := Parse([]byte(sortedDoc(nil, []string{
		trustOf(`{"key":"`+kEd+`"}`, `"admission","corroboration"`, `{"contents":["`+dA+`"]}`),
		trustOf(`{"key":"`+kEth+`"}`, `"corroboration"`, `{"any_content":true}`)})))
	if err != nil {
		t.Fatal(err)
	}
	observed := &wire.Statement{ID: ref, Signer: kEth, Kind: "observed", Body: bodyOf(t, `{"content":{"digest":"`+dA+`","size":1}}`)}
	observedB := &wire.Statement{ID: ref, Signer: kEth, Kind: "observed", Body: bodyOf(t, `{"content":{"digest":"`+dB+`","size":1}}`)}
	corr := func(signer string) *wire.Statement {
		return &wire.Statement{ID: "c", Signer: signer, Kind: "corroborates", Body: bodyOf(t, `{"of":"`+ref+`","result":"`+ref+`","verdict":"supports"}`)}
	}
	holding := func(s *wire.Statement) func(string) (*wire.Statement, bool) {
		return func(id string) (*wire.Statement, bool) { return s, id == s.ID }
	}
	none := func(string) (*wire.Statement, bool) { return nil, false }

	// the reference held: judged by the referenced content, as if named directly
	if tg := ResolveTarget(corr(kEd), holding(observed)); tg.Content != dA || tg.Unresolved != "" {
		t.Fatalf("held reference: %+v", tg)
	}
	if a := p.TrustsTarget(corr(kEd), PurposeCorroboration, ResolveTarget(corr(kEd), holding(observed)), nil); a.State != Trusted {
		t.Fatalf("held, covered: %s", a)
	}
	if a := p.TrustsTarget(corr(kEd), PurposeCorroboration, ResolveTarget(corr(kEd), holding(observedB)), nil); a.State != NotTrusted {
		t.Fatalf("held, not covered: %s", a)
	}
	// the reference not held: unknown for a contents entry of the principal, for each purpose it names
	tg := ResolveTarget(corr(kEd), none)
	if tg.Unresolved != ref || tg.Content != "" {
		t.Fatalf("unresolved: %+v", tg)
	}
	for _, purpose := range []string{PurposeCorroboration, PurposeAdmission} {
		a := p.TrustsTarget(corr(kEd), purpose, tg, nil)
		if a.State != UnknownTarget || a.Trusted() || a.Policy != p.Digest {
			t.Fatalf("%s unresolved: %s", purpose, a)
		}
	}
	// TrustsStatement over "" would have said not trusted: the reference is not "names no content"
	if a := p.TrustsStatement(corr(kEd), PurposeCorroboration, "", nil); a.State != NotTrusted {
		t.Fatalf("baseline: %s", a)
	}
	// any_content trusts whatever the content; a principal no entry names is not trusted whatever the content;
	// a purpose no entry names stays unconfigured
	if a := p.TrustsTarget(corr(kEth), PurposeCorroboration, tg, nil); a.State != Trusted {
		t.Fatalf("any_content: %s", a)
	}
	other := "ed25519:" + ref
	if a := p.TrustsTarget(corr(other), PurposeCorroboration, tg, nil); a.State != NotTrusted {
		t.Fatalf("no entry for the principal: %s", a)
	}
	if a := p.TrustsTarget(corr(kEd), PurposeAttestation, tg, nil); a.State != Unconfigured {
		t.Fatalf("unconfigured purpose: %s", a)
	}
	// admission: refused as not admitted, labelled with the unknown answer
	if ad := p.AdmitTarget(corr(kEd), tg, FloorRefuse, nil); ad.Admitted || ad.Refusal == nil {
		t.Fatalf("admission refused: %+v", ad)
	}
	if ad := p.AdmitTarget(corr(kEd), tg, FloorLabel, nil); !ad.Admitted || ad.Label == "" {
		t.Fatalf("admission labelled: %+v", ad)
	}
	// an identity contents entry: an unresolved reference is unknown for any signer it could act for
	pi, err := Parse([]byte(sortedDoc(nil, []string{trustOf(`{"identity":"`+idI+`"}`, `"corroboration"`, `{"contents":["`+dA+`"]}`)})))
	if err != nil {
		t.Fatal(err)
	}
	if a := pi.TrustsTarget(corr(other), PurposeCorroboration, tg, nil); a.State != UnknownTarget {
		t.Fatalf("identity contents entry, unresolved: %s", a)
	}
	// direct content: exactly TrustsStatement
	for _, s := range []*wire.Statement{observed, observedB, {Kind: "describes", Signer: kEd, Body: bodyOf(t, `{"about":{"content":"`+dA+`"}}`)}} {
		tg := ResolveTarget(s, none)
		if tg.Unresolved != "" {
			t.Fatalf("direct content read as a reference: %+v", tg)
		}
		if a, b := p.TrustsTarget(s, PurposeCorroboration, tg, nil), p.TrustsStatement(s, PurposeCorroboration, tg.Content, nil); a.State != b.State {
			t.Fatalf("direct: %s vs %s", a, b)
		}
	}
	// one hop only: a statement about a statement about content judges the middle one, which names no content
	middle := corr(kEth)
	middle.ID = ref
	if tg := ResolveTarget(corr(kEd), holding(middle)); tg.Content != "" || tg.Unresolved != "" {
		t.Fatalf("two hops: %+v", tg)
	}
	// a describes of a statement is a reference too
	ds := &wire.Statement{Kind: "describes", Signer: kEd, Body: bodyOf(t, `{"about":{"statement":"`+ref+`"}}`)}
	if tg := ResolveTarget(ds, none); tg.Unresolved != ref {
		t.Fatalf("describes of a statement: %+v", tg)
	}
}
