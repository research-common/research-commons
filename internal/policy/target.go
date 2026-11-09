package policy

import (
	"slices"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// Target references (identity profile §6: "Targets apply to the content being judged, not an incidental digest;
// unresolved target references remain unknown"; docs/READER-POLICY.md "Trust").
//
// Some statements name the content they are about directly (`authored`, `holds`, `observed`, `reproduced`:
// body.content.digest; `describes`: about.content). Others reach it through a reference: a `corroborates`,
// `refutes` or `retracts` is about the content of the statement its `of` names, and a `describes` of a statement
// about that statement's content. Target is the content being judged as the caller could reach it: the digest, or
// the reference it could not follow because the statement it names is not held.
//
// An unresolved reference is not "names no content": the content exists, the reader cannot see it. So a trust
// answer that depends on it reads UnknownTarget: never Trusted (that would trust content nobody checked) and never
// NotTrusted (that would refuse it for a content the reader does not know). It depends on the content only when a
// `contents` entry for the purpose could match the principal; an `any_content` entry trusts it whatever the
// content, and a principal no entry names is not trusted whatever the content, so those answers stand.

// Target is the content a trust question judges.
type Target struct {
	// Content is the content digest being judged; "" when the statement names no content (only any_content covers
	// it) or the reference is unresolved.
	Content string
	// Unresolved is the statement id the content is reached through, when that statement is not held; "" otherwise.
	Unresolved string
}

// UnknownTarget: the content being judged is reached through a reference (Target.Unresolved) to a statement this
// reader does not hold, and a `contents` trust entry for the purpose could match the principal, so whether it is
// trusted depends on content the reader cannot see. Not trusted for counting or admission, labelled as unknown
// rather than as a refusal of the principal.
const UnknownTarget TrustState = "unknown (target reference not resolved)"

// TargetRefs is how a statement reaches the content it is about, read from its body: the content digest it names
// directly, else the statement id it is about. A statement of another kind returns ("", ""): it names no content.
func TargetRefs(st *wire.Statement) (content, ref string) {
	if st == nil || st.Body == nil {
		return "", ""
	}
	b := st.Body
	switch st.Kind {
	case "corroborates", "refutes", "retracts":
		return "", bodyField(b, "of")
	case "describes":
		if about := bodyObject(b, "about"); about != nil {
			if c := bodyField(about, "content"); c != "" {
				return c, ""
			}
			return "", bodyField(about, "statement")
		}
		return "", ""
	}
	if c := bodyObject(b, "content"); c != nil {
		return bodyField(c, "digest"), ""
	}
	return "", ""
}

// ResolveTarget is the Target of st: its own content, or the content of the statement it references, looked up with
// held (a statement id names one line, so whichever copy is found is that statement). A reference held names its
// content (or none); a reference not held is Unresolved.
func ResolveTarget(st *wire.Statement, held func(id string) (*wire.Statement, bool)) Target {
	content, ref := TargetRefs(st)
	if ref == "" {
		return Target{Content: content}
	}
	if held != nil {
		if r, ok := held(ref); ok {
			// one hop: the referenced statement's own content. A statement about a statement about content judges
			// the middle statement, which names no content of its own, so only any_content covers it.
			c, rr := TargetRefs(r)
			if rr != "" {
				c = ""
			}
			return Target{Content: c}
		}
	}
	return Target{Unresolved: ref}
}

// TrustsTarget is TrustsStatement over a Target: with the content resolved it is TrustsStatement exactly; with an
// unresolved reference the answer reads UnknownTarget when a `contents` entry for the purpose could match the
// statement's principal (its key, or any identity), and otherwise is the content-free answer (any_content trusts;
// no entry for the principal is not trusted).
func (p *Policy) TrustsTarget(st *wire.Statement, purpose string, t Target, actors ActorEligibility) Answer {
	a := p.TrustsStatement(st, purpose, t.Content, actors)
	if t.Unresolved == "" || a.State == Trusted || a.State == Unconfigured {
		return a
	}
	for _, e := range p.Trust {
		if e.AnyContent || !slices.Contains(e.Purposes, purpose) {
			continue
		}
		if e.Principal.Key == st.Signer || e.Principal.Identity != "" {
			return Answer{State: UnknownTarget, Key: st.Signer, Principal: Principal{Key: st.Signer}, Purpose: purpose,
				Policy: p.Digest, Evaluator: a.Evaluator, Why: []string{"the content is reached through statement " + short(t.Unresolved) + ", which this reader does not hold"}}
		}
	}
	return a
}

// AdmitTarget is AdmitStatement over a Target (TrustsTarget for admission).
func (p *Policy) AdmitTarget(st *wire.Statement, t Target, floor Floor, actors ActorEligibility) Admission {
	ans := p.TrustsTarget(st, PurposeAdmission, t, actors)
	scope := "objects signed by " + st.Signer
	if len(ans.Why) > 0 {
		scope = "this object, signed by " + st.Signer
	}
	return admission(ans, scope, floor)
}

func bodyObject(o *canon.Object, k string) *canon.Object {
	if v, ok := o.Get(k); ok {
		if x, ok := v.(*canon.Object); ok {
			return x
		}
	}
	return nil
}

func bodyField(o *canon.Object, k string) string {
	if v, ok := o.Get(k); ok {
		if x, ok := v.(canon.String); ok {
			return string(x)
		}
	}
	return ""
}
