package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// TrustState is the answer to "does this reader trust key K for purpose P over content C".
type TrustState string

const (
	// Unconfigured: trust is not configured for the purpose: no policy is configured, or no trust entry of the
	// configured one names the purpose (trust is configured per purpose, note §6). Callers keep their documented
	// no-policy behaviour for that purpose and say so.
	Unconfigured TrustState = "not configured"
	// Trusted: a `{key: K}` entry names the purpose and its target covers the content.
	Trusted TrustState = "trusted"
	// NotTrusted: some trust entry names the purpose, and no entry trusts K for it over the content. Once a
	// purpose is configured, only the listed principals count for it, never universal trust (note §6).
	NotTrusted TrustState = "not trusted"
	// Unknown: no `{key: K}` entry matches, but an `{identity: I}` entry names the purpose over the content, and
	// this reader cannot tell whether K acts for I (the identity profile is not active). Not trusted for
	// counting, and labelled as unknown rather than as a refusal of K.
	Unknown TrustState = "unknown (identity profile not active)"
	// UnknownActor: an actor evaluator is configured, and it cannot say whether the statement acts for an
	// identity the policy trusts for the purpose (a missing grant, a missing ancestor, a cap). Not trusted for
	// counting, labelled as unknown rather than as a refusal.
	UnknownActor TrustState = "unknown (actor eligibility not established)"
)

// Actor eligibility states an ActorEligibility answers with.
const (
	ActorEligible = "eligible"
	ActorDenied   = "denied"
	ActorUnknown  = "unknown"
)

// ActorEligibility is the identity evaluator's hook: whether one statement is eligible to act for the identity
// its signed actor names. It is the only thing the trust seam asks of an identity evaluator.
//
// identity is the identity the statement's actor claims, "" when it names none (a bare-key statement, or an
// actor that did not read) or when the evaluator holds no issuer-authenticated binding that would make the
// claim relevant (profile §5.1: an outsider's unproven header must not stall the identity it names). state is
// ActorEligible, ActorDenied or ActorUnknown; anything else is read as unknown. why is a short list of reasons a
// reader can show. An implementation does no trust evaluation and reads no policy: eligibility is authority,
// trust is the reader's own choice (profile §6, "trust is not authorship").
type ActorEligibility interface {
	Eligible(st *wire.Statement) (identity, state string, why []string)
}

// ActorEvaluator is optionally implemented by an ActorEligibility that can name itself: its evaluator identity
// and the evidence it answers from (a digest or receipt). An answer that consulted it cites this text beside the
// policy digest, so two readers with the same policy and different evaluators or evidence are told apart: the
// meaning of `{identity: I}` is fixed by the policy, the answer by policy and evaluator together (identity
// profile §6).
type ActorEvaluator interface {
	Evaluator() string
}

func evaluatorOf(a ActorEligibility) string {
	if e, ok := a.(ActorEvaluator); ok {
		return e.Evaluator()
	}
	return ""
}

// Answer is one trust answer with what it rests on.
type Answer struct {
	State                 TrustState
	Key, Purpose, Content string
	// Principal is the principal the answer is about: the key asked about, or the identity a statement was
	// found eligible for (Trusted or NotTrusted through the actor hook). A denied or unknown actor keeps the
	// signing key.
	Principal Principal
	// Why lists what the actor evaluator said, when the hook was consulted; empty otherwise.
	Why []string
	// Entry is the canonical text of the matching trust entry (Trusted), or of the identity entry that made
	// the answer unknown (Unknown).
	Entry string
	// Policy is the policy digest the answer comes from; "" when unconfigured (also when a policy is configured
	// but names no principal for the purpose).
	Policy string
	// Evaluator is the actor evaluator the answer consulted (ActorEvaluator), cited beside Policy; "" when the
	// hook was not consulted or does not name itself.
	Evaluator string
}

// Trusted reports whether the answer admits the evidence for its purpose. Unconfigured is not Trusted: a caller
// that keeps a no-policy default must check for Unconfigured itself.
func (a Answer) Trusted() bool { return a.State == Trusted }

// String is the answer as a reader-facing phrase, citing the policy digest.
func (a Answer) String() string {
	what := a.Purpose
	if a.Content != "" {
		what += " of " + short(a.Content)
	}
	pol := short(a.Policy)
	if a.Evaluator != "" {
		pol += " and actor evaluator " + a.Evaluator
	}
	switch a.State {
	case Unconfigured:
		return "trust not configured"
	case Trusted:
		line := fmt.Sprintf("trusted for %s under reader policy %s", what, pol)
		if a.Principal.Identity != "" {
			line += " as identity " + short(a.Principal.Identity)
		}
		return line
	case Unknown:
		return fmt.Sprintf("trust for %s unknown under reader policy %s: the policy names an identity, and the identity profile is not active", what, short(a.Policy))
	case UnknownActor:
		return fmt.Sprintf("trust for %s unknown under reader policy %s: the policy names an identity, and whether this statement acts for it is not established%s", what, pol, a.because())
	}
	return fmt.Sprintf("not trusted for %s under reader policy %s%s", what, pol, a.because())
}

func (a Answer) because() string {
	if len(a.Why) == 0 {
		return ""
	}
	return " (" + strings.Join(a.Why, "; ") + ")"
}

// Trusts answers whether the policy trusts signing key key for purpose over content: TrustsPrincipal for the
// key principal. An `{identity: I}` entry that names the purpose over the content answers Unknown for a key
// no `{key: K}` entry matches: whether K acts for I depends on a statement, which TrustsStatement has.
func (p *Policy) Trusts(key, purpose, content string) Answer {
	return p.TrustsPrincipal(Principal{Key: key}, purpose, content)
}

// TrustsPrincipal answers whether the policy trusts the typed principal for purpose over content (the content
// being judged, never an incidental digest; "" when the evidence names no content, which only an any_content
// target covers). A purpose matches only itself. Overlapping entries are additive: one match is enough. Trust
// is configured per purpose: a purpose no trust entry names answers Unconfigured, even under a configured
// policy (a policy that only pins a workflow changes no count); once any entry names a principal for it, only
// listed principals are trusted.
//
// It does no authority evaluation (profile §6: trust is not authorship). A key principal is matched by its
// `{key: K}` entries only; `{identity: I}` entries that name the purpose over the content leave it Unknown,
// since a key alone cannot be shown to act for I. An identity principal is matched by `{identity: I}` entries
// only; no key entry ever trusts an identity, and an identity entry never trusts a key.
func (p *Policy) TrustsPrincipal(pr Principal, purpose, content string) Answer {
	a := Answer{Key: pr.Key, Principal: pr, Purpose: purpose, Content: content}
	if !p.Configures(purpose) {
		a.State = Unconfigured
		return a
	}
	a.Policy, a.State = p.Digest, NotTrusted
	for _, t := range p.Trust {
		if !slices.Contains(t.Purposes, purpose) || !t.covers(content) {
			continue
		}
		switch {
		case t.Principal == pr:
			a.State, a.Entry = Trusted, t.text
			return a
		case pr.Key != "" && t.Principal.Identity != "" && a.State == NotTrusted:
			a.State, a.Entry = Unknown, t.text
		}
	}
	return a
}

// TrustsStatement is the question every consumer asks: does this reader trust the statement st for purpose over
// content. Its signing key is asked first, exactly as Trusts does. Only when that answer is Unknown (no key
// entry matched, and an identity entry names the purpose over the content) is actors consulted: st is trusted
// when the evaluator calls it eligible for an identity I and an `{identity: I}` entry trusts I for the purpose
// over the content. A statement the evaluator calls denied, or eligible for an identity no entry names, is not
// trusted; one it cannot decide reads UnknownActor. A bare statement by a worker key is never I's: it is not
// eligible for I, so I's trust never reaches it (profile §5.3, §6). With actors nil the answer is Trusts'.
func (p *Policy) TrustsStatement(st *wire.Statement, purpose, content string, actors ActorEligibility) Answer {
	a := p.Trusts(st.Signer, purpose, content)
	if a.State != Unknown || actors == nil {
		return a
	}
	id, state, why := actors.Eligible(st)
	a.Evaluator = evaluatorOf(actors)
	switch {
	case state == ActorEligible && id != "":
		b := p.TrustsPrincipal(Principal{Identity: id}, purpose, content)
		b.Evaluator = a.Evaluator
		b.Why = append([]string{"eligible for identity " + short(id)}, why...)
		if b.State != Trusted {
			b.Key, b.Why = st.Signer, append(b.Why, "no trust entry trusts that identity for this purpose over this content")
		}
		return b
	case state == ActorDenied:
		a.State, a.Entry = NotTrusted, ""
		a.Why = append([]string{"not eligible for identity " + short(id)}, why...)
		if id == "" {
			a.Why = append([]string{"no identity actor is eligible"}, why...)
		}
	default:
		a.State, a.Entry = UnknownActor, ""
		a.Why = append([]string{"actor eligibility is unknown"}, why...)
	}
	return a
}

// NamesIdentity reports whether some `{identity: I}` trust entry names purpose over content: the only case in
// which TrustsStatement consults an actor evaluator.
func (p *Policy) NamesIdentity(purpose, content string) bool {
	if p == nil {
		return false
	}
	for _, t := range p.Trust {
		if t.Principal.Identity != "" && slices.Contains(t.Purposes, purpose) && t.covers(content) {
			return true
		}
	}
	return false
}

// Configures reports whether trust is configured for purpose: a policy is configured and at least one of its
// trust entries names the purpose (whatever its principal or target).
func (p *Policy) Configures(purpose string) bool {
	if p == nil {
		return false
	}
	for _, t := range p.Trust {
		if slices.Contains(t.Purposes, purpose) {
			return true
		}
	}
	return false
}

func (t Trust) covers(content string) bool {
	if t.AnyContent {
		return true
	}
	return content != "" && slices.Contains(t.Contents, content)
}

// Floor is a gate's choice for evidence its admission trust does not cover: refuse it, or admit it and label it
// (C-core-111: "refused, or admitted and labelled, per the reader's policy"). reader-policy-v1 has no member for
// this choice, so the gate passes it in.
type Floor int

const (
	FloorRefuse Floor = iota
	FloorLabel
)

// TrustFloorReason is the refusal reason of an admission refused by the reader's trust floor (claims §11).
const TrustFloorReason = "trust floor"

// Admission is the admission predicate a gate calls for one object: Admitted, the trust answer behind it, a
// Label when it is admitted without admission trust, and a typed Refusal when it is refused.
type Admission struct {
	Admitted bool
	Answer   Answer
	Label    string
	Refusal  *refusal.Refusal
}

// Admit decides admission of an object signed by key whose content digest is content ("" when it names none)
// under the reader's trust floor: the policy's `admission` entries. With no admission entry (no policy, or a
// policy that names no principal for admission) every object is admitted unlabelled, as today. With one, an object whose signer is not trusted for admission over that content is
// refused with class `reader policy`, reason `trust floor`, scoped to the signer's objects, or admitted and
// labelled when floor is FloorLabel. Admission trust admits evidence; it never makes a signature valid, an
// authority, or a successful reproduction (note §6).
func (p *Policy) Admit(key, content string, floor Floor) Admission {
	return admission(p.Trusts(key, PurposeAdmission, content), "objects signed by "+key, floor)
}

// AdmitStatement is Admit for one statement, with identity entries decided by actors (TrustsStatement; nil
// actors is Admit over the signer). A refusal is scoped to this object when the answer rests on the statement's
// actor, and to the signer's objects otherwise.
func (p *Policy) AdmitStatement(st *wire.Statement, content string, floor Floor, actors ActorEligibility) Admission {
	ans := p.TrustsStatement(st, PurposeAdmission, content, actors)
	scope := "objects signed by " + st.Signer
	if len(ans.Why) > 0 {
		scope = "this object, signed by " + st.Signer
	}
	return admission(ans, scope, floor)
}

func admission(ans Answer, scope string, floor Floor) Admission {
	switch ans.State {
	case Unconfigured, Trusted:
		return Admission{Admitted: true, Answer: ans}
	}
	detail := fmt.Sprintf("scope: %s; %s", scope, ans)
	if floor == FloorLabel {
		return Admission{Admitted: true, Answer: ans, Label: "admitted below the reader's trust floor (" + detail + ")"}
	}
	return Admission{Answer: ans, Refusal: &refusal.Refusal{Class: refusal.Policy, Reason: TrustFloorReason, Detail: detail}}
}

func short(d string) string {
	const n = len("sha256:") + 12
	if len(d) > n {
		return d[:n]
	}
	return d
}
