package policy

import (
	"fmt"
	"slices"

	"github.com/research-common/research-commons/internal/refusal"
)

// TrustState is the answer to "does this reader trust key K for purpose P over content C".
type TrustState string

const (
	// Unconfigured: no policy is configured. Callers keep their documented no-policy behaviour and say so.
	Unconfigured TrustState = "not configured"
	// Trusted: a `{key: K}` entry names the purpose and its target covers the content.
	Trusted TrustState = "trusted"
	// NotTrusted: a policy is configured and no entry trusts K for the purpose over the content. No configured
	// trust means not trusted, never universal trust (note §6).
	NotTrusted TrustState = "not trusted"
	// Unknown: no `{key: K}` entry matches, but an `{identity: I}` entry names the purpose over the content, and
	// this reader cannot tell whether K acts for I (the identity profile is not active). Not trusted for
	// counting, and labelled as unknown rather than as a refusal of K.
	Unknown TrustState = "unknown (identity profile not active)"
)

// Answer is one trust answer with what it rests on.
type Answer struct {
	State                 TrustState
	Key, Purpose, Content string
	// Entry is the canonical text of the matching trust entry (Trusted), or of the identity entry that made
	// the answer unknown (Unknown).
	Entry string
	// Policy is the policy digest the answer comes from; "" when unconfigured.
	Policy string
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
	switch a.State {
	case Unconfigured:
		return "trust not configured"
	case Trusted:
		return fmt.Sprintf("trusted for %s under reader policy %s", what, short(a.Policy))
	case Unknown:
		return fmt.Sprintf("trust for %s unknown under reader policy %s: the policy names an identity, and the identity profile is not active", what, short(a.Policy))
	}
	return fmt.Sprintf("not trusted for %s under reader policy %s", what, short(a.Policy))
}

// Trusts answers whether the policy trusts signing key key for purpose over content (the content being judged,
// never an incidental digest; "" when the evidence names no content, which only an any_content target covers).
// A purpose matches only itself. Overlapping entries are additive: one match is enough.
func (p *Policy) Trusts(key, purpose, content string) Answer {
	a := Answer{Key: key, Purpose: purpose, Content: content}
	if p == nil {
		a.State = Unconfigured
		return a
	}
	a.Policy, a.State = p.Digest, NotTrusted
	for _, t := range p.Trust {
		if !slices.Contains(t.Purposes, purpose) || !t.covers(content) {
			continue
		}
		switch {
		case t.Principal.Key == key:
			a.State, a.Entry = Trusted, t.text
			return a
		case t.Principal.Identity != "" && a.State == NotTrusted:
			a.State, a.Entry = Unknown, t.text
		}
	}
	return a
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
// under the reader's trust floor: the policy's `admission` entries. With no policy every object is admitted
// unlabelled, as today. With one, an object whose signer is not trusted for admission over that content is
// refused with class `reader policy`, reason `trust floor`, scoped to the signer's objects, or admitted and
// labelled when floor is FloorLabel. Admission trust admits evidence; it never makes a signature valid, an
// authority, or a successful reproduction (note §6).
func (p *Policy) Admit(key, content string, floor Floor) Admission {
	ans := p.Trusts(key, PurposeAdmission, content)
	switch ans.State {
	case Unconfigured, Trusted:
		return Admission{Admitted: true, Answer: ans}
	}
	detail := fmt.Sprintf("scope: objects signed by %s; %s", key, ans)
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
