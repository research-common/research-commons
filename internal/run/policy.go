package run

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/refusal"
)

// Policy is the reader's execution policy (execution note §2, §2.3, §2.4, §6). Every grant is explicit; the
// zero Policy grants nothing.
//
// The policy says which keys and workflow hashes the reader lets run. It deliberately holds no notion of trust
// in a key: trust level, hub endorsement and task beneficiary status grant nothing (§2.3, C-exec-07). The
// trust level a refusal shows is passed in by the caller as display only (Request.TrustShown).
type Policy struct {
	// ExecSigners and ExecWorkflows grant executable admission per signer key or per workflow hash (§2.3).
	ExecSigners   []string
	ExecWorkflows []string
	// Own are the reader's own keys: only a workflow signed by one of them may run native (§2.4).
	Own []string
	// NativeWorkflows and NativeAll are the `native` grant: per workflow hash, or `own: all` (§2).
	NativeWorkflows []string
	NativeAll       bool
	// AcceptNative accepts native records in a stranger's `verify`: the profile mismatch is still named and the
	// comparison proceeds (§2.4).
	AcceptNative bool
	// Network grants a network to a workflow hash (§2.1); the run may use only the endpoints its spec declares.
	Network []string
	// Grants maps a workflow hash to the named secrets or host resources that may cross into it (§6). Only the
	// names are ever recorded; values never leave the runner.
	Grants map[string][]string
	// Ceiling is the most the reader allows per cap (§2.2). An absent cap is not limited by the reader.
	Ceiling Resources
	// Images is the digest-pinned image allowlist, when present (§2.1). Entries are digests; an entry that is
	// not a digest cannot be resolved and refuses (fails closed, operational).
	Images []string
}

// Reasons for the refusals made before staging. Each is a stable token; Detail names the specifics.
const (
	ReasonAdmission   = "executable admission"
	ReasonNative      = "native"
	ReasonNetwork     = "network"
	ReasonResources   = "resources"
	ReasonNoImage     = "no image"
	ReasonImageList   = "image allowlist"
	ReasonRuntime     = "sandbox runtime unavailable"
	ReasonProfile     = "unknown profile"
	ReasonImageDigest = "hash mismatch"
	ReasonUnsafePath  = "unsafe path"
)

// Request is one invocation of `run` as the admission checks see it.
type Request struct {
	Spec *Spec
	// Signer is the key that signed the workflow's `authored` statement (the workflow's author).
	Signer string
	// Profile is the profile the invocation named: "" means sandbox (§2: the default). The implementation never
	// changes it.
	Profile string
	// BelowProfile is the reader's explicit opt-in to run below the spec's declared profile (§2.2).
	BelowProfile bool
	// TrustShown is the reader's trust level in Signer, as text, shown beside a missing grant so the reader sees
	// why trust did not suffice (§2.3). Never read as permission.
	TrustShown string
}

func (q Request) profile() string {
	if q.Profile == "" {
		return Sandbox
	}
	return q.Profile
}

// Admitted is what admission decided: the profile, the caps in force (with the declared values of any lowered
// cap), the network granted, and the grant names that cross.
type Admitted struct {
	Profile  string
	Caps     Resources
	Declared Resources
	Network  []string
	Grants   []string
	// Undeclared lists the caps the spec does not declare: they run at the implementation floor (here, the
	// reader's ceiling) and are shown as `undeclared` (§1 table).
	Undeclared []string
}

// Admit makes every check §2 places before staging, in a fixed order, and refuses with the first that fails.
// It runs nothing and touches no file. A refusal here is not a result token and writes no run record (§5.2).
//
//  1. the profile: `sandbox` or `native`, never changed (§2);
//  2. executable admission for the signer or the workflow hash (§2.3);
//  3. for `native`: the author key is the reader's own, and a native grant covers the workflow (§2.4);
//  4. for `sandbox`: the spec pins an image, and an allowlist (if any) is digest-pinned and admits it (§2.1);
//  5. network: `required` needs a grant naming this workflow hash (§2.1);
//  6. resources: the spec's profile against the reader's ceiling (§2.2).
func (p *Policy) Admit(q Request) (*Admitted, error) {
	s := q.Spec
	prof := q.profile()
	scope := "workflow " + s.Digest
	if prof != Sandbox && prof != Native {
		return nil, &refusal.Refusal{Class: refusal.Policy, Reason: ReasonProfile, Detail: fmt.Sprintf("profile %q is neither sandbox nor native; %s", prof, scope)}
	}
	if !slices.Contains(p.ExecSigners, q.Signer) && !slices.Contains(p.ExecWorkflows, s.Digest) {
		d := "no execution grant for signer " + q.Signer + " or " + scope
		if q.TrustShown != "" {
			d += "; trust level " + q.TrustShown + " (trust is not permission to execute)"
		}
		return nil, &refusal.Refusal{Class: refusal.Policy, Reason: ReasonAdmission, Detail: d}
	}
	if prof == Native {
		switch {
		case !slices.Contains(p.Own, q.Signer):
			return nil, &refusal.Refusal{Class: refusal.Policy, Reason: ReasonNative,
				Detail: "the workflow's author " + q.Signer + " is not one of the reader's own keys; native runs only the reader's own workflows; " + scope}
		case !p.NativeAll && !slices.Contains(p.NativeWorkflows, s.Digest):
			return nil, &refusal.Refusal{Class: refusal.Policy, Reason: ReasonNative,
				Detail: "no native grant covers " + scope}
		}
	}
	if prof == Sandbox {
		if s.Image == nil {
			return nil, &refusal.Refusal{Class: refusal.Policy, Reason: ReasonNoImage, Detail: "the spec pins no image; sandbox needs one; " + scope}
		}
		if p.Images != nil {
			ok := false
			for _, e := range p.Images {
				if !IsDigest(e) {
					return nil, &refusal.Refusal{Class: refusal.Operational, Reason: ReasonImageList,
						Detail: fmt.Sprintf("allowlist entry %q is not a digest and cannot be resolved; the allowlist fails closed", e)}
				}
				ok = ok || e == s.Image.Digest
			}
			if !ok {
				return nil, &refusal.Refusal{Class: refusal.Policy, Reason: ReasonImageList,
					Detail: "image " + s.Image.Digest + " is not on the reader's allowlist; " + scope}
			}
		}
	}
	a := &Admitted{Profile: prof}
	if s.Network != nil {
		if !slices.Contains(p.Network, s.Digest) {
			return nil, &refusal.Refusal{Class: refusal.Policy, Reason: ReasonNetwork,
				Detail: "the spec requires network (" + strings.Join(s.Network, ", ") + ") and no policy grant names " + scope}
		}
		a.Network = slices.Clone(s.Network)
	}
	caps, declared, undeclared, err := Caps(s.Resources, p.Ceiling, q.BelowProfile)
	if err != nil {
		return nil, err
	}
	a.Caps, a.Declared, a.Undeclared = caps, declared, undeclared
	if g := p.Grants[s.Digest]; len(g) > 0 {
		a.Grants = slices.Sorted(slices.Values(g))
	}
	return a, nil
}

// Caps decides the cap values in force (§2.2). The spec's value is used when it is at or under the reader's
// ceiling. A spec value over the ceiling refuses (reader policy: resources) naming both numbers, unless the
// reader opted in to running below the declared profile: then the ceiling is in force and the declared value is
// recorded beside it. A cap the spec does not declare runs at the ceiling (the floor this implementation offers)
// and is listed as undeclared.
func Caps(spec, ceiling Resources, below bool) (caps, declared Resources, undeclared []string, err error) {
	caps, declared = Resources{}, Resources{}
	var over []string
	for _, c := range CapNames {
		sv, sok := spec[c]
		cv, cok := ceiling[c]
		switch {
		case !sok:
			undeclared = append(undeclared, c)
			if cok {
				caps[c] = cv
			}
		case cok && sv > cv:
			if !below {
				over = append(over, fmt.Sprintf("%s: the spec declares %d, the reader's ceiling is %d", c, sv, cv))
				continue
			}
			caps[c], declared[c] = cv, sv
		default:
			caps[c] = sv
		}
	}
	if len(over) > 0 {
		return nil, nil, nil, &refusal.Refusal{Class: refusal.Policy, Reason: ReasonResources,
			Detail: strings.Join(over, "; ") + "; run where the declared profile is available, raise the ceiling, or opt in to running below the declared profile"}
	}
	if len(declared) == 0 {
		declared = nil
	}
	return caps, declared, undeclared, nil
}
