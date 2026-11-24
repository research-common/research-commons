package identity

import (
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/identitymodel"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

// Actors is the CANDIDATE actor evaluator: policy.ActorEligibility over one admitted Snapshot. It answers, for a
// statement, whether the statement may act for the identity its signed actor names, from the reference model's
// Evaluate. It does no trust evaluation and reads no policy (profile §6: eligibility is authority, trust is the
// reader's own choice).
//
// Every production reader builds it over its held lines through Evaluator (nil when none is an rc/2 line), and
// passes it to the resolver and the pull gate's trust floor. The writer still signs rc/1 only (wire.Major).
//
// Statements are looked up by id in the snapshot, never read from the caller's *wire.Statement: the default
// reader retains an rc/2 line unverified and never sets its Actor, so the caller's copy cannot say what was
// signed. A statement the snapshot does not hold has no evidence here.
type Actors struct {
	s   *Snapshot
	lim identitymodel.Limits // zero: the profile's caps; tests lower them (export_test.go)
}

// NewActors admits lines (Admit) and returns the evaluator over the resulting snapshot.
func NewActors(lines [][]byte) (*Actors, error) {
	s, err := Admit(lines)
	if err != nil {
		return nil, err
	}
	return s.Actors(), nil
}

// Actors returns the actor evaluator over this snapshot.
func (s *Snapshot) Actors() *Actors { return &Actors{s: s} }

// Snapshot is the admitted evidence the evaluator answers from.
func (a *Actors) Snapshot() *Snapshot { return a.s }

// EvaluatorContext is what an answer resting on this evaluator cites beside the reader policy digest: two readers
// with the same policy and different evaluators or evidence are told apart by it.
type EvaluatorContext struct {
	// Version is the model's evaluator version.
	Version string
	// EvidenceDigest is the model digest over normalized facts.
	EvidenceDigest string
	// Receipt digests the exact admitted lines (Snapshot.Receipt).
	Receipt string
}

// String is the context as one reader-facing phrase.
func (c EvaluatorContext) String() string {
	return c.Version + " over evidence " + short(c.EvidenceDigest) + " (receipt " + short(c.Receipt) + ")"
}

// Context is the evaluator context of every answer this evaluator gives.
func (a *Actors) Context() EvaluatorContext {
	return EvaluatorContext{Version: identitymodel.EvaluatorVersion, EvidenceDigest: a.s.EvidenceDigest(), Receipt: a.s.Receipt()}
}

// Evaluator is Context as text (policy.ActorEvaluator): what a trust answer that consulted this evaluator cites.
func (a *Actors) Evaluator() string { return a.Context().String() }

// Eligible implements policy.ActorEligibility.
//
//   - A statement the snapshot does not hold: ("", unknown), "not in the actor evaluator's evidence".
//   - A held statement with no identity actor (every rc/1 line, an rc/1 line carrying x_actor_v1 included):
//     ("", denied), no_identity_actor. Its bare-key eligibility is the legacy evaluator's, not this one's.
//   - An actor without an issuer-authenticated binding (bound): "" with the model's status. The claim names an
//     identity this evidence cannot connect the signer to, so it must not stall that identity (profile §5.1).
//   - A bound actor: the identity it names, with the model's status: eligible, denied or unknown.
//   - A model cap (model_limit): unknown naming the cap, whatever else the walk found before it stopped.
//
// why lists the model's reasons as "code: detail" (sorted, as the model gives them), then its warnings as
// "warning code: detail" (an eligible act under an open grant after a delegate's self-revoke is never shown
// clean: profile §4.1).
func (a *Actors) Eligible(st *wire.Statement) (identity, state string, why []string) {
	if st == nil {
		return "", policy.ActorUnknown, []string{"no statement"}
	}
	held, ok := a.s.held[st.ID]
	if !ok {
		return "", policy.ActorUnknown, []string{"not in the actor evaluator's evidence"}
	}
	r := a.s.model.EvaluateWith(identitymodel.ID(st.ID), a.lim)
	why = reasons(r)
	state = mapStatus(r.Status)
	capped := false
	for _, x := range r.Reasons {
		if x.Code == "model_limit" {
			capped = true
		}
	}
	if capped {
		state = policy.ActorUnknown
	}
	if r.Actor.Kind != identitymodel.IdentitySubject || held.Actor == nil {
		if !capped && state != policy.ActorUnknown {
			state = policy.ActorDenied
		}
		return "", state, why
	}
	if !a.bound(held) {
		return "", state, append(why, "no issuer-authenticated binding of this signer to identity "+short(held.Actor.Identity))
	}
	return string(r.Actor.Identity), state, why
}

// bound reports whether the actor's grant is issuer-authenticated evidence that connects this signer to the
// identity it names: the identity's inception and the grant are both held and authenticated, the grant is signed
// by the inception's (root) key, and it names this identity and this signer as delegate. Whether the grant is in
// force (lineage, cuts, scope, retirement) is the model's answer, not this test's: a bound actor's denial or
// uncertainty is the identity's to report.
func (a *Actors) bound(st *wire.Statement) bool {
	id, gid := st.Actor.Identity, st.Actor.Grant
	root, ok := a.s.held[id]
	if !ok || !a.s.Authenticated(id) || root.Kind != "identity_inception" {
		return false
	}
	g, ok := a.s.held[gid]
	if !ok || !a.s.Authenticated(gid) || g.Kind != "identity_grant" || g.Body == nil {
		return false
	}
	if g.Signer != root.Signer && !a.s.successorRoot(id, g.Signer) {
		return false
	}
	return idText(g.Body, "identity") == id && text(object(g.Body, "delegate"), "key") == st.Signer
}

// successorRoot reports whether key has an authenticated identity_succession for identity at seq 0 in the
// snapshot: issuer-authenticated evidence that it is, or was named to be, a later root of a recoverable-root
// identity (recoverable-root note §4). Whether the recovery that named it is complete is the model's answer.
func (s *Snapshot) successorRoot(identity, key string) bool {
	for id, st := range s.held {
		if st.Kind == "identity_succession" && st.Seq == 0 && st.Signer == key && s.Authenticated(id) && st.Body != nil &&
			idText(st.Body, "identity") == identity {
			return true
		}
	}
	return false
}

// NotEstablished is the freshness of every identity answer (the model's word, re-exported: only this adapter
// imports the model).
const NotEstablished = identitymodel.NotEstablished

// Grant is one grant naming a delegate key, with its grant-level state (profile §4.1, "requirements on
// consumers"): the second axis of every view of a delegate, beside the key's bare-key status.
type Grant struct {
	Grant, Identity string
	// State is identitymodel.GrantStatus as text: open, cut at last_good, cut null, unknown or denied.
	State string
	// LastGood is each last_good of an effective cut at a line (state cut at last_good).
	LastGood []string
	// Cuts is every held cut addressed to the grant on its identity's lineage.
	Cuts []string
	// Why lists the model's reasons, then its warnings, as Eligible's why does.
	Why []string
	// Freshness is always identitymodel.NotEstablished: a cut this reader does not hold is not ruled out.
	Freshness string
}

// Grants lists every grant of the snapshot naming delegate as its delegate key, by grant id, each with its
// grant-level state. A grant not signed by its identity's root key is never open: the model's root-ancestry check
// denies it (wrong_signer), as it denies every act under it.
func (a *Actors) Grants(delegate string) []Grant {
	var out []Grant
	for _, gid := range a.s.model.GrantsTo(identitymodel.Key(delegate)) {
		gs := a.s.model.GrantStateWith(gid, a.lim)
		g := Grant{Grant: string(gid), Identity: string(gs.Identity), State: string(gs.Status), Freshness: gs.Freshness}
		for _, l := range gs.LastGood {
			g.LastGood = append(g.LastGood, string(l))
		}
		for _, c := range gs.Cuts {
			g.Cuts = append(g.Cuts, string(c))
		}
		g.Why = reasons(identitymodel.Result{Reasons: gs.Reasons, Warnings: gs.Warnings})
		out = append(out, g)
	}
	return out
}

func mapStatus(s identitymodel.Status) string {
	switch s {
	case identitymodel.Eligible:
		return policy.ActorEligible
	case identitymodel.Denied:
		return policy.ActorDenied
	}
	return policy.ActorUnknown
}

func reasons(r identitymodel.Result) []string {
	var out []string
	for _, x := range r.Reasons {
		out = append(out, phrase(x.Code, x.Detail))
	}
	for _, w := range r.Warnings {
		out = append(out, "warning "+phrase(w.Code, w.Detail))
	}
	return slices.Compact(out)
}

func phrase(code, detail string) string {
	if detail == "" {
		return code
	}
	return code + ": " + detail
}

func short(d string) string {
	const n = len("sha256:") + 12
	if strings.HasPrefix(d, "sha256:") && len(d) > n {
		return d[:n]
	}
	if len(d) > 12 && !strings.HasPrefix(d, "sha256:") {
		return d[:12]
	}
	return d
}
