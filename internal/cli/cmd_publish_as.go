package cli

import (
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// publish --as <identity> --grant <id>: a statement acting for a fixed-root identity (identity profile §2.1, §5).
// The writer signs it rc/2 with x_actor_v1 {identity, grant} in the signed envelope (wire.WriterMajor,
// wire.IdentityDraft) and appends it only when the identity evaluator over the statements this store holds plus
// the new line reads the act eligible for that identity. There is no override: an act the held evidence denies
// would count toward nothing, so the writer does not make one (publish --draft without --as stays the raw path).

// prepareActor reads --as, --grant and --amends: the request alone decides these refusals (exit 2).
func prepareActor(c *Ctx, p *pubPrep) *Problem {
	as, hasAs := c.Flag("as")
	grant, hasGrant := c.Flag("grant")
	am, hasAmends := c.Flag("amends")
	switch {
	case hasAs != hasGrant:
		return usage("missing-argument", "--as and --grant go together", "an act for an identity names the identity and the grant it acts under; nothing was done",
			"option --as", "give both --as <identity> and --grant <grant id>", "")
	case hasAmends && !hasAs:
		return usage("conflicting-options", "--amends needs --as", "only an act for an identity amends the identity's claims; nothing was done",
			"option --amends", "give --as and --grant, or drop --amends", am)
	case !hasAs:
		return nil
	}
	if wire.WriterMajor(p.kind, true) != wire.CandidateMajor {
		return usage("malformed-argument", "this kind does not act for an identity",
			p.kind+" is a raw-key statement or a key event in the identity profile (§2.1, §2.3) and carries no actor; nothing was done",
			"option --as", "publish it without --as", p.kind)
	}
	if hasAmends {
		if p.kind != "authored" && p.kind != "observed" {
			return usage("conflicting-options", "--amends applies to authored and observed only", "nothing was done", "option --amends", "drop --amends", p.kind)
		}
		for _, x := range strings.Split(am, ",") {
			if !slices.Contains(p.amends, x) {
				p.amends = append(p.amends, x)
			}
		}
		slices.Sort(p.amends)
	}
	p.actor = &wire.Actor{Identity: as, Grant: grant}
	return nil
}

// amendsMarker is the body marker of an act: {amends: [...]} or {} (nil: IdentityDraft's default).
func amendsMarker(ids []string) *canon.Object {
	if len(ids) == 0 {
		return nil
	}
	a := canon.Array{}
	for _, id := range ids {
		a = append(a, canon.String(id))
	}
	return &canon.Object{Keys: []string{"amends"}, Members: map[string]canon.Value{"amends": a}}
}

// actingAnswer is the identity evaluator's answer for the signed act s over the held statements plus s. Eligible for
// the named identity: the answer to print. Denied: refused, exit 2, naming why. Anything else: refused, exit 3.
func actingAnswer(c *Ctx, s signed) (*Obj, *Problem) {
	lines, err := c.Store.Statements()
	if err != nil {
		return nil, failed(err, "store", false, "run status, then fsck")
	}
	ev := heldActors(lines, s.line)
	state, id, why := policy.ActorUnknown, "", []string{"no identity evaluator"}
	if ev != nil {
		id, state, why = ev.Eligible(s.st)
	}
	a := newObj().set("identity", refV(s.st.Actor.Identity)).set("grant", refV(s.st.Actor.Grant))
	if state == policy.ActorEligible && id == s.st.Actor.Identity {
		a.set("state", tokV(tok(policy.ActorEligible)))
		if len(why) > 0 {
			a.set("reasons", texts(why...))
		}
		return a, nil
	}
	detail := "the identity evaluator over the statements this store holds plus this line reads the act " + state
	if id == "" {
		detail += " and binds it to no identity"
	}
	if len(why) > 0 {
		detail += ": " + strings.Join(why, "; ")
	}
	p := &Problem{Slug: "act-not-eligible", Title: "refused: the act would not count for the identity", Class: refusal.Policy, Scope: "option --as",
		Detail: detail + "; nothing was signed or appended", Peer: s.st.Actor.Grant, Exit: ExitDidNotStart,
		Next: "act under a grant of that identity naming your key, in force and covering this kind and target (commons show <grant>)"}
	if state != policy.ActorDenied {
		p.Slug, p.Title, p.Exit = "act-undecided", "refused: the held statements cannot decide the act", ExitCouldNot
		p.Next = "fetch the identity's inception, the grant and your key's first line (pull from the root's store), then publish again"
	}
	return nil, p
}
