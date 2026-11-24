package wire

import (
	"errors"

	"github.com/research-common/research-commons/internal/canon"
)

// identityExtension is the validator the identity reader registers for the one critical extension of the candidate
// profile, x_identity_v1 (docs/DESIGN-notes-fixed-root-identity.md §2.1, §2.3). The reader's registry runs it on a
// verified rc/2 envelope whose crit names the extension, and it decides everything the marker and its pairing with
// the signed actor must satisfy; the kind's own body is read afterwards (candidateBody), so a recognized marker
// never replaces the base schema. It returns nil to accept, otherwise the reason the statement is Invalid.
//
// env is the private copy the registry hands a validator: the envelope without sig. The function reads only that
// argument: it is deterministic and has no side effects (ExtensionValidator).
//
// The rules, in the order every reader applied them before the registry existed (each reason is unchanged):
//
//   - body.x_identity_v1 is an object;
//   - the raw-key administrative kinds (identity_inception, identity_grant, identity_cut) and genesis and
//     describes take no x_actor_v1;
//   - the marker's own shape per kind: {} for the administrative kinds, the task kinds without an intent pin, and
//     every base kind but authored and observed; {intent} for progress and withdraw; {task_roles} for an edition
//     (the roles' own shape is checked here, their pairing with the contract is the edition's body rule);
//     {amends?} for authored and observed, where `amends` needs an actor.
//
// Kinds the reader does not interpret (a raw key event, an unknown kind) have no marker rule: their reasons are
// the kind's, and nothing is promoted to Valid by a registered extension.
func identityExtension(env *canon.Object) error {
	bodyV, _ := env.Get("body")
	body, _ := bodyV.(*canon.Object)
	if body == nil {
		return extErr("body is not an object")
	}
	markerV, _ := body.Get(IdentityCrit)
	marker, ok := markerV.(*canon.Object)
	if !ok {
		return extErr("body." + IdentityCrit + " is not an object")
	}
	kindV, _ := env.Get("kind")
	kind, _ := kindV.(canon.String)
	k := string(kind)
	_, hasActor := env.Get(ActorField)
	admin := k == "identity_inception" || k == "identity_grant" || k == "identity_cut" ||
		k == "identity_succession" || k == "identity_recovery" || k == "identity_handover"
	if hasActor && (admin || k == "genesis" || k == "describes") {
		return extErr(k + " is a raw-key statement and takes no " + ActorField)
	}
	mp := "body." + IdentityCrit
	switch {
	case admin:
		if len(marker.Keys) != 0 {
			return extErr(mp + " must be {}")
		}
	case k == "rotate_key" || k == "revoke_key" || candidateNotImplemented[k]:
		// the kind's own reason (raw key events stay rc/1, not implemented), not a marker rule
	case candidateTask[k]:
		if k == "progress" || k == "withdraw" {
			if why := closed(marker, mp, "intent"); why != "" {
				return extErr(why)
			}
			if _, ok := idValue(marker, "intent"); !ok {
				return extErr(mp + ".intent is required for " + k + " and must be a statement id (the attempt's intent)")
			}
		} else if len(marker.Keys) != 0 {
			return extErr(mp + " must be {} for " + k)
		}
	case candidateResource[k]:
		if k == "edition" {
			if why := closed(marker, mp, "task_roles"); why != "" {
				return extErr(why)
			}
			if tr, ok := marker.Get("task_roles"); ok {
				if err := taskRoles()(tr, mp+".task_roles", &schemaCtx{}); err != nil {
					return err
				}
			}
		} else if len(marker.Keys) != 0 {
			return extErr(mp + " must be {} for " + k)
		}
	case candidateBase[k]:
		if k == "authored" || k == "observed" {
			if why := closed(marker, mp, "amends"); why != "" {
				return extErr(why)
			}
			if av, ok := marker.Get("amends"); ok {
				if err := boundedSet(av, mp+".amends", id()); err != nil {
					return err
				}
				if !hasActor {
					return extErr("amends requires an identity actor")
				}
			}
		} else if len(marker.Keys) != 0 {
			return extErr(mp + " must be {} for " + k)
		}
	}
	return nil
}

// extErr is a validator's refusal reason. The identity reader reports it unchanged as the Why of an Invalid line.
func extErr(why string) error { return errors.New(why) }

// runValidators runs the registered validator of every crit name, in crit order, each on its own deep copy of the
// envelope (the registry's isolation guarantee), and returns the first error unchanged. The unchanged reader turns
// that error into a refusal (validateExtensions); the identity reader turns it into an Invalid statement, because
// its line is verified by now and a verified line that breaks a rule stays visible as non-passing evidence. Every
// name in crit must be registered (supports): the caller preflights, so no validator runs for a partly unknown list.
func (r *Reader) runValidators(crit []string, env *canon.Object) error {
	for _, name := range crit {
		if err := r.extensions[name](copyExtensionValue(env).(*canon.Object)); err != nil {
			return err
		}
	}
	return nil
}
