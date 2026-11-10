package wire

import (
	"strconv"

	"github.com/research-common/research-commons/internal/canon"
)

// The CANDIDATE rc/2 resource kinds (docs/DESIGN-notes-fixed-root-identity.md §2.1, §5.2, §5.3): genesis, edition
// and withdraw_approval read with typed controller subjects. Nothing here changes an rc/1 body: the rc/1 schema
// (schema.go) still reads `controllers` as a set of keys, and Read never reaches this file.

// subject is one typed subject: an object with exactly one member, `key` (a key) or `identity` (a statement id).
func subject() rule {
	return func(v canon.Value, p string, ctx *schemaCtx) error {
		o, ok := v.(*canon.Object)
		if !ok {
			return bad(p, "is not a typed subject ({key: K} or {identity: I})")
		}
		if len(o.Keys) != 1 {
			return bad(p, "must carry exactly one of key, identity")
		}
		switch k := o.Keys[0]; k {
		case "key":
			return key()(o.Members[k], p+".key", ctx)
		case "identity":
			return id()(o.Members[k], p+".identity", ctx)
		default:
			return bad(p+"."+k, "is not a member of a typed subject")
		}
	}
}

// subjects is a nonempty set of typed subjects, sorted by the JCS text of each entry and duplicate-free (§3: the
// profile's ordering for structured sets), of at most maxSetEntries entries.
func subjects() rule {
	return func(v canon.Value, p string, ctx *schemaCtx) error {
		a, ok := v.(canon.Array)
		if !ok {
			return bad(p, "is not a list")
		}
		if len(a) == 0 {
			return bad(p, "is an empty set")
		}
		if len(a) > maxSetEntries {
			return bad(p, "has more than "+strconv.Itoa(maxSetEntries)+" entries")
		}
		for i, e := range a {
			if err := subject()(e, p+"["+itoa(i)+"]", ctx); err != nil {
				return err
			}
			if i > 0 && canon.CompareKeys(string(canon.Encode(a[i-1])), string(canon.Encode(e))) >= 0 {
				return bad(p, "is a set and is not sorted and duplicate-free")
			}
		}
		return nil
	}
}

// taskRoles is the edition marker's task_roles object (§5.3): a closed object with one typed beneficiary, exactly
// one of eligible_issuers (typed subjects) and any_issuer:true, and an explicit counting unit. Shape only: no
// consumer reads it in this reader.
func taskRoles() rule {
	inner := exactlyOne([]field{opt("eligible_issuers", subjects()), opt("any_issuer", isTrue())},
		req("beneficiary", subject()), req("counting_unit", enum("key", "identity")))
	return func(v canon.Value, p string, ctx *schemaCtx) error {
		if o, ok := v.(*canon.Object); ok {
			if why := closed(o, p, "beneficiary", "eligible_issuers", "any_issuer", "counting_unit"); why != "" {
				return bad(p, why[len(p)+1:])
			}
		}
		return inner(v, p, ctx)
	}
}

// contractRoleFields are the role declarations a contract must not carry beside the identity marker's task_roles
// (§5.3: forbidden, never silently overridden).
var contractRoleFields = []string{"any_issuer", "beneficiary", "counting_unit", "eligible_issuers"}

var candidateResourceKinds = map[string][]field{
	"genesis": {req("type", enum("collection", "task", "series")), req("name", text()), req("controllers", subjects()),
		req("rule", ruleObj), opt("forked_from", id())},
	"edition":           {req("resource", id()), req("predecessors", boundedIDs()), req("contents", object(candidateEditionContents()...))},
	"withdraw_approval": kinds["withdraw_approval"],
}

// boundedIDs is a nonempty sorted duplicate-free set of statement ids of at most maxSetEntries entries.
func boundedIDs() rule {
	return func(v canon.Value, p string, _ *schemaCtx) error { return boundedSet(v, p, id()) }
}

// candidateEditionContents is the rc/1 edition contents with typed `controllers` and a contract that names its
// profile.
func candidateEditionContents() []field {
	out := make([]field, 0, len(editionContents))
	for _, f := range editionContents {
		switch f.name {
		case "controllers":
			f = opt("controllers", subjects())
		case "contract":
			f = opt("contract", object(req("profile", text())))
		}
		out = append(out, f)
	}
	return out
}

// resourceBody reads an rc/2 genesis, edition or withdraw_approval. The marker is {} except that an edition's may
// carry task_roles; a task_roles object and a contents.contract come together or not at all; a contract carries
// no top-level role declaration; a controller change names both complete typed controllers and a rule (§2.1:
// partial changes are refused); a genesis rule is satisfiable by its controllers.
func resourceBody(s *Statement, marker *canon.Object) (Status, string) {
	mp := "body." + IdentityCrit
	if s.Kind == "edition" {
		if why := closed(marker, mp, "task_roles"); why != "" {
			return Invalid, why
		}
		if tr, ok := marker.Get("task_roles"); ok {
			if err := taskRoles()(tr, mp+".task_roles", &schemaCtx{}); err != nil {
				return Invalid, err.Error()
			}
		}
	} else if len(marker.Keys) != 0 {
		return Invalid, mp + " must be {} for " + s.Kind
	}
	ctx := &schemaCtx{}
	if err := checkFields(s.Body, "body", ctx, candidateResourceKinds[s.Kind]); err != nil {
		return Invalid, err.Error()
	}
	if err := checkBodyTimes(s.Kind, s.Body); err != nil {
		return Invalid, err.Error()
	}
	switch s.Kind {
	case "genesis":
		if err := satisfiable(s.Body, "body"); err != nil {
			return Invalid, err.Error()
		}
	case "edition":
		if err := completenessBeside(s.Body); err != nil {
			return Invalid, err.Error()
		}
		c := s.Body.Members["contents"].(*canon.Object)
		_, hasCtrl := c.Get("controllers")
		_, hasRule := c.Get("rule")
		if hasCtrl != hasRule {
			return Invalid, "body.contents: a controller change names both complete controllers and rule"
		}
		cv, hasContract := c.Get("contract")
		_, hasRoles := marker.Get("task_roles")
		switch {
		case hasContract && !hasRoles:
			return Invalid, "body.contents.contract requires " + mp + ".task_roles"
		case hasRoles && !hasContract:
			return Invalid, mp + ".task_roles requires body.contents.contract"
		}
		if hasContract {
			for _, f := range contractRoleFields {
				if _, ok := cv.(*canon.Object).Get(f); ok {
					return Invalid, "body.contents.contract." + f + " is forbidden: task roles live in " + mp + ".task_roles"
				}
			}
		}
	}
	s.Unpinned, s.refs = ctx.unpinned, sortedRefs(ctx.refs)
	return Valid, ""
}
