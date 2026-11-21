package cli

import (
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// An identity's root key is dedicated (fixed-root note, "Root vocabulary on the pinned I lineage is closed"): on
// the identity's lineage it signs its inception, grants, cuts, describes, anchors and key events, and nothing else.
// Any other line there reads unsupported_root_event to every reader that holds it, which leaves every act of the
// identity's delegates unknown, earlier ones included. The writer refuses such a line with no override: nothing
// useful is gained by signing it.
//
// The check sits where every signed line passes before it is appended or packaged (commitUnit, commitUnitFrom,
// gc --release), and asks one question of the store: does it hold a valid identity_inception signed by this key?
// It can only see this store: a root key used with a store that does not hold its inception is not refused.

// rootLineGuard is off only in the test that shows the refusal is what keeps the line out (the mutation check).
var rootLineGuard = true

// rootInceptions lists the valid identity inceptions signed by signer that the store holds, sorted.
func rootInceptions(s *store.Store, signer string) ([]string, error) {
	sts, err := s.SignerStatements(signer)
	if err != nil {
		return nil, err
	}
	var out []string
	for id, st := range sts {
		if st.Kind == "identity_inception" && st.Seq == 0 && st.Verified && st.Status == wire.Valid {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out, nil
}

// rootLineRefused refuses a unit holding a line outside the root vocabulary signed by the root of an identity whose
// inception the store holds. none says what was not done ("nothing was appended", "no package was written").
func rootLineRefused(s *store.Store, sts []*wire.Statement, none string) *Problem {
	if !rootLineGuard {
		return nil
	}
	for _, st := range sts {
		if st.Kind == "identity_inception" || identity.InRootVocabulary(st) {
			continue // an inception is identity new's, which refuses a key that already has a log
		}
		ids, err := rootInceptions(s, st.Signer)
		if err != nil {
			return failed(err, "store", false, "run status, then fsck")
		}
		if len(ids) == 0 {
			continue
		}
		what := "identity " + ids[0]
		if len(ids) > 1 {
			what = "identities " + strings.Join(ids, ", ")
		}
		return &Problem{Slug: "root-ordinary-line", Title: "refused: this key is an identity's root; it signs only identity statements",
			Class: refusal.Policy, Scope: "this key's log",
			Detail: "this store holds the inception of " + what + ", signed by this key; a line of kind " + st.Kind +
				" by an identity's root is outside the closed root vocabulary (inception, grants, cuts, describes, anchors, key events): one ordinary statement by an identity's root stops the identity's delegates' acts from counting, earlier acts included; " + none,
			Next: "sign it with another key (a delegate of the identity with commons publish --as, or a key of its own: commons key new --out <file>)",
			Peer: ids[0], Exit: exitWriterRefused}
	}
	return nil
}

func signedStatements(sts []signed) []*wire.Statement {
	out := make([]*wire.Statement, len(sts))
	for i, s := range sts {
		out[i] = s.st
	}
	return out
}

// rootLinesObj is the reader's pointer (issue #271): the held lines signed by the root of the identity whose
// inception is ident, outside the closed root vocabulary. Every one of them reads unsupported_root_event, which
// leaves the identity's acts unknown; nil when there is none, so a sound identity's output is unchanged.
func (v *view) rootLinesObj(root, ident string) *Obj {
	l := listV{}
	for _, ln := range v.logs.Log(root).View().Lines {
		st := ln.St
		if st.ID == ident || st.Kind == "identity_inception" && st.Seq == 0 || identity.InRootVocabulary(st) {
			continue
		}
		l = append(l, newObj().set("statement", refV(st.ID)).set("kind", peerV(st.Kind)).set("seq", intV(st.Seq)))
	}
	if len(l) == 0 {
		return nil
	}
	return newObj().set("identity", refV(ident)).set("lines", l).
		set("effect", textV("these lines by the identity's root are outside the closed root vocabulary (inception, grants, cuts, describes, anchors, key events): every reader that holds one reads the identity's acts unknown, earlier acts included")).
		set("recovery", textV("if a line never left the store it was written in, removing it there restores the identity; once another store holds it, treat the identity as one whose root is lost"))
}

// rootLinesFor is rootLinesObj for every valid identity inception signed by key that this store holds.
func (v *view) rootLinesFor(key string) listV {
	ids, err := rootInceptions(v.st, key)
	if err != nil {
		return nil
	}
	l := listV{}
	for _, id := range ids {
		if o := v.rootLinesObj(key, id); o != nil {
			l = append(l, o)
		}
	}
	return l
}
