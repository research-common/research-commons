package cli

import (
	"errors"

	"github.com/research-common/research-commons/internal/refusal"
)

// Problem is an error in the form of claims-model note §13: an RFC 9457 problem-details object (`type`,
// `title`, `detail`) with the extension members `class`, `scope`, `committed` and `next`. The same object is
// a CLI's JSON output and a hub's HTTP error body.
//
// Title, Detail and Next are the tool's own words. Peer-supplied text (a value from a statement, a file name
// from a package, the argument a user typed) goes in Peer, an extension member carrying a JSON string, and is
// never interpolated into Title or Detail (§13).
type Problem struct {
	Slug   string // the type's last segment, a stable token: unknown-option, malformed-argument, …
	Title  string
	Detail string
	Class  refusal.Class
	Scope  string // what it applies to: "invocation", "argument <name>", "policy file", "store", a statement id
	// Committed says whether anything landed. Always false with exit 2.
	Committed bool
	Next      string
	// Peer is the offending peer- or user-supplied text, carried verbatim as a JSON string; "" when none.
	Peer string
	Exit int
}

// ProblemTypeBase prefixes every problem type. It is a URN, not a URL: the type identifies the problem and
// is never dereferenced by the tool (RFC 9457 §3.1.1 allows a non-resolvable URI).
const ProblemTypeBase = "urn:research-commons:problem:"

func (p *Problem) Error() string { return p.Title + ": " + p.Detail }

func (p *Problem) obj() *Obj {
	o := newObj().
		set("type", textV(ProblemTypeBase+p.Slug)).
		set("title", textV(p.Title)).
		set("detail", textV(p.Detail)).
		set("class", textV(string(p.Class))).
		set("scope", textV(p.Scope)).
		set("committed", boolV(p.Committed)).
		set("next", textV(p.Next)).
		set("exit", intV(p.Exit))
	if p.Peer != "" {
		o.set("peer_text", peerV(p.Peer))
	}
	return o
}

// Problem classes for conditions that are not refusals of an object. Claims-model §11 names three classes
// (intrinsic, reader policy, operational); an invocation the tool cannot act on is classed by what is wrong:
// an argument or file that no reader could act on is intrinsic, scoped to that argument or file; a missing or
// unusable store is operational, scoped to the store.

func usage(slug, title, detail, scope, next, peer string) *Problem {
	return &Problem{Slug: slug, Title: title, Detail: detail, Class: refusal.Intrinsic, Scope: scope, Next: next,
		Peer: peer, Exit: ExitDidNotStart}
}

// failed wraps an error that happened after work started: never exit 2 (§13: exit 2 never accompanies
// partial results). committed says whether the operation reached its commit point.
func failed(err error, scope string, committed bool, next string) *Problem {
	var p *Problem
	if errors.As(err, &p) {
		return p
	}
	pr := &Problem{Slug: "operation-failed", Title: "the operation did not complete", Class: refusal.Operational,
		Scope: scope, Committed: committed, Next: next, Exit: ExitCouldNot}
	var r *refusal.Refusal
	if errors.As(err, &r) {
		pr.Class, pr.Slug = r.Class, "refused"
		pr.Title = "refused: " + r.Reason
	}
	pr.Detail = "the store or resolver returned an error; its text is in peer_text because it may quote stored bytes"
	pr.Peer = err.Error()
	if committed {
		pr.Detail += "; the operation reached its commit point and the next open of the store replays it"
	} else {
		pr.Detail += "; nothing was committed"
	}
	return pr
}
