package cli

import (
	"errors"
	"strings"

	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/hubcheck"
)

// hub check: a hub's CI over one change (hub template docs/CLI-CONTRACT.md, H-01 to H-52), through package
// hubcheck, which reads the repository by git plumbing only and passes the change to the same validation core
// pull uses. It is not a Store command: opening a store replays its journal, a write, and the check writes
// nothing (H-14). The hub root is the nearest ancestor of the working directory holding rc-store (H-10); the
// policy is hub-policy.json at the base revision (H-12); nothing else configures it: no --store, no reader
// policy, no environment variable (H-13).

func init() {
	Register(&Command{Name: "hub check", Summary: "check a change to the hub this directory is in, as the hub's CI does (writes nothing)",
		Flags: []Flag{{Name: "base", Value: "rev", Help: "check the change between merge-base(<rev>, HEAD) and HEAD against the tree and hub-policy.json at <rev> (default: a full check of the tree at HEAD)",
			Check: func(v string) error {
				if v == "" || strings.HasPrefix(v, "-") {
					return errors.New("a revision is a non-empty name that does not start with -")
				}
				return nil
			}}},
		Help: "Exit 0 every object admitted (possibly labelled) or only control-plane paths reported, 1 at least one object refused, 2 the check did not start (not inside a hub, unknown layout, --base not a commit, unusable hub-policy.json at the base), 3 nothing refused and at least one object undecided, or git failed. Side effects: none (no registry change; no fetch; no cache).",
		Run:  hubCheckCmd})
}

func hubCheckCmd(c *Ctx) (*Obj, int, error) {
	wd, err := c.Env.Getwd()
	if err != nil {
		return nil, 0, usage("no-hub", "not inside a hub", "the working directory could not be read; nothing was done", "working directory", "run the check from inside a hub checkout", "")
	}
	base, _ := c.Flag("base")
	res, err := hubcheck.Check(wd, hubcheck.Config{Base: base})
	if err != nil {
		var d *gate.DidNotStart
		if errors.As(err, &d) {
			return nil, 0, didNotStart(d)
		}
		return nil, 0, failed(err, "repository", false, "check that git works in this checkout, then run the check again")
	}
	o := gateReport(res.Report)
	o.set("hub", peerV(res.Root)).set("head", refV(res.Head))
	if res.Base != "" {
		o.set("base", refV(res.Base)).set("merge_base", refV(res.MergeBase))
	}
	pol := o.get("policy").(*Obj)
	pol.set("revision", refV(res.PolicyRev))
	if res.PolicyAbsent {
		pol.set("source", textV("defaults (no "+hubcheck.PolicyFile+" at the policy revision)"))
	} else {
		pol.set("source", textV(hubcheck.PolicyFile+" at the policy revision"))
	}
	o.set("evaluator", evaluatorObj(c.Env.Build))
	o.set("side_effects", textV(hubcheck.SideEffects))
	return o, gateExit(res.Report), nil
}

// didNotStart maps a gate's did-not-start error to exit 2 problem details.
func didNotStart(d *gate.DidNotStart) *Problem {
	scope := d.Scope
	if scope == "" {
		scope = "invocation"
	}
	return &Problem{Slug: "did-not-start", Title: d.Title, Detail: "nothing was evaluated and nothing committed; the cause is in peer_text",
		Class: d.Class(), Scope: scope, Next: d.Next, Peer: d.Detail, Exit: ExitDidNotStart}
}
