package cli

import (
	"errors"
	"strings"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/hubcheck"
)

// push: the sender's side of a hub (storage note §3.2, §4.5; claims-model note §11; bitcoin-time note §2, §10).
// The store is a git checkout of the hub; the change a push would carry is what HEAD adds over the hub's branch
// (merge-base(base, HEAD)..HEAD), read through git plumbing exactly as `hub check` reads it (package hubcheck),
// and judged by gate.Push against the hub's history and policy at the base: what the hub's CI would answer.
// Beside the verdicts it applies the writer's own preconditions, which are not admission verdicts and which no
// other gate applies: the anchor before transport (a statement whose standing requires an anchor is not carried
// until an anchors line covers it) and the withheld bytes (a blob whose availability is withheld is not carried
// before its reveal).
//
// This slice transports nothing: only --dry-run is built. Like hub check it is not a Store command: opening a store
// replays its journal, a write, and a dry run writes nothing (C-core-137).

// PushSideEffects is the dry run's declaration of what it did not do.
const PushSideEffects = "no registry change; no fetch; no cache; no transport"

// WithheldBytes is the reason of the withheld precondition's refusal.
const WithheldBytes = "withheld bytes"

func init() {
	Register(&Command{Name: "push", Summary: "check what pushing this hub checkout's commits would carry, as the hub's CI would judge it, and the anchor and withheld-bytes preconditions (only --dry-run is built; writes nothing)",
		Flags: []Flag{
			{Name: "remote", Value: "name", Help: "the git remote that is the hub (default origin)", Check: func(v string) error {
				if v == "" || strings.HasPrefix(v, "-") || strings.ContainsAny(v, " \t\n/:\\") {
					return errors.New("a remote name is non-empty, does not start with -, and holds no space, slash or colon")
				}
				return nil
			}},
			{Name: "base", Value: "rev", Help: "the hub branch the change is for, as this checkout knows it (default refs/remotes/<remote>/HEAD; exit 2 when that is not set)", Check: func(v string) error {
				if v == "" || strings.HasPrefix(v, "-") {
					return errors.New("a revision is a non-empty name that does not start with -")
				}
				return nil
			}},
			{Name: "anchor-policy", Value: "required|none", Help: "your local anchor policy for every statement carried, replacing the default by standing (bitcoin-time note §2 step 3); named in the output", Check: func(v string) error {
				if v != "required" && v != "none" {
					return errors.New("required or none")
				}
				return nil
			}},
			{Name: "dry-run", Help: "judge and print what the push would carry; transport nothing (the only mode built)"},
		},
		Prepare: preparePush, Run: pushCmd,
		Help: "Run inside a git checkout of the hub whose top level holds rc-store (a store kept elsewhere: pull it into a hub checkout first). " +
			"The change is merge-base(<base>, HEAD)..HEAD: commit what you publish, then push; data files the working tree has and HEAD does not are listed as uncommitted and are not carried. " +
			"Each object gets the verdict the hub's CI would give (hub check: the hub's history and hub-policy.json at the base). " +
			"Then the writer's preconditions, which are not admission verdicts: each statement carried whose standing requires an anchor (an authored without provenance, a fulfills, a withheld availability, an anchored-at-capture observation) is refused, reader policy anchor required, unless an anchors line by its signer, carried or held by the hub, covers it; a pending proof covers (run anchor stamp, commit, push). A statement with standing anchor: none that nothing covers is carried with a warning naming the rule. --anchor-policy replaces the standing for every statement. " +
			"A blob carried whose availability a statement declares withheld, with no serving holds (the reveal), is refused, reader policy " + WithheldBytes + ": carrying it would release the bytes. An anchors line whose proof blob neither travels nor is held by the hub is carried with a warning (readers see missing-proof until it is held). " +
			"No transport is built yet: without --dry-run, push exits 2 and does nothing. " +
			"Exit 0 nothing refused and nothing undecided; 1 at least one object or precondition refused; 2 did not start (no --dry-run, not a hub checkout, no such remote, base not known, unusable hub-policy.json at the base); 3 nothing refused and at least one object undecided, or git failed. Side effects: none (" + PushSideEffects + ")."})
}

func preparePush(c *Ctx) *Problem {
	if _, ok := c.Flag("dry-run"); !ok {
		return usage("not-available", "transport not built yet; use --dry-run", "push transports nothing in this build: --dry-run judges what it would carry; nothing was done",
			"invocation", "run commons push --dry-run; to send the commits, git push the branch and open a pull request on the hub", "")
	}
	return nil
}

func pushCmd(c *Ctx) (*Obj, int, error) {
	wd, err := c.Env.Getwd()
	if err != nil {
		return nil, 0, usage("no-hub", "not inside a hub checkout", "the working directory could not be read; nothing was done", "working directory", "run push from inside a hub checkout", "")
	}
	remote, ok := c.Flag("remote")
	if !ok {
		remote = "origin"
	}
	base, _ := c.Flag("base")
	var override btctime.AnchorDefault
	switch v, _ := c.Flag("anchor-policy"); v {
	case "required":
		override = btctime.AnchorRequired
	case "none":
		override = btctime.AnchorNone
	}
	plan, err := hubcheck.PlanPush(wd, hubcheck.PushConfig{Remote: remote, Base: base})
	if err != nil {
		var d *gate.DidNotStart
		if errors.As(err, &d) {
			return nil, 0, didNotStart(d)
		}
		return nil, 0, failed(err, "repository", false, "check that git works in this checkout, then run push again")
	}
	pre := plan.CheckPreconditions(override)

	o := gateReport(plan.Report)
	o.set("hub", peerV(plan.Root)).set("remote", peerV(plan.Remote)).set("head", refV(plan.Head)).
		set("base", refV(plan.Base)).set("base_from", peerV(plan.BaseFrom)).set("merge_base", refV(plan.MergeBase))
	pol := o.get("policy").(*Obj)
	pol.set("revision", refV(plan.PolicyRev))
	if plan.PolicyAbsent {
		pol.set("source", textV("defaults (no "+hubcheck.PolicyFile+" at the base)"))
	} else {
		pol.set("source", textV(hubcheck.PolicyFile+" at the base (the hub's policy, as its CI reads it)"))
	}

	ag := listV{}
	for _, a := range pre.Anchors {
		row := rowObj().set("path", peerV(a.Path)).set("id", refV(a.ID)).set("standing", textV(string(a.Standing))).set("decided_by", textV(a.DecidedBy))
		if len(a.CoveredBy) > 0 {
			row.set("covered_by", refs(a.CoveredBy...))
		}
		if a.Refused {
			row.set("verdict", tokV(tok(string(gate.Refused)))).set("class", tokV(tok("reader policy"))).set("reason", textV(string(btctime.AnchorRequired))).
				set("scope", peerV("statement "+a.ID)).
				set("next", textV("commons anchor stamp "+a.ID+", commit the anchors line and its proof blob, then push again (or --anchor-policy none)"))
		} else {
			row.set("verdict", tokV(tok(string(gate.Admitted))))
		}
		ag = append(ag, row)
	}
	o.set("anchor_gate", ag)
	wh := listV{}
	for _, w := range pre.Withheld {
		wh = append(wh, rowObj().set("path", peerV(w.Path)).set("id", refV(w.Digest)).set("verdict", tokV(tok(string(gate.Refused)))).
			set("class", tokV(tok("reader policy"))).set("reason", textV(WithheldBytes)).set("declared_by", refs(w.By...)).
			set("scope", peerV("object "+w.Path)).
			set("next", textV("remove the blob from the commit (keep it in your store), or publish and commit the holds that reveals it first")))
	}
	o.set("withheld", wh)
	if len(pre.Warnings) > 0 {
		o.set("warnings", texts(pre.Warnings...))
	}
	if len(plan.Uncommitted) > 0 {
		us := listV{}
		for _, p := range plan.Uncommitted {
			us = append(us, peerV(p))
		}
		o.set("uncommitted", us).set("uncommitted_note", textV("data files in the working tree that HEAD does not hold as they are: not part of the change, not carried; commit them to carry them"))
	}
	o.set("transport", textV("none: dry run (no transport is built yet)"))
	o.set("evaluator", evaluatorObj(c.Env.Build))
	o.set("side_effects", textV(PushSideEffects))
	code := gateExit(plan.Report)
	if pre.Refused() {
		code = ExitWrong
	}
	return o, code, nil
}
