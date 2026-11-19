package cli

import (
	"errors"
	"strconv"
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
// When the judgement is clean (the gate exits 0 and no precondition refuses) and --dry-run is not given, push sends
// the judged commit with one `git push <remote> <sha>:refs/heads/<branch>` in the user's git environment, never
// forced (hubcheck.Send). Any other judgement transports nothing. Like hub check it is not a Store command: opening
// a store replays its journal, a write, and push writes nothing in the store (C-core-137).

// PushSideEffects is the declaration of a push that sent nothing: a dry run, or a judgement that was not clean.
const PushSideEffects = "no registry change; no fetch; no cache; no transport"

// PushSentSideEffects is the declaration of a push that ran the transport (whether or not git's push was accepted).
const PushSentSideEffects = "no registry change; no fetch; no cache; one git push of the judged commit to one branch, never forced (git records the remote branch it saw in refs/remotes/<remote>/<branch>)"

// WithheldBytes is the reason of the withheld precondition's refusal.
const WithheldBytes = "withheld bytes"

func init() {
	Register(&Command{Name: "push", NoStoreHint: "drop --store and run push from inside a git checkout of the hub (the store is the checkout's top level); a store kept elsewhere is pulled into a hub checkout first", Examples: []string{"commons push --dry-run"}, Summary: "judge the commits of this hub checkout as the hub's CI would, apply the anchor and withheld-bytes preconditions, and when all is clean git push the judged commit (never forced; --dry-run sends nothing)",
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
			{Name: "branch", Value: "name", Help: "the remote branch to update (default: the base's branch on the remote, e.g. main for origin/HEAD → origin/main); name your own branch to open a pull request from it", Check: func(v string) error {
				if !hubcheck.BranchName(v) {
					return errors.New("a short branch name: not HEAD, no refs/ prefix, no leading -, no space, colon, *, ?, [, \\, ^, ~ or @{")
				}
				return nil
			}},
			{Name: "anchor-policy", Value: "required|none", Help: "your local anchor policy for every statement carried, replacing the default by standing (bitcoin-time note §2 step 3); named in the output", Check: func(v string) error {
				if v != "required" && v != "none" {
					return errors.New("required or none")
				}
				return nil
			}},
			{Name: "dry-run", Help: "judge and print what the push would carry; send nothing"},
		},
		Prepare: preparePush, Run: pushCmd,
		Help: "Run inside a git checkout of the hub whose top level holds rc-store (a store kept elsewhere: pull it into a hub checkout first). " +
			"The change is merge-base(<base>, HEAD)..HEAD: commit what you publish, then push; data files the working tree has and HEAD does not are listed as uncommitted and are not carried. " +
			"Each object gets the verdict the hub's CI would give (hub check: the hub's history and hub-policy.json at the base). " +
			"Then the writer's preconditions, which are not admission verdicts: each statement carried whose standing requires an anchor (an authored without provenance, a fulfills, a withheld availability, an anchored-at-capture observation) is refused, reader policy anchor required, unless an anchors line by its signer, carried or held by the hub, covers it; a pending proof covers (run anchor stamp, commit, push). A statement with standing anchor: none that nothing covers is carried with a warning naming the rule. --anchor-policy replaces the standing for every statement. " +
			"A blob carried whose availability a statement declares withheld, with no serving holds (the reveal), is refused, reader policy " + WithheldBytes + ": carrying it would release the bytes. An anchors line whose proof blob neither travels nor is held by the hub is carried with a warning (readers see missing-proof until it is held). " +
			"Transport: only when every object is admitted and no precondition refuses, push runs git push <remote> <judged commit>:refs/heads/<branch> in your own git environment (your credentials, configuration and hooks), never forced, no tags. It sends the commit it judged, never whatever HEAD is by then. The branch is --branch, else the base's branch on the remote (origin/HEAD → main); when the base is not a branch of the remote, push exits 2 asking for --branch. " +
			"To contribute through a pull request, push to a branch of your own: --branch <name> on the hub, or --remote <your fork> --base origin/main --branch <name>; then open the pull request. Pushing to the hub's default branch directly works where the hub allows it (a protected branch refuses it: exit 3, the hub's answer quoted). " +
			"A refusal by git (the branch moved on, authentication, a hook, a protected branch) is exit 3 with transported false and git's message, credentials removed. Nothing is ever pushed when the judgement exits 1 or 3. " +
			"Exit 0 nothing refused and nothing undecided, and (without --dry-run) the hub's branch holds the judged commit; 1 at least one object or precondition refused, nothing sent; 2 did not start (not a hub checkout, no such remote, base not known, branch not known, unusable hub-policy.json at the base); 3 nothing refused and at least one object undecided (nothing sent), or git failed or refused the push. Side effects: none in the store; " + PushSideEffects + " for a dry run or a judgement that is not clean, else " + PushSentSideEffects + "."})
}

func preparePush(c *Ctx) *Problem { return nil }

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
	branch, _ := c.Flag("branch")
	_, dry := c.Flag("dry-run")
	var override btctime.AnchorDefault
	switch v, _ := c.Flag("anchor-policy"); v {
	case "required":
		override = btctime.AnchorRequired
	case "none":
		override = btctime.AnchorNone
	}
	plan, err := hubcheck.PlanPush(wd, hubcheck.PushConfig{Remote: remote, Base: base, Branch: branch, Transport: !dry})
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
	code := gateExit(plan.Report)
	if pre.Refused() {
		code = ExitWrong
	}
	if plan.Branch != "" {
		o.set("branch", peerV(plan.Branch)).set("branch_from", peerV(plan.BranchFrom))
	}
	effects := PushSideEffects
	switch {
	case dry:
		o.set("transport", textV("none: dry run")).set("transported", boolV(false))
	case code != ExitOK:
		// the judgement decides: a refusal (1) or an undecided object (3) sends nothing (C-core-108, C-btc-03c)
		o.set("transport", textV("none: the judgement is not clean (exit "+strconv.Itoa(code)+"); nothing is sent unless every object is admitted and no precondition refuses")).
			set("transported", boolV(false))
	default:
		effects = PushSentSideEffects
		sent, err := plan.Send()
		if err != nil {
			return nil, 0, failed(err, "option --branch", false, "name the branch with --branch <name>")
		}
		o.set("transport", textV("git push "+plan.Remote+" "+sent.Pushed+":"+sent.Ref)).set("transported", boolV(sent.Transported)).
			set("pushed", refV(sent.Pushed)).set("update", peerV(sent.Update))
		if !sent.Transported {
			code = ExitCouldNot
			o.set("git", peerV(sent.Git)).set("next", textV(pushNext(sent)))
		}
	}
	o.set("evaluator", evaluatorObj(c.Env.Build))
	o.set("side_effects", textV(effects))
	return o, code, nil
}

// pushNext is the next step after git refused or failed the push.
func pushNext(s *hubcheck.SendResult) string {
	switch {
	case strings.Contains(s.Update, "non-fast-forward") || strings.Contains(s.Update, "fetch first") || strings.Contains(s.Update, "stale info"):
		return "the hub's branch has moved on: fetch, rebase your data commits onto the hub, push again (never force)"
	case strings.HasPrefix(s.Update, "remote rejected"):
		return "the hub refused the update (a protected branch or a hook): push to a branch of your own with --branch <name> and open a pull request, or ask the hub's maintainers"
	}
	return "check that git push works from this checkout to the remote (its URL, your credentials), then run push again; nothing was sent"
}
