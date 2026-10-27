package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// gc: local garbage collection (storage note §6.1, §6.2) through store.GC and store.Release. A dry run by
// default: it prints what it would delete, with hashes and sizes, what it keeps and why, and states its side
// effects ("no deletion; no registry change"); --apply deletes, re-checking each candidate at deletion.
// --grace <d> sets the window for this run only and is printed in the plan. --release <hash> is the one way to
// remove a blob the operator's own serving `holds` pins: it signs a `holds` with withdrawn:true and deletes the
// blob in one operation, so it acts at once and takes the signing key (--key <file>, else $COMMONS_KEY_FILE;
// never printed). It does not combine with --apply or --grace.

func init() {
	Register(&Command{Name: "gc", Summary: "list (default) or delete unreferenced blobs outside the grace window; release a blob this store serves",
		Flags: []Flag{
			{Name: "apply", Help: "delete the candidates (default: a dry run that deletes nothing)"},
			{Name: "grace", Value: "duration", Help: "the grace window for this run only (Go duration, e.g. 10m, 48h); default the policy window",
				Check: func(v string) error {
					d, err := time.ParseDuration(v)
					if err != nil || d < 0 {
						return errors.New("a non-negative duration such as 10m or 48h")
					}
					return nil
				}},
			{Name: "release", Value: "digest", Help: "withdraw this store's serving holds for the blob and delete it, as one operation (signs; acts at once)",
				Check: func(v string) error {
					if !isDigest(v) {
						return errors.New("a content digest (sha256: + 64 lowercase hex)")
					}
					return nil
				}},
			{Name: "key", Value: "file", Help: "the signing key file for --release (default: $" + KeyEnv + "); a key file written by commons key new; never printed"},
		},
		Store: true, Before: gcBefore,
		Help: "Exit 0 the plan was made (dry run) or carried out; 2 did not start (a malformed duration or digest, --release with --apply or --grace, --key without --release, no usable key for --release); 3 the operation failed after work started (the output says whether anything was committed).",
		Run:  gcCmd})
}

func gcBefore(c *Ctx) *Problem {
	_, rel := c.Flag("release")
	_, apply := c.Flag("apply")
	_, grace := c.Flag("grace")
	keyPath, keyGiven := c.Flag("key")
	switch {
	case rel && (apply || grace):
		return usage("conflicting-options", "--release does not combine with --apply or --grace",
			"a release acts at once on the one blob it names; nothing was done", "option --release", "run gc --release <digest> on its own", "")
	case keyGiven && !rel:
		return usage("conflicting-options", "--key applies only to --release", "nothing else gc does signs; nothing was done",
			"option --key", "drop --key, or add --release <digest>", "")
	case !rel:
		return nil
	}
	if keyPath == "" && c.Env.Getenv(KeyEnv) == "" {
		return policyProblem("no-key", "--release needs a signing key", "option --key",
			"give --key <file> or set "+KeyEnv+"; a release that cannot sign deletes nothing", "")
	}
	k, prob := signingKey(c)
	if prob != nil {
		return prob
	}
	c.state = k.Key
	return nil
}

func gcCmd(c *Ctx) (*Obj, int, error) {
	if d, ok := c.Flag("release"); ok {
		return releaseCmd(c, store.Digest(d), c.state.(wire.Key))
	}
	cfg := store.GCConfig{}
	if g, ok := c.Flag("grace"); ok {
		d, _ := time.ParseDuration(g)
		cfg.PerRun = &d
	}
	_, apply := c.Flag("apply")
	plan, err := c.Store.GC(cfg, apply)
	if err != nil {
		committed := plan != nil && len(plan.Deleted) > 0
		return nil, 0, failed(err, "store", committed, "run gc again (it re-checks everything); if it recurs, fsck")
	}
	o := newObj().set("grace_window", textV(plan.Grace.String())).set("grace_source", textV(plan.GraceSource))
	rows := func(bs []store.GCBlob, why bool) listV {
		l := listV{}
		for _, b := range bs {
			r := rowObj().set("digest", refV(string(b.Digest))).set("size", intV(b.Size))
			if why {
				r.set("why", textV(b.Why))
			}
			l = append(l, r)
		}
		return l
	}
	if plan.Applied {
		o.set("deleted", rows(plan.Deleted, false))
		if len(plan.Skipped) > 0 {
			o.set("kept_at_recheck", rows(plan.Skipped, true))
		}
	} else {
		o.set("would_delete", rows(plan.Candidates, false))
	}
	o.set("kept", rows(plan.Kept, true))
	if len(plan.Strays) > 0 {
		st := listV{}
		for _, s := range plan.Strays {
			st = append(st, peerV(s))
		}
		o.set("strays_left_alone", st)
	}
	o.set("side_effects", textV(plan.SideEffects()))
	if !plan.Applied {
		o.set("next", textV("re-run with --apply to delete the listed blobs"))
	}
	return o, ExitOK, nil
}

func releaseCmd(c *Ctx, d store.Digest, k wire.Key) (*Obj, int, error) {
	res, err := c.Store.Release(d, store.SignerFromKey(k, nil))
	committed := res != nil && res.Withdrawal != ""
	if err != nil {
		next := "nothing was deleted; see the detail"
		if committed {
			next = "the withdrawal is committed; run gc --release again to finish the removal"
		}
		return nil, 0, failed(err, "blob "+string(d), committed, next)
	}
	o := newObj().set("blob", refV(string(d))).set("signer", refV(k.Signer()))
	if res.Withdrawal != "" {
		o.set("withdrawal", refV(res.Withdrawal)).set("operation", refV(res.Op))
	}
	o.set("blob_removed", boolV(res.BlobRemoved))
	if res.Completed {
		o.set("note", textV("an earlier release had committed the withdrawal; this run removed the blob"))
	}
	if res.NeedsRepair != nil {
		o.set("store_state", tokV(tok("committed, needs repair")))
	}
	se := "committed one operation: a holds with withdrawn: true"
	if res.Withdrawal == "" {
		se = "no statement committed"
	}
	o.set("side_effects", textV(fmt.Sprintf("%s; blob file %s under blobs/; no other statement or registry entry changed", se, map[bool]string{true: "deleted", false: "not deleted"}[res.BlobRemoved])))
	return o, ExitOK, nil
}
