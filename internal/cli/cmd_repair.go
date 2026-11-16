package cli

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/store"
)

// repair [<operation-id>|--all] [--blob <file>]: finish committed operations the store could not finish on its
// own (storage note §3.5). Opening the store has already replayed every journal record (§3.4); what is left is a
// record whose blob is missing (`committed, needs repair`), one whose projection failed, or one whose replay failed
// (a permission, a full disk). repair runs steps 3–5 again for the named record (every record with --all or with no
// argument) through store.Repair, continuing past a record that fails, then rebuilds the registered projections and
// compares each with a cold build.
//
// --blob <file> installs exact bytes the record names: the file is hashed before the store is opened and must hash
// to a blob an unfinished record names (the named record, or any record with --all); the install hashes it again and
// installs nothing on a mismatch. So a missing blob is repaired without a hold that serves it.
//
// repair never signs, rewrites or deletes a statement or a blob, never rolls back, never reads an operation history,
// and never reads, moves or deletes anything under quarantine/: it prints how many items are there.
//
// Exit (claims-model note §13): 0 every named record finished and every projection equals a cold build (a
// well-formed operation id no record has is "nothing to repair": exit 0); 1 a projection still differs from a cold
// build after the rebuild (the check ran and disagreed: a bug); 2 a malformed operation id, conflicting options, or
// --blob bytes no unfinished record names (nothing was done); 3 a record could not be finished (a blob still
// missing, a replay that still fails), or the repair failed after it started.

var reOpID = regexp.MustCompile(`^[0-9a-f]{64}$`)

func init() {
	Register(&Command{Name: "repair", Summary: "finish committed operations the store could not finish: reinstall, re-check blobs, rebuild projections",
		Args: []Arg{{Name: "operation", Shape: ShapeText, Optional: true}},
		Flags: []Flag{
			{Name: "all", Help: "every unfinished journal record (the default when no operation is named)"},
			{Name: "blob", Value: "file", Help: "install these exact bytes first: they must hash to a blob an unfinished record names (the named operation's, or any with --all); hashed again on install, nothing installed on a mismatch",
				Check: func(v string) error {
					if v == "" {
						return errors.New("a file")
					}
					return nil
				}},
		},
		Store: true, Prepare: prepareRepair, Before: repairBefore, Run: repairCmd,
		Help: "Every open of the store replays unfinished journal records first; repair finishes what that replay could not: a blob a committed operation names is missing (give it with --blob <file>, or commons fetch <digest>, then repair), a projection failed, or a replay failed (fix the permission or free the disk, then repair). It never signs, rewrites or deletes a statement or blob, never rolls back, and never touches quarantine/ (it prints how many items are there; inspect them with fsck). Exit 0 every named operation finished and every projection equals a cold build (an operation id no record has: nothing to repair, also 0); 1 a projection still differs from a cold build after the rebuild; 2 did not start (a malformed operation id, an operation id with --all, --blob bytes no unfinished operation names); 3 an operation could not be finished (a blob still missing, a replay still failing), or the repair failed after it started.",
	})
}

// repairPrep is what Prepare and Before checked, for Run.
type repairPrep struct {
	ops      []string
	blobFile string
	blob     store.Digest // the digest of --blob's bytes when Prepare hashed them
}

func prepareRepair(c *Ctx) *Problem {
	p := &repairPrep{}
	op, hasOp := c.Args["operation"]
	if _, all := c.Flag("all"); all && hasOp {
		return usage("conflicting-options", "an operation id and --all name different sets",
			"give one operation id, or --all; nothing was done", "option --all", "drop the operation id or --all", "")
	}
	if hasOp {
		if !reOpID.MatchString(op) {
			return usage("malformed-argument", "an argument has the wrong shape",
				"the argument must be an operation id (64 lowercase hex: commons status lists them); nothing was done",
				"argument operation", "give the full operation id", op)
		}
		p.ops = []string{op}
	}
	if f, ok := c.Flag("blob"); ok {
		fh, err := os.Open(f)
		if err != nil {
			return usage("unreadable-file", "a file named on the command line cannot be read", "nothing was done", "option --blob", "check the path", f)
		}
		d, err := store.HashReader(fh)
		fh.Close()
		if err != nil {
			return usage("unreadable-file", "a file named on the command line cannot be read", "nothing was done", "option --blob", "check the file", f)
		}
		p.blobFile, p.blob = f, d
	}
	c.Prep = p
	return nil
}

// repairBefore checks --blob against the journal before the store is opened: the bytes must be a blob an
// unfinished record names. It reads the journal only.
func repairBefore(c *Ctx) *Problem {
	p := c.Prep.(*repairPrep)
	if p.blobFile == "" {
		return nil
	}
	recs, err := store.JournalBlobs(c.Root)
	if err != nil {
		return &Problem{Slug: "operation-failed", Title: "the journal could not be read", Class: refusal.Operational, Scope: "store",
			Detail: "repair checks --blob against the journal before it opens the store; the error is in peer_text; nothing was done",
			Next:   "run commons status; if the store is damaged, fsck", Peer: err.Error(), Exit: ExitDidNotStart}
	}
	var named []string
	for op, bs := range recs {
		if len(p.ops) > 0 && !slices.Contains(p.ops, op) {
			continue
		}
		for _, b := range bs {
			if b == p.blob {
				return nil
			}
			named = append(named, string(b))
		}
	}
	slices.Sort(named)
	what := "no unfinished journal record names a blob"
	if len(named) > 0 {
		what = "the unfinished record(s) name " + strings.Join(slices.Compact(named), ", ")
	}
	if len(p.ops) > 0 {
		if _, ok := recs[p.ops[0]]; !ok {
			what = "no unfinished journal record has that operation id"
		}
	}
	return &Problem{Slug: "blob-not-named", Title: "the bytes are not a blob an unfinished operation names", Class: refusal.Intrinsic,
		Scope: "option --blob", Detail: "the file hashes to " + string(p.blob) + "; " + what + "; nothing was done",
		Next: "give the file whose bytes the operation names (commons status lists the operation, fsck names its missing blob), or commons fetch <digest> from a hold",
		Peer: p.blobFile, Exit: ExitDidNotStart}
}

func repairCmd(c *Ctx) (*Obj, int, error) {
	p := c.Prep.(*repairPrep)
	o := newObj().set("store", refV(c.Root))
	var effects []string
	if p.blobFile != "" {
		f, err := os.Open(p.blobFile)
		if err != nil {
			return nil, 0, failed(err, "option --blob", false, "check the file and run repair again")
		}
		_, res, err := c.Store.InstallBlob(f, p.blob)
		f.Close()
		if err != nil {
			// a hash mismatch here means the file changed since it was checked: nothing was installed
			return nil, 0, failed(err, "option --blob", false, "the file changed while repairing? run repair again")
		}
		o.set("blob", newObj().set("digest", refV(string(p.blob))).set("result", textV(string(res))))
		effects = append(effects, fmt.Sprintf("blob %s %s from --blob", p.blob, res))
	}
	evs, err := c.Store.Repair(p.ops...)
	if err != nil {
		return nil, 0, failed(err, "store", false, "run commons status; if the store is damaged, fsck")
	}
	// the blobs each record still present names, for the next step of one whose blob is still missing
	recBlobs, err := store.JournalBlobs(c.Root)
	if err != nil {
		return nil, 0, failed(err, "store", false, "run commons status; if the store is damaged, fsck")
	}
	code := ExitOK
	rows := listV{}
	finished := 0
	for _, e := range evs {
		x := rowObj().set("what", tokV(tok(e.What)))
		if e.Op != "" {
			x.set("operation", refV(e.Op))
		}
		if e.Kind != "" {
			x.set("kind", textV(e.Kind))
		}
		switch e.What {
		case "needs repair":
			code = ExitCouldNot
			var missing []string
			for _, b := range recBlobs[e.Op] {
				if !c.Store.HasBlob(b) {
					missing = append(missing, string(b))
				}
			}
			x.set("store_state", tokV(tok("committed, needs repair")))
			if len(missing) > 0 {
				x.set("missing_blobs", refs(missing...))
				x.set("next", textV("install the bytes: commons repair "+e.Op+" --blob <file> (the file whose bytes hash to "+strings.Join(missing, ", ")+
					"), or commons fetch "+strings.Join(missing, " ")+" from a hold and then commons repair "+e.Op))
			} else {
				x.set("next", textV("fix the cause in detail, then run commons repair "+e.Op))
			}
		case "replay failed":
			code = ExitCouldNot
			x.set("next", textV(replayFailedNext))
		case "replayed", "projected":
			finished++
		}
		if e.Detail != "" {
			// a store error may quote stored bytes
			x.set("detail", peerV(e.Detail))
		}
		rows = append(rows, x)
	}
	o.set("repaired", rows)
	// what this command's open of the store already finished, before repair ran (status prints the same list)
	rec := listV{}
	for _, e := range c.Store.Recovered {
		x := rowObj().set("what", tokV(tok(e.What)))
		if e.Op != "" {
			x.set("operation", refV(e.Op))
		}
		if e.Kind != "" {
			x.set("kind", textV(e.Kind))
		}
		rec = append(rec, x)
	}
	o.set("recovered_on_open", rec)

	// step 5's projections: rebuild every registered one cold, then compare each with a second cold build; a
	// difference is drift (a bug in the projection: its build is not a function of blobs and statements)
	cache := store.NewCache(c.Store)
	for _, pr := range projections {
		if err := cache.Register(pr); err != nil {
			return nil, 0, failed(err, "cache", false, "report the bug")
		}
	}
	rb, err := cache.Rebuild()
	if err != nil {
		return nil, 0, failed(err, "cache", false, "run commons fsck; if it recurs, report the bug")
	}
	drift, err := cache.Drift()
	if err != nil {
		return nil, 0, failed(err, "cache", false, "run commons fsck; if it recurs, report the bug")
	}
	pj := newObj().set("rebuilt", intV(int64(len(rb))))
	if len(cache.Registered()) == 0 {
		pj.set("note", textV("this version registers no projection: every read resolves from the installed statements"))
	}
	if len(drift) > 0 {
		dl := listV{}
		for _, d := range drift {
			dl = append(dl, rowObj().set("projection", textV(d.Name)).set("key", refV(d.Key)).set("warm", refV(string(d.Warm))).set("cold", refV(string(d.Cold))))
		}
		pj.set("drift", dl)
		if code == ExitOK {
			code = ExitWrong
		}
	}
	o.set("projections", pj)

	n, err := c.Store.QuarantineCount()
	if err != nil {
		return nil, 0, failed(err, "store", false, "run commons fsck")
	}
	q := "nothing under quarantine/"
	if n > 0 {
		q = fmt.Sprintf("%d item(s) under quarantine/ (moved aside, never deleted); repair does not touch them; inspect them with commons fsck", n)
	}
	o.set("quarantine", textV(q))

	recs, err := c.Store.Status()
	if err != nil {
		return nil, 0, failed(err, "store", false, "run commons fsck")
	}
	state := "nothing pending"
	for _, r := range recs {
		if r.What == "committed, needs repair" || state == "nothing pending" {
			state = r.What
		}
	}
	o.set("store_state", tokV(tok(state)))
	if finished > 0 {
		effects = append(effects, fmt.Sprintf("finished %d journal record(s)", finished))
	}
	if len(rb) > 0 {
		effects = append(effects, fmt.Sprintf("rebuilt %d projection(s) under cache/", len(rb)))
	}
	effects = append(effects, "no statement signed, rewritten or deleted; nothing rolled back; quarantine/ untouched")
	o.set("side_effects", textV(strings.Join(effects, "; ")))
	return o, code, nil
}
