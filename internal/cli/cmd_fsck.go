package cli

import (
	"errors"
	"slices"

	"github.com/research-common/research-commons/internal/store"
)

// fsck: the store's consistency check (storage note §5.3, §7) through store.Fsck: every blob re-hashed, every
// statement re-read, every reference resolved, the journal and the projection cache checked; read-only except
// for --rebuild, which drops and recomputes the named projection. Findings are fatal (a reader would get a
// wrong or missing answer: exit 1, "checked and wrong") or housekeeping (reported, exit 0).

// projections are the projections this binary registers on the store's cache. None yet: every read command
// resolves from installed statements directly, so --rebuild names nothing that exists and exits 2.
var projections = []store.Projection{}

func init() {
	Register(&Command{Name: "fsck", Summary: "check the store: blobs re-hashed, statements re-read, references resolved, journal and cache checked",
		Flags: []Flag{{Name: "rebuild", Value: "projection", Help: "drop and recompute this registered projection cold (none is registered by this version)",
			Check: func(v string) error {
				if v == "" {
					return errors.New("a projection name")
				}
				return nil
			}}},
		Store: true, Before: fsckBefore,
		Help: "Exit 0 no fatal finding (housekeeping findings are listed), 1 a fatal finding (corruption, an invalid statement, an unresolved reference a record promised, drift), 2 did not start (an unknown projection), 3 the check failed after it started.",
		Run:  fsckCmd})
}

func fsckBefore(c *Ctx) *Problem {
	name, ok := c.Flag("rebuild")
	if !ok {
		return nil
	}
	if !slices.ContainsFunc(projections, func(p store.Projection) bool { return p.Name == name }) {
		return usage("unknown-projection", "no such projection", "this version registers no projection by that name; nothing was done",
			"option --rebuild", "run fsck without --rebuild", name)
	}
	return nil
}

func fsckCmd(c *Ctx) (*Obj, int, error) {
	cache := store.NewCache(c.Store)
	for _, p := range projections {
		if err := cache.Register(p); err != nil {
			return nil, 0, failed(err, "cache", false, "report the bug")
		}
	}
	opt := store.FsckOptions{Cache: cache}
	if n, ok := c.Flag("rebuild"); ok {
		opt.Rebuild = []string{n}
	}
	rep, err := c.Store.Fsck(opt)
	if err != nil {
		return nil, 0, failed(err, "store", false, "run fsck again; if it recurs, check the filesystem")
	}
	o := newObj().set("scanned", newObj().set("blobs", intV(int64(rep.Blobs))).set("statements", intV(int64(rep.Statements))).
		set("journal_records", intV(int64(rep.Records))))
	fs := listV{}
	for _, f := range rep.Findings {
		fs = append(fs, rowObj().set("finding", textV(f.Class)).set("object", peerV(f.Object)).set("fatal", boolV(f.Fatal)).set("detail", peerV(f.Detail)))
	}
	o.set("findings", fs)
	if len(rep.Rebuilt) > 0 {
		rb := listV{}
		for _, r := range rep.Rebuilt {
			rb = append(rb, rowObj().set("projection", textV(r.Name)).set("key", refV(r.Key)).set("size", intV(int64(r.Bytes))))
		}
		o.set("rebuilt", rb)
	}
	o.set("clean", boolV(rep.Clean()))
	se := "no registry change; nothing moved or deleted"
	if len(rep.Rebuilt) > 0 {
		se = "rebuilt the named projection under cache/; no registry change"
	}
	o.set("side_effects", textV(se))
	if !rep.Clean() {
		return o, ExitWrong, nil
	}
	return o, ExitOK, nil
}
