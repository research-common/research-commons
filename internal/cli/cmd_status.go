package cli

import (
	"github.com/research-common/research-commons/internal/store"
)

// status: the store's recovery state and durability declaration (storage note §3.3, §3.5, §7). Opening the
// store already replayed the journal (§3.4); status reports what that replay did and every record still
// present: `committed, pending install` or `committed, needs repair`, each by operation id and kind
// (C-core-125).

func init() {
	Register(&Command{Name: "status", Summary: "store recovery state, unfinished operations and the durability declaration", Store: true,
		Run: statusCmd})
}

func statusCmd(c *Ctx) (*Obj, int, error) {
	recs, err := c.Store.Status()
	if err != nil {
		return nil, 0, failed(err, "store", false, "run fsck")
	}
	o := newObj().set("store", refV(c.Root)).set("layout", refV(store.Layout()))
	state := "nothing pending"
	ops := listV{}
	for _, r := range recs {
		ops = append(ops, newObj().set("operation", refV(r.Op)).set("kind", textV(r.Kind)).set("store_state", tokV(tok(r.What))))
		if r.What == "committed, needs repair" || state == "nothing pending" {
			state = r.What
		}
	}
	o.set("store_state", tokV(tok(state)))
	o.set("operations", ops)
	rec := listV{}
	for _, e := range c.Store.Recovered {
		x := newObj().set("what", tokV(tok(e.What)))
		if e.Op != "" {
			x.set("operation", refV(e.Op))
		}
		if e.Kind != "" {
			x.set("kind", textV(e.Kind))
		}
		if e.Detail != "" {
			// a decode or verify error may quote the record's bytes
			x.set("detail", peerV(e.Detail))
		}
		rec = append(rec, x)
	}
	o.set("recovered_on_open", rec)
	d := c.Store.Durability()
	o.set("durability", newObj().set("file_sync", textV(d.FileSync)).set("dir_sync", textV(d.DirSync)).
		set("rename", textV(d.Rename)).set("exclusive_create", textV(d.ExclusiveCreate)).
		set("same_filesystem", textV(d.SameFilesystem)).set("locks", textV(d.Locks)).set("gc_grace", textV(d.GCGrace)).
		set("history", textV("off")).set("assumes", textV(d.Assumes)))
	o.set("policy", newObj().set("source", textV(c.Policy.Source)).set("digest", refV(c.Policy.Digest)))
	// status succeeded; an unfinished operation is a state it reports, not a failure of status (claims §13:
	// exit 0 means the requested operation succeeded)
	return o, ExitOK, nil
}
