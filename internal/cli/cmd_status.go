package cli

import (
	"slices"

	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// status: the store's recovery state and durability declaration (storage note §3.3, §3.5, §7). Opening the
// store already replayed the journal (§3.4); status reports what that replay did and every record still
// present: `committed, pending install` or `committed, needs repair`, each by operation id and kind
// (C-core-125).

func init() {
	Register(&Command{Name: "status", Summary: "store recovery state, unfinished operations and the durability declaration", Store: true, ReaderPolicy: true,
		Flags: []Flag{{Name: "limits", Help: "also print every limit this tool applies: name, value, where the value comes from and what it bounds"}},
		Run:   statusCmd})
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
	o.set("policy", newObj().set("source", textV(c.Policy.Source)).set("digest", refV(c.Policy.Digest)).set("reader_policy", c.Policy.readerObj()))
	o.set("key", keyStatus(c))
	if _, ok := c.Flag("limits"); ok {
		o.set("limits", limitsTable(c.Policy))
	}
	// status succeeded; an unfinished operation is a state it reports, not a failure of status (claims §13:
	// exit 0 means the requested operation succeeded)
	return o, ExitOK, nil
}

// limitsTable is the one table of limits (storage note §8: every limit has a name and a value, read from the
// reader's policy and printed with a refusal): the gate's limits as the hub policy sets them, the scan limits,
// the fetch bound, the gc grace window, and the format's and the policy reader's fixed bounds.
func limitsTable(p *Policy) listV {
	row := func(name string, v int64, unit, source, bounds string) value {
		return rowObj().set("name", textV(name)).set("value", intV(v)).set("unit", textV(unit)).set("source", textV(source)).set("bounds", textV(bounds))
	}
	var l listV
	names := make([]string, 0, len(gate.DefaultLimits))
	for k := range gate.DefaultLimits {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, k := range names {
		src := "tool default"
		if p.Hub.Limits[k] != gate.DefaultLimits[k] {
			src = PolicyFile
		}
		what := map[string]string{gate.LimitBlobBytes: "one blob in a package (pull, hub check)", gate.LimitStatementBytes: "one statement file in a package (pull, hub check)"}[k]
		l = append(l, row(k, p.Hub.Limits[k], "bytes", src, what))
	}
	sl := store.DefaultLimits()
	for _, r := range []struct {
		n    string
		v    int64
		unit string
		what string
	}{
		{store.LimitMemberBytes, sl.MemberBytes, "bytes", "one archive member read by a scan"},
		{store.LimitTotalBytes, sl.TotalBytes, "bytes", "all members read in one scan"},
		{store.LimitMembers, int64(sl.Members), "count", "members listed in one archive"},
		{store.LimitDepth, int64(sl.Depth), "levels", "archive nesting examined"},
		{store.LimitPathBytes, int64(sl.PathBytes), "bytes", "one member name"},
		{store.LimitRatio, sl.ExpansionRatio, "ratio", "uncompressed bytes per compressed byte"},
	} {
		l = append(l, row("scan."+r.n, r.v, r.unit, "tool default", r.what))
	}
	l = append(l,
		row("fetch_bytes", store.DefaultMaxFetchBytes, "bytes", "tool default", "a fetch with no declared size"),
		row("gc_grace", int64(store.DefaultGrace.Seconds()), "seconds", "tool default", "how long an unreferenced blob is kept after install or reuse (gc --grace overrides for one run)"),
		row("gc_grace_floor", int64(store.MinGrace.Seconds()), "seconds", "tool default", "the least policy grace window; below it the window must be given for one run"),
		row("wire.line_bytes", wire.MaxLine, "bytes", "format", "one statement line"),
		row("wire.signed_string_bytes", wire.MaxSignedString, "bytes", "format", "one signed string"),
		row("reader_policy.input_bytes", policy.MaxInput, "bytes", "tool default", "the reader policy file and the hub policy file"),
		row("reader_policy.entries", policy.MaxEntries, "count", "tool default", "selections, and trust entries, in a reader policy"),
	)
	return l
}

// keyStatus says whether a signing key is configured: $COMMONS_KEY set and loadable shows the signer and the
// algorithm; set but unusable says so (never why in key terms beyond the file's shape: loadKey's problem text
// names the file, not its content); unset says none is configured. Never key material, and never a failure of
// status: a reader that does not sign has no use for a key.
func keyStatus(c *Ctx) *Obj {
	path := c.Env.Getenv(KeyEnv)
	if path == "" {
		return newObj().set("configured", boolV(false)).set("detail", textV("no key configured; to sign, run commons key new --out <file> and give --key <file> or "+KeyEnv))
	}
	lk, prob := loadKey(path, "environment "+KeyEnv)
	if prob != nil {
		return newObj().set("configured", boolV(false)).set("source", textV("environment "+KeyEnv)).set("file", peerV(path)).
			set("detail", textV("the file named by "+KeyEnv+" cannot be used as a key ("+prob.Title+"); run commons key show <file> for the reason"))
	}
	return newObj().set("configured", boolV(true)).set("source", textV("environment "+KeyEnv)).set("signer", refV(lk.Key.Signer())).
		set("alg", textV(lk.Key.Alg()))
}
