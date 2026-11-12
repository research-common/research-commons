package cli

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/refusal"
)

// The chain backend (bitcoin-time note §6.1, §9.1, §10): headers the reader validated, persisted in receiver-local
// state, and the two commands that manage them.
//
//   - `anchor headers sync --from <file>` is the only command that acquires headers. It reads concatenated raw
//     80-byte headers from a file the operator obtained (the note's "operator chooses sources explicitly";
//     transport is untrusted, so where the file came from grants nothing), validates every one through the
//     headers-only chain, and persists the result. No network source is built yet.
//   - `anchor status` reports the backend without changing it.
//   - Every read (show, verify, explain, list, publish's readiness) builds its time verifier from the persisted
//     view when one exists; with none, every answer is the one the tool gave before the database existed
//     (backend-unconfigured).
//
// The state directory is the one btctime.Locate resolves for the store's root: the common git directory for a
// git-backed hub, else the directory $COMMONS_STATE_DIR names (outside the store). Without either there is no
// state and no backend.

// StateDirEnv names the receiver-local state directory for a store that is not git-backed (bitcoin-time note
// §9.1). A git-backed store uses its git directory and ignores it unless set.
const StateDirEnv = "COMMONS_STATE_DIR"

// chainParams are the header rules the reader validates with. Mainnet only: the policy admits no other network as
// production evidence (§7). Tests in this package replace it with an easy-work network; nothing else can.
var chainParams = btctime.Mainnet

// chainPolicy is the reader's time policy (§7 defaults). Tests replace it to point at their network.
var chainPolicy = btctime.DefaultPolicy

func init() {
	Register(&Command{Name: "anchor headers sync", Summary: "validate Bitcoin block headers from a file and persist them as this reader's chain view", Store: true,
		Flags: []Flag{
			{Name: "from", Value: "file", Help: "concatenated raw 80-byte block headers, in chain order (required). Every header is validated; where the file came from grants nothing"},
			{Name: "bootstrap-height", Value: "n", Help: "first sync only: the first 11 headers of the file are an explicit local trust root at this height (a retarget-period start), accepted without validation; every later header is validated on top of them. Without it the chain starts at genesis",
				Check: func(v string) error {
					n, err := strconv.ParseInt(v, 10, 64)
					if err != nil || n <= 0 {
						return errors.New("a positive block height")
					}
					return nil
				}},
			{Name: "bootstrap-work", Value: "hex", Help: "with --bootstrap-height: the cumulative chainwork below the bootstrap, in hex, as the reader established it",
				Check: func(v string) error {
					if w, ok := new(big.Int).SetString(strings.TrimPrefix(v, "0x"), 16); !ok || w.Sign() < 0 {
						return errors.New("a non-negative hex number")
					}
					return nil
				}},
			{Name: "max-headers", Value: "n", Help: "read at most this many headers in this sync (default 2000000); a sync that stops at the bound keeps what validated and does not count as a completed sync",
				Check: func(v string) error {
					if n, err := strconv.ParseInt(v, 10, 64); err != nil || n <= 0 {
						return errors.New("a positive count")
					}
					return nil
				}},
		},
		Writes:  true, // it writes receiver-local state (never the store): the read sweeps skip it; its own tests cover it
		Prepare: prepareHeadersSync,
		Help: "The only command that acquires headers (bitcoin-time note §10). It reads the file, validates every header (linkage, proof of work, the exact retarget, median time past, future time against this clock, version rules) and persists the chain in this reader's state: the store's git directory, or " + StateDirEnv + " for a store that is not git-backed; never inside the store. " +
			"A header that fails validation stops the sync with its reason; what validated before it is kept, and the sync does not count as completed (the view's last-sync time does not move). Running it again with headers already held changes nothing but the last-sync time. The tool ships no checkpoint. No network source is built: obtain the file from sources you choose. " +
			"Recommended: start from a bootstrap near the tip (--bootstrap-height at a recent retarget-period start, with the chainwork below it as you established it), not from genesis. Every read command re-validates the whole persisted chain when it loads it, so its cost grows with the headers held: a few thousand headers load in milliseconds, a chain synced from genesis (close to a million headers) costs every read on the order of a second and a few hundred MB. A bootstrap is a trust root you choose: anchors below it read unknown-height. " +
			"Exit 0 the sync completed; 1 a header failed validation; 3 the sync did not complete for another reason (bounded, cancelled, no state directory, the database refused or locked); 2 did not start.",
		Run: headersSyncCmd})
	Register(&Command{Name: "anchor status", Summary: "this reader's chain backend: provider, mode, network, bootstrap, tip, last sync, freshness, receipt count", Store: true,
		Help: "Reads the persisted chain view without changing it and without contacting anything: provider, validation mode, network and genesis, bootstrap identity, tip height, hash and chainwork, header count, last successful sync, freshness under the time policy (maximum view age, maximum tip age), the policy fingerprint, and the receipt files held. Prints no secret. " +
			"Exit 0 a chain view is configured (fresh or not; freshness is a state it reports); 3 none is (no state directory, no database, or the database refused).",
		Run: anchorStatusCmd})
}

type syncPrep struct {
	from string
	boot *btctime.BootstrapSpec
	max  int64
}

func prepareHeadersSync(c *Ctx) *Problem {
	p := &syncPrep{}
	from, ok := c.Flag("from")
	if !ok || from == "" {
		return usage("missing-argument", "anchor headers sync needs --from <file>", "no network source is built; give a file of raw 80-byte headers; nothing was done", "option --from",
			"commons anchor headers sync --from <file>", "")
	}
	fi, err := os.Stat(from)
	if err != nil || !fi.Mode().IsRegular() {
		return usage("unreadable-file", "the headers file could not be read", "nothing was done", "option --from", "check the path", from)
	}
	if fi.Size()%btctime.HeaderSize != 0 {
		return usage("malformed-file", "the headers file is not a whole number of 80-byte headers", "nothing was done", "option --from",
			"give concatenated raw 80-byte headers (not hex, not JSON)", from)
	}
	p.from = from
	h, hasH := c.Flag("bootstrap-height")
	w, hasW := c.Flag("bootstrap-work")
	if hasH != hasW {
		return usage("missing-argument", "--bootstrap-height and --bootstrap-work go together", "a bootstrap names both its height and the chainwork below it; nothing was done", "invocation",
			"give both, or neither to sync from genesis", "")
	}
	if hasH {
		n, _ := strconv.ParseInt(h, 10, 64)
		work, _ := new(big.Int).SetString(strings.TrimPrefix(w, "0x"), 16)
		p.boot = &btctime.BootstrapSpec{Height: n, Work: work}
	}
	if m, ok := c.Flag("max-headers"); ok {
		p.max, _ = strconv.ParseInt(m, 10, 64)
	}
	c.Prep = p
	return nil
}

// chainState locates the receiver-local state for the store and names its header database.
func chainState(c *Ctx) (*btctime.HeaderDB, error) {
	loc, err := btctime.Locate(c.Root, c.Env.Getenv(StateDirEnv))
	if err != nil {
		return nil, err
	}
	return btctime.OpenHeaderDB(loc)
}

// syncCtx is the sync's context; tests replace it to cancel a sync.
var syncCtx = context.Background

func headersSyncCmd(c *Ctx) (*Obj, int, error) {
	p := c.Prep.(*syncPrep)
	db, err := chainState(c)
	if err != nil {
		return nil, 0, &Problem{Slug: "no-state", Title: "no receiver-local state for headers", Class: refusal.Operational, Scope: "store",
			Detail: "the store is not git-backed and " + StateDirEnv + " names no usable directory outside it; nothing was synced", Next: "set " + StateDirEnv + " to a directory outside the store",
			Peer: err.Error(), Exit: ExitCouldNot}
	}
	f, err := os.Open(p.from)
	if err != nil {
		return nil, 0, failed(err, "option --from", false, "check the file and run the command again")
	}
	defer f.Close()
	res, err := db.Sync(syncCtx(), chainParams(), f, btctime.SyncOptions{Provider: "headers-file", Bootstrap: p.boot, MaxHeaders: p.max, Now: Now})
	if err != nil {
		var re *btctime.HeaderDBError
		switch {
		case errors.As(err, &re):
			return nil, 0, &Problem{Slug: "header-database-refused", Title: "the header database is not trusted", Class: refusal.Intrinsic, Scope: "header database",
				Detail: "it is never extended or partly used; nothing was synced", Next: "move the database aside (" + db.Path() + ") and sync again from a file you choose",
				Peer: re.Reason, Exit: ExitCouldNot}
		case errors.Is(err, btctime.ErrHeaderDBLocked):
			return nil, 0, &Problem{Slug: "header-database-locked", Title: "another sync holds the header database", Class: refusal.Operational, Scope: "header database",
				Detail: "nothing was synced", Next: "wait for the other sync, then run this one again", Exit: ExitCouldNot}
		case errors.Is(err, btctime.ErrBootstrapMismatch):
			return nil, 0, usage("bootstrap-mismatch", "the header database was started from another trust root", "a sync never replaces the trust root; nothing was synced", "option --bootstrap-height",
				"drop --bootstrap-height/--bootstrap-work to extend the database, or move it aside to choose again", "")
		}
		return nil, 0, failed(err, "header database", false, "check the headers file and run the command again")
	}
	o := newObj().set("database", refV(db.Path())).set("read", intV(res.Read)).set("added", intV(res.Added)).set("already_held", intV(res.AlreadyHeld))
	o.set("completed", boolV(res.Synced))
	code := ExitOK
	switch {
	case res.Stopped != nil:
		code = ExitWrong
		var he *btctime.HeaderError
		s := newObj().set("position", intV(res.StoppedAt))
		if errors.As(res.Stopped, &he) {
			s.set("reason", textV(he.Reason))
		}
		s.set("detail", peerV(res.Stopped.Error()))
		o.set("stopped", s)
	case res.Bounded:
		code = ExitCouldNot
		o.set("stopped", newObj().set("detail", textV("--max-headers reached; run the sync again to continue")))
	case res.Cancelled:
		code = ExitCouldNot
		o.set("stopped", newObj().set("detail", textV("cancelled")))
	}
	o.set("chain", chainObj(res.View, db, chainPolicy(), Now()))
	return o, code, nil
}

// chainObj is the chain view as status and sync print it. No secret is in it: the receipt key is never read.
func chainObj(v *btctime.ChainView, db *btctime.HeaderDB, pol btctime.Policy, now time.Time) *Obj {
	o := newObj().set("provider", textV(v.Provider)).set("validation", textV(v.Mode)).
		set("network", textV(v.Network)).set("genesis", refV(v.GenesisHash))
	o.set("bootstrap", refV(v.Bootstrap)) // "genesis:<hash>" from genesis, "bootstrap:sha256:<…>" from a local trust root
	o.set("base_height", intV(v.Base)).set("tip_height", intV(v.TipHeight)).set("tip_hash", refV(v.TipHash.String())).
		set("tip_chainwork", textV("0x"+v.TipWork.Text(16))).
		set("tip_time", textV(time.Unix(int64(v.TipTime), 0).UTC().Format(time.RFC3339)+" (miner-reported)"))
	if v.Unresolved > 0 {
		o.set("unresolved_tips", intV(int64(v.Unresolved)))
	}
	if v.LastSync.IsZero() {
		o.set("last_sync", textV("never"))
	} else {
		o.set("last_sync", textV(v.LastSync.UTC().Format(time.RFC3339)))
	}
	fresh, never, why := pol.Freshness(v, now)
	switch {
	case fresh:
		o.set("freshness", textV("fresh"))
	case never:
		o.set("freshness", textV("not usable for live evidence: "+why))
	default:
		o.set("freshness", textV(fmt.Sprintf("not fresh: %s; bounds read as of the last sync (verified at %d+ confirmations, else verified-historical)", why, pol.SettledDepth)))
	}
	o.set("policy_fingerprint", refV(pol.Fingerprint()))
	if db != nil {
		o.set("state_via", textV(db.Location().Via))
	}
	return o
}

func anchorStatusCmd(c *Ctx) (*Obj, int, error) {
	o := newObj()
	db, err := chainState(c)
	if err != nil {
		o.set("configured", boolV(false)).set("detail", textV("no receiver-local state: the store is not git-backed and "+StateDirEnv+" is not set; every bound stays local (backend-unconfigured)"))
		return o, ExitCouldNot, nil
	}
	o.set("database", refV(db.Path()))
	ch, err := db.Load(chainParams(), Now())
	if n, ok := btctime.ReceiptFiles(db.Location()); ok {
		o.set("receipt_files", intV(int64(n)))
	} else {
		o.set("receipt_files", intV(0))
	}
	var re *btctime.HeaderDBError
	switch {
	case errors.Is(err, btctime.ErrNoHeaderDB):
		o.set("configured", boolV(false)).set("detail", textV("no header database: run commons anchor headers sync --from <file>; every bound stays local (backend-unconfigured)"))
		return o, ExitCouldNot, nil
	case errors.As(err, &re):
		o.set("configured", boolV(false)).set("detail", textV("the header database is present and not trusted; every bound reads backend-unavailable")).set("refused", peerV(re.Reason))
		return o, ExitCouldNot, nil
	case err != nil:
		return nil, 0, failed(err, "header database", false, "run the command again")
	}
	o.set("configured", boolV(true)).set("headers", intV(int64(ch.Len())))
	o.set("chain", chainObj(ch.Snapshot(), db, chainPolicy(), Now()))
	return o, ExitOK, nil
}

// timeVerifierFor is the read commands' time verifier: over the persisted chain view when the reader has one, with
// the §7 policy and the reader's clock. No state or no database: the verifier of newTimeVerifier, so every answer
// is byte-identical to a reader without a backend (backend-unconfigured). A database present and refused: no view,
// and every anchor reads backend-unavailable naming why (never a partial view).
//
// With a view, the verifier also reads through the receipt store in the same state (bitcoin-time note §9):
// read-write when the state directory is writable (a cold evaluation leaves a receipt for the next read),
// read-only otherwise (receipts are used, none is written, nothing is created). A receipt is a cache, never
// evidence: every answer is the one a cold evaluation gives (P-07), so a store that cannot be opened is no store.
func timeVerifierFor(c *Ctx) *btctime.Verifier {
	tv := newTimeVerifier(c.Store)
	db, err := chainState(c)
	if err != nil {
		return tv
	}
	ch, err := db.Load(chainParams(), Now())
	var re *btctime.HeaderDBError
	switch {
	case errors.As(err, &re):
		tv.Unavailable = "header database refused: " + re.Reason
		return tv
	case err != nil:
		return tv
	}
	tv.Policy, tv.View, tv.Now = chainPolicy(), ch.Snapshot(), Now
	tv.Receipts = readReceipts(db.Location())
	return tv
}

// readReceipts is how a read opens the receipt store; tests replace it to read with none (every proof cold) or to
// observe the store a read used.
var readReceipts = receiptsFor

// receiptsFor opens the receipt store for a read: read-write when the state is writable, else (or when that open
// fails) read-only; nil when there is no store to read, so every proof is read cold.
func receiptsFor(loc btctime.Location) *btctime.Receipts {
	if btctime.StateWritable(loc) {
		if r, err := btctime.OpenReceipts(loc, btctime.ReceiptOptions{}); err == nil {
			return r
		}
	}
	if r, err := btctime.OpenReceipts(loc, btctime.ReceiptOptions{ReadOnly: true}); err == nil {
		return r
	}
	return nil
}

// chainContext is explain's time context when a chain view answers: the view the bounds were read against and the
// clock that decided freshness.
func chainContext(tv *btctime.Verifier) string {
	v := tv.View
	now := tv.Now()
	fresh, _, why := tv.Policy.Freshness(v, now)
	state := "fresh"
	if !fresh {
		state = "not fresh (" + why + ")"
	}
	return fmt.Sprintf("read time %s: anchors are evaluated against this reader's %s chain view (%s, tip %d, last sync %s), %s",
		now.UTC().Format(time.RFC3339), v.Mode, v.Network, v.TipHeight, syncText(v.LastSync), state)
}

func syncText(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}
