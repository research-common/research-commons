package btctime

// The receipt store (bitcoin-time note §9). A receipt records, for one anchors statement, the immutable binding a
// verification found (this proof's bytes select a Bitcoin attestation whose calculated digest is the Merkle root
// of this header) together with everything that binding was computed under. It is a cache, never evidence:
//
//   - every read re-runs §4 checks 3–5 and hashes the proof bytes it holds (check 1 of §9.3) before a receipt is
//     even looked up, so changed bytes are caught whatever their size or modification time;
//   - a receipt is used only when its hub, verifier, policy, network and provider identities equal this read's
//     (check 2), the chain view is ready (check 3), the recorded header is still the active one at its height
//     (check 4), and the chain has only been extended since the receipt was written (check 5: the tip recorded
//     at verification is still on the accepted chain, so no reorganisation has happened that could change which
//     attestation is selected). Confirmations and freshness (§7, §9.4) are then applied to the current view
//     exactly as a cold evaluation applies them;
//   - anything else (no receipt, a corrupt, truncated, copied, foreign-hub or unknown-version file, a mismatched
//     identity, a reorganisation) means the receipt is not used: the read evaluates the proof cold and, unless
//     the store is read-only, replaces the receipt. A receipt never decides a verdict the cold evaluation would
//     not give: with or without receipts, the answer is the same (P-07).
//
// Files live under <state dir>/receipts-v1 (Locate): mode 0700 directories, 0600 files, one file per anchors
// statement named by its id, written to a temporary, synced and renamed into place under a lock file. A per-
// store random key authenticates every receipt (HMAC-SHA256): a receipt copied from another reader's or another
// hub's state, or written by anything but this store, fails it and is inert. The key is not a signing key and
// signs nothing anyone else reads; verifying needs no key of the reader's own (§9.1).

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// ReceiptVersion is the receipt format this store writes and the only one it reads.
const ReceiptVersion = 1

const (
	receiptsDir   = "receipts-v1"
	maxReceipt    = 64 << 10
	tmpGraceAge   = time.Hour
	defaultStale  = 30 * time.Second
	keyFileName   = "key"
	lockFileName  = "lock"
	receiptSubdir = "r"
)

// Crash points of a receipt write, in order (tests inject a crash at each).
const (
	CrashPartialTemp = "receipt-partial-temp" // half the bytes written to the temporary
	CrashTempWritten = "receipt-temp-written" // all bytes written, not yet synced
	CrashTempSynced  = "receipt-temp-synced"  // synced, not yet renamed into place
	CrashRenamed     = "receipt-renamed"      // renamed into place, directory not yet synced
	CrashDirSynced   = "receipt-dir-synced"   // durable, lock not yet released
)

// ErrReceiptCrash is what a test crash hook returns to abort a write where it stands.
var ErrReceiptCrash = errors.New("injected crash")

var reAnchorID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ReceiptOptions configure a receipt store.
type ReceiptOptions struct {
	// ReadOnly reads receipts but never writes one (a read-only status read). Default: a re-check replaces the
	// receipt it re-checked.
	ReadOnly bool
	// NoSync skips fsync (tests that do not exercise power loss).
	NoSync bool
	// LockStale is how old a lock file must be before a writer breaks it (a writer that crashed holding it).
	// Zero means 30 s. A writer that finds a live lock skips its write; a cache write is never required.
	LockStale time.Duration
	// crash, when set, is called at each crash point and may abort the write there (tests only).
	crash func(point string) error
}

// Receipts is an open receipt store. It is safe for concurrent use.
type Receipts struct {
	loc Location
	dir string
	key []byte
	opt ReceiptOptions

	mu    sync.Mutex
	stats ReceiptStats
}

// ReceiptStats counts what reads did with receipts.
type ReceiptStats struct {
	// Used: reads answered from a receipt after every §9.3 check. Cold: reads that evaluated the proof.
	Used, Cold int
	// Written: receipts written. Skipped: writes skipped (read-only, lock held, write error).
	Written, Skipped int
	// Downgraded: receipt files present but not trusted (corrupt, copied, foreign, unknown version, mode).
	Downgraded int
}

// ReceiptUse says what one read did with the receipt for its anchor.
type ReceiptUse struct {
	// Used is true when the answer came from the receipt (all §9.3 checks held).
	Used bool
	// Why names why the receipt was not used: "no receipt", "corrupt: …", "copied or forged: …",
	// "foreign hub: …", "unknown version …", "policy changed", "provider changed", "chain reorganised …", ….
	Why string
	// Downgraded is true when a receipt file was present but could not be trusted at all.
	Downgraded bool
	// Written is true when the read replaced the receipt after its cold evaluation.
	Written bool
}

// OpenReceipts opens (creating if needed) the receipt store at loc. Leftover temporaries older than an hour are
// removed; a missing key is created (link-exclusive, so two openers agree on one); a malformed key is replaced,
// which leaves every existing receipt inert.
func OpenReceipts(loc Location, opt ReceiptOptions) (*Receipts, error) {
	if loc.Dir == "" || loc.Hub == "" {
		return nil, ErrNoState
	}
	r := &Receipts{loc: loc, dir: filepath.Join(loc.Dir, receiptsDir), opt: opt}
	for _, d := range []string{loc.Dir, r.dir, r.path(receiptSubdir), r.path("tmp")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return nil, err
		}
	}
	if err := r.sweepTmp(time.Now()); err != nil {
		return nil, err
	}
	key, err := r.loadKey()
	if err != nil {
		return nil, err
	}
	r.key = key
	return r, nil
}

// Location is where this store lives and the hub identity its receipts bind.
func (r *Receipts) Location() Location { return r.loc }

// Stats returns the counts so far.
func (r *Receipts) Stats() ReceiptStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

func (r *Receipts) path(parts ...string) string {
	return filepath.Join(append([]string{r.dir}, parts...)...)
}

func (r *Receipts) hook(point string) error {
	if r.opt.crash != nil {
		return r.opt.crash(point)
	}
	return nil
}

func (r *Receipts) count(f func(*ReceiptStats)) {
	r.mu.Lock()
	f(&r.stats)
	r.mu.Unlock()
}

func (r *Receipts) sweepTmp(now time.Time) error {
	ents, err := os.ReadDir(r.path("tmp"))
	if err != nil {
		return err
	}
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(fi.ModTime()) > tmpGraceAge {
			_ = os.Remove(r.path("tmp", e.Name()))
		}
	}
	return nil
}

func (r *Receipts) loadKey() ([]byte, error) {
	p := r.path(keyFileName)
	for try := 0; try < 3; try++ {
		b, err := os.ReadFile(p)
		if err == nil {
			if k, err := hex.DecodeString(string(bytes.TrimSpace(b))); err == nil && len(k) == 32 {
				if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
					_ = os.Chmod(p, 0o600)
				}
				return k, nil
			}
			// malformed: replace it; every receipt authenticated by the old key becomes inert
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		tmp, err := r.writeTemp([]byte(hex.EncodeToString(k)+"\n"), false)
		if err != nil {
			return nil, err
		}
		err = os.Link(tmp, p)
		_ = os.Remove(tmp)
		if err == nil {
			_ = r.syncDir(r.dir)
			return k, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		// another opener won the race: read theirs
	}
	return nil, errors.New("receipt store key could not be created or read")
}

func (r *Receipts) syncDir(d string) error {
	if r.opt.NoSync {
		return nil
	}
	f, err := os.Open(d)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// writeTemp writes b to a new 0600 temporary under tmp/ and returns its path. With crash points it may stop
// part-way, leaving the temporary behind as a crashed process would.
func (r *Receipts) writeTemp(b []byte, hooks bool) (string, error) {
	f, err := os.CreateTemp(r.path("tmp"), "w-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(name)
		return "", err
	}
	if hooks {
		if _, err := f.Write(b[:len(b)/2]); err != nil {
			f.Close()
			return "", err
		}
		if err := r.hook(CrashPartialTemp); err != nil {
			f.Close()
			return "", err
		}
		b = b[len(b)/2:]
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(name)
		return "", err
	}
	if hooks {
		if err := r.hook(CrashTempWritten); err != nil {
			f.Close()
			return "", err
		}
	}
	if !r.opt.NoSync {
		if err := f.Sync(); err != nil {
			f.Close()
			os.Remove(name)
			return "", err
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	if hooks {
		if err := r.hook(CrashTempSynced); err != nil {
			return "", err
		}
	}
	return name, nil
}

var errLocked = errors.New("receipt store locked by another writer")

// lock takes the store's write lock (a file created exclusively). A lock older than LockStale is a crashed
// writer's and is broken.
func (r *Receipts) lock(now time.Time) error {
	p := r.path(lockFileName)
	stale := r.opt.LockStale
	if stale == 0 {
		stale = defaultStale
	}
	for try := 0; try < 2; try++ {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d %s\n", os.Getpid(), now.UTC().Format(time.RFC3339Nano))
			return f.Close()
		}
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
		fi, err := os.Stat(p)
		if err != nil {
			continue // released meanwhile
		}
		if now.Sub(fi.ModTime()) <= stale {
			return errLocked
		}
		_ = os.Remove(p)
	}
	return errLocked
}

func (r *Receipts) unlock() { _ = os.Remove(r.path(lockFileName)) }

// receipt is one stored receipt (note §9.2).
type receipt struct {
	Version int64
	Hub     string
	// the anchors statement: id, signer, a content hash of its full line, the covered head
	Anchor, Signer, AnchorLine, Covered string
	// the proof blob hash and the stamped digest (hex of the raw covered bytes)
	Proof, Stamped string
	// network, genesis
	Network, Genesis string
	// the bound block: height, display hash, a content hash of the raw 80 bytes, the calculated digest (hex)
	Height                          int64
	BlockHash, HeaderDigest, Digest string
	// provider, bootstrap identity and validation mode
	Provider, Bootstrap, Mode string
	// verifier version and policy fingerprint
	Verifier, Policy string
	// chain snapshot at verification: tip height and hash, epoch, last sync
	TipHeight     int64
	TipHash       string
	Epoch         int64
	LastSync      string
	VerifiedAt    string
	StateAtVerify string
	Notes         []string
}

func (rc *receipt) object() *canon.Object {
	notes := canon.Array{}
	for _, n := range rc.Notes {
		notes = append(notes, canon.String(n))
	}
	m := map[string]canon.Value{
		"v": canon.Int(rc.Version), "hub": canon.String(rc.Hub),
		"anchor": canon.String(rc.Anchor), "signer": canon.String(rc.Signer), "anchor_line": canon.String(rc.AnchorLine),
		"covered": canon.String(rc.Covered), "proof": canon.String(rc.Proof), "stamped": canon.String(rc.Stamped),
		"network": canon.String(rc.Network), "genesis": canon.String(rc.Genesis),
		"height": canon.String(strconv.FormatInt(rc.Height, 10)), "block_hash": canon.String(rc.BlockHash),
		"header_digest": canon.String(rc.HeaderDigest), "digest": canon.String(rc.Digest),
		"provider": canon.String(rc.Provider), "bootstrap": canon.String(rc.Bootstrap), "mode": canon.String(rc.Mode),
		"verifier": canon.String(rc.Verifier), "policy": canon.String(rc.Policy),
		"tip_height": canon.String(strconv.FormatInt(rc.TipHeight, 10)), "tip_hash": canon.String(rc.TipHash),
		"epoch": canon.String(strconv.FormatInt(rc.Epoch, 10)), "last_sync": canon.String(rc.LastSync),
		"verified_at": canon.String(rc.VerifiedAt), "state": canon.String(rc.StateAtVerify), "notes": notes,
	}
	o := &canon.Object{Members: m}
	for k := range m {
		o.Keys = append(o.Keys, k)
	}
	o.Keys = canon.SortedKeys(o)
	return o
}

// encode is the receipt's canonical bytes with its MAC.
func (r *Receipts) encode(rc *receipt) []byte {
	o := rc.object()
	o.Keys = append(o.Keys, "mac")
	o.Members["mac"] = canon.String(r.mac(canon.Encode(rc.object())))
	return append(canon.Encode(o), '\n')
}

func (r *Receipts) mac(b []byte) string {
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte("research-commons receipt v1\n"))
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}

// decode reads a stored receipt. Every failure is a reason the file is not trusted.
func (r *Receipts) decode(b []byte) (*receipt, string) {
	v, err := canon.Parse(bytes.TrimSuffix(b, []byte("\n")))
	if err != nil {
		return nil, "corrupt: " + err.Error()
	}
	o, ok := v.(*canon.Object)
	if !ok {
		return nil, "corrupt: not an object"
	}
	if ver, ok := o.Members["v"].(canon.Int); !ok || int64(ver) != ReceiptVersion {
		return nil, fmt.Sprintf("unknown version %v (this store reads version %d only)", o.Members["v"], ReceiptVersion)
	}
	mac, ok := o.Members["mac"].(canon.String)
	if !ok {
		return nil, "corrupt: no mac"
	}
	str := func(k string) string { s, _ := o.Members[k].(canon.String); return string(s) }
	num := func(k string) (int64, bool) { n, err := strconv.ParseInt(str(k), 10, 64); return n, err == nil }
	rc := &receipt{Version: ReceiptVersion, Hub: str("hub"), Anchor: str("anchor"), Signer: str("signer"), AnchorLine: str("anchor_line"),
		Covered: str("covered"), Proof: str("proof"), Stamped: str("stamped"), Network: str("network"), Genesis: str("genesis"),
		BlockHash: str("block_hash"), HeaderDigest: str("header_digest"), Digest: str("digest"),
		Provider: str("provider"), Bootstrap: str("bootstrap"), Mode: str("mode"), Verifier: str("verifier"), Policy: str("policy"),
		TipHash: str("tip_hash"), LastSync: str("last_sync"), VerifiedAt: str("verified_at"), StateAtVerify: str("state")}
	var ok1, ok2, ok3 bool
	rc.Height, ok1 = num("height")
	rc.TipHeight, ok2 = num("tip_height")
	rc.Epoch, ok3 = num("epoch")
	if !ok1 || !ok2 || !ok3 {
		return nil, "corrupt: malformed number"
	}
	if ns, ok := o.Members["notes"].(canon.Array); ok {
		for _, n := range ns {
			s, ok := n.(canon.String)
			if !ok {
				return nil, "corrupt: malformed notes"
			}
			rc.Notes = append(rc.Notes, string(s))
		}
	} else {
		return nil, "corrupt: no notes"
	}
	// exactly the members this version writes: anything else is not a receipt this store wrote
	if len(o.Members) != len(rc.object().Members)+1 {
		return nil, "corrupt: unexpected members"
	}
	if !hmac.Equal([]byte(r.mac(canon.Encode(rc.object()))), []byte(string(mac))) {
		return nil, "copied or forged: the receipt is not authenticated by this store's key"
	}
	return rc, ""
}

// read loads the receipt for anchor id. A missing file is ("", nil-ish) with why "no receipt" and downgraded
// false; any other failure is downgraded.
func (r *Receipts) read(id string) (*receipt, string, bool) {
	if !reAnchorID.MatchString(id) {
		return nil, "no receipt (not a statement id)", false
	}
	p := r.path(receiptSubdir, id)
	if li, err := os.Lstat(p); err == nil && !li.Mode().IsRegular() {
		return nil, "not a regular file (a symlink or other entry is never followed)", true
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "no receipt", false
	}
	if err != nil {
		return nil, "unreadable: " + err.Error(), true
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, "unreadable: " + err.Error(), true
	}
	if !fi.Mode().IsRegular() {
		return nil, "not a regular file", true
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Sprintf("permissions %04o are not owner-only", fi.Mode().Perm()), true
	}
	b, err := io.ReadAll(io.LimitReader(f, maxReceipt+1))
	if err != nil {
		return nil, "unreadable: " + err.Error(), true
	}
	if len(b) > maxReceipt {
		return nil, "corrupt: over the size limit", true
	}
	rc, why := r.decode(b)
	if rc == nil {
		return nil, why, true
	}
	if rc.Hub != r.loc.Hub {
		return nil, fmt.Sprintf("foreign hub: written for %s, read under %s", rc.Hub, r.loc.Hub), true
	}
	if rc.Anchor != id {
		return nil, "corrupt: names another anchors statement", true
	}
	return rc, "", false
}

// put writes rc atomically under the lock. A crash at any point leaves either the previous receipt (or none) or
// the complete new one in place, never a partial file under its name.
func (r *Receipts) put(rc *receipt) (err error) {
	if !reAnchorID.MatchString(rc.Anchor) {
		return fmt.Errorf("anchor id %q is not a statement id", rc.Anchor)
	}
	if err := r.lock(time.Now()); err != nil {
		return err
	}
	crashed := false
	defer func() {
		if !crashed {
			r.unlock()
		}
	}()
	b := r.encode(rc)
	tmp, err := r.writeTemp(b, true)
	if errors.Is(err, ErrReceiptCrash) {
		crashed = true
		return err
	}
	if err != nil {
		return err
	}
	dst := r.path(receiptSubdir, rc.Anchor)
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := r.hook(CrashRenamed); err != nil {
		crashed = true
		return err
	}
	if err := r.syncDir(filepath.Dir(dst)); err != nil {
		return err
	}
	if err := r.hook(CrashDirSynced); err != nil {
		crashed = true
		return err
	}
	return nil
}

func idMatches(a *wire.Statement) bool {
	h := sha256.Sum256(a.SignedString)
	return hex.EncodeToString(h[:]) == a.ID
}

// lineDigest is a content hash of the statement's whole line, signature included (the id covers the signed
// string only).
func lineDigest(a *wire.Statement) string {
	h := sha256.Sum256(a.Line())
	return "sha256:" + hex.EncodeToString(h[:])
}

func headerDigest(h Header) string {
	d := sha256.Sum256(h.Raw[:])
	return "sha256:" + hex.EncodeToString(d[:])
}

func timeText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func (r *Receipts) evaluate(v *Verifier, a *wire.Statement) Evidence {
	e, _ := r.Evaluate(v, a)
	return e
}

// Evaluate answers one anchors statement for v, using the stored receipt when every check of §9.3 holds and
// evaluating the proof cold otherwise. The evidence is the same either way; ReceiptUse says which path ran.
func (r *Receipts) Evaluate(v *Verifier, a *wire.Statement) (Evidence, ReceiptUse) {
	e, held, done := v.anchorChecks(a) // §4 checks 3–5; §9.3 check 1 for the proof blob (read once, hashed)
	if done {
		r.count(func(s *ReceiptStats) { s.Cold++ })
		return e, ReceiptUse{Why: "the anchor did not pass its binding checks: " + string(e.State)}
	}
	use := ReceiptUse{}
	if !idMatches(a) {
		// a statement whose id is not the hash of its signed bytes is never looked up or recorded under that id
		r.count(func(s *ReceiptStats) { s.Cold++ })
		e, _ = v.proofBound(e, held.bytes, held.covered)
		return e, ReceiptUse{Why: "statement id does not match its signed bytes; no receipt read or written"}
	}
	rc, why, down := r.read(a.ID)
	if rc != nil {
		if ev, ok, why2 := r.eligible(v, a, e, held, rc); ok {
			r.count(func(s *ReceiptStats) { s.Used++ })
			return ev, ReceiptUse{Used: true}
		} else {
			why = why2
		}
	}
	use.Why, use.Downgraded = why, down
	cold, bd := v.proofBound(e, held.bytes, held.covered)
	r.count(func(s *ReceiptStats) {
		s.Cold++
		if down {
			s.Downgraded++
		}
	})
	if bd == nil {
		return cold, use
	}
	if r.opt.ReadOnly {
		r.count(func(s *ReceiptStats) { s.Skipped++ })
		return cold, use
	}
	view := v.View
	nrc := &receipt{Version: ReceiptVersion, Hub: r.loc.Hub, Anchor: a.ID, Signer: a.Signer, AnchorLine: lineDigest(a),
		Covered: cold.Covered, Proof: held.digest, Stamped: hex.EncodeToString(held.covered),
		Network: view.Network, Genesis: view.GenesisHash,
		Height: bd.height, BlockHash: bd.header.Hash.String(), HeaderDigest: headerDigest(bd.header), Digest: hex.EncodeToString(bd.digest),
		Provider: view.Provider, Bootstrap: view.Bootstrap, Mode: view.Mode,
		Verifier: VerifierVersion, Policy: v.Policy.Fingerprint(),
		TipHeight: view.TipHeight, TipHash: view.TipHash.String(), Epoch: int64(view.Epoch & (1<<62 - 1)),
		LastSync: timeText(view.LastSync), VerifiedAt: timeText(cold.VerifiedAt), StateAtVerify: string(cold.State),
		Notes: append([]string{}, bd.notes...)}
	if err := r.put(nrc); err != nil {
		r.count(func(s *ReceiptStats) { s.Skipped++ })
		return cold, use
	}
	r.count(func(s *ReceiptStats) { s.Written++ })
	use.Written = true
	return cold, use
}

// eligible runs §9.3 checks 1–5 for a stored receipt against this read, and on success applies the mutable
// half of the verdict (confirmations, freshness) to the current view.
func (r *Receipts) eligible(v *Verifier, a *wire.Statement, e Evidence, held heldProof, rc *receipt) (Evidence, bool, string) {
	// 1. the anchors statement and the proof blob still hash as recorded (the blob was hashed by anchorChecks)
	switch {
	case rc.Anchor != a.ID || rc.Signer != a.Signer || rc.AnchorLine != lineDigest(a) || rc.Covered != e.Covered:
		return e, false, "anchors statement bytes changed since the receipt"
	case rc.Proof != held.digest || rc.Stamped != hex.EncodeToString(held.covered):
		return e, false, "proof bytes changed since the receipt"
	}
	// 2. verifier, provider and policy identities
	view := v.View
	switch {
	case rc.Verifier != VerifierVersion:
		return e, false, fmt.Sprintf("verifier changed (%s, now %s)", rc.Verifier, VerifierVersion)
	case rc.Policy != v.Policy.Fingerprint():
		return e, false, "policy changed since the receipt"
	case view == nil:
		return e, false, "no chain view"
	case rc.Network != view.Network || rc.Genesis != view.GenesisHash:
		return e, false, fmt.Sprintf("network changed (%s, now %s)", rc.Network, view.Network)
	case rc.Provider != view.Provider || rc.Bootstrap != view.Bootstrap || rc.Mode != view.Mode:
		return e, false, "provider changed since the receipt"
	}
	// 3. the view is ready (backend, network under policy, chainwork floor); freshness is applied below
	e, ok := v.ready(e)
	if !ok {
		return e, false, "chain view not ready: " + string(e.State)
	}
	// 5. no reorganisation since the receipt: the tip it was verified under is still on the accepted chain, so the
	// active chain up to it is the one the selection was made on (a reorg or a rollback re-selects, cold)
	tip, err := ParseDisplayHash(rc.TipHash)
	if err != nil || !view.IsActive(tip, rc.TipHeight) {
		return e, false, "chain reorganised or rolled back since the receipt (its tip is no longer on the accepted chain)"
	}
	// 4. the recorded header is still the active one at its height, and binds the recorded digest
	h, ok := view.HeaderAt(rc.Height)
	digest, err := hex.DecodeString(rc.Digest)
	if !ok || err != nil || h.Hash.String() != rc.BlockHash || headerDigest(h) != rc.HeaderDigest || !bytes.Equal(h.MerkleRoot[:], digest) {
		return e, false, "recorded block is not active at its height"
	}
	bd := &binding{height: rc.Height, header: h, digest: digest, notes: append([]string(nil), rc.Notes...)}
	e.Notes = append([]string(nil), bd.notes...) // nil when none, as the cold path leaves it
	return v.eligible(e, bd), true, ""
}
