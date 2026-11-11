package btctime

// The header database (bitcoin-time note §6.1, §9.1): the headers a reader validated, persisted in receiver-local
// state so every later read evaluates anchors against them without contacting anything (§9.4).
//
// One file, <state dir>/headers-v1/chain: a first line of canonical JSON naming the database (version, hub
// instance, network, genesis, provider, bootstrap, header count, a content hash of the header bytes, last
// successful sync), then the raw 80-byte headers. The bootstrap's own headers come first (none from genesis),
// then every other held header after its parent. It is written whole to a temporary, synced and renamed into
// place under a lock file, so a crash leaves the previous database or the new one, never a mix.
//
// A database is never trusted because it exists. Loading it re-validates every header through Chain.Add, exactly
// as a sync does; the only values taken without validation are the ones the reader chose explicitly (genesis from
// the network rules, or the bootstrap named on the first sync), and the bootstrap's content hash must equal the
// identity recorded. A file of another hub, another network or genesis, an unknown version, a header-count or
// content-hash mismatch, or a header that fails validation is refused as a whole: the reader then has no chain
// view (backend-unavailable, naming why), never a partial one.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/research-common/research-commons/internal/canon"
)

// HeaderDBVersion is the database format this package writes and the only one it reads.
const HeaderDBVersion = 1

const (
	headersDir      = "headers-v1"
	headersFile     = "chain"
	headersLock     = "lock"
	maxMetaLine     = 4 << 10
	headerLockStale = 10 * time.Minute
)

// ErrNoHeaderDB is LoadHeaderDB's answer when the state directory holds no header database.
var ErrNoHeaderDB = errors.New("no header database: no headers have been synced into this reader's state")

// ErrHeaderDBLocked is the answer when another sync holds the database's lock.
var ErrHeaderDBLocked = errors.New("header database locked by another sync")

// HeaderDBError is a database present but refused: never trusted, never partly used.
type HeaderDBError struct{ Reason string }

func (e *HeaderDBError) Error() string { return "header database refused: " + e.Reason }

func dbRefuse(f string, a ...any) error { return &HeaderDBError{Reason: fmt.Sprintf(f, a...)} }

// HeaderDB is the header database of one state location.
type HeaderDB struct {
	loc Location
	dir string
	// NoSync skips fsync (tests that do not exercise power loss).
	NoSync bool
}

// OpenHeaderDB names the database at loc. It touches nothing on disk: reads stay read-only, and a sync creates
// the directory when it writes.
func OpenHeaderDB(loc Location) (*HeaderDB, error) {
	if loc.Dir == "" || loc.Hub == "" {
		return nil, ErrNoState
	}
	return &HeaderDB{loc: loc, dir: filepath.Join(loc.Dir, headersDir)}, nil
}

// Path is the database file.
func (d *HeaderDB) Path() string { return filepath.Join(d.dir, headersFile) }

// Location is the state location the database lives in.
func (d *HeaderDB) Location() Location { return d.loc }

// Exists reports whether a database file is present (whatever its contents).
func (d *HeaderDB) Exists() bool {
	_, err := os.Lstat(d.Path())
	return err == nil
}

// dbMeta is the first line of the file.
type dbMeta struct {
	Version               int64
	Hub, Network, Genesis string
	Provider, Bootstrap   string
	BootHeight, BootCount int64
	BootWork              string // hex; "" from genesis
	Count                 int64
	Digest                string // sha256 hex of every header byte after the line
	LastSync              string // RFC 3339 nanoseconds UTC; "" never synced
}

func (m *dbMeta) object() *canon.Object {
	mm := map[string]canon.Value{
		"v": canon.Int(m.Version), "hub": canon.String(m.Hub), "network": canon.String(m.Network),
		"genesis": canon.String(m.Genesis), "provider": canon.String(m.Provider), "bootstrap": canon.String(m.Bootstrap),
		"bootstrap_height": canon.String(strconv.FormatInt(m.BootHeight, 10)),
		"bootstrap_count":  canon.String(strconv.FormatInt(m.BootCount, 10)),
		"bootstrap_work":   canon.String(m.BootWork),
		"count":            canon.String(strconv.FormatInt(m.Count, 10)),
		"headers_sha256":   canon.String(m.Digest), "last_sync": canon.String(m.LastSync),
	}
	o := &canon.Object{Members: mm}
	for k := range mm {
		o.Keys = append(o.Keys, k)
	}
	o.Keys = canon.SortedKeys(o)
	return o
}

func parseMeta(line []byte) (*dbMeta, error) {
	v, err := canon.Parse(line)
	if err != nil {
		return nil, dbRefuse("corrupt: %v", err)
	}
	o, ok := v.(*canon.Object)
	if !ok {
		return nil, dbRefuse("corrupt: the first line is not an object")
	}
	if ver, ok := o.Members["v"].(canon.Int); !ok || int64(ver) != HeaderDBVersion {
		return nil, dbRefuse("unknown version %v (this reader reads version %d only)", o.Members["v"], HeaderDBVersion)
	}
	str := func(k string) string { s, _ := o.Members[k].(canon.String); return string(s) }
	num := func(k string) (int64, bool) {
		n, err := strconv.ParseInt(str(k), 10, 64)
		return n, err == nil && n >= 0
	}
	m := &dbMeta{Version: HeaderDBVersion, Hub: str("hub"), Network: str("network"), Genesis: str("genesis"),
		Provider: str("provider"), Bootstrap: str("bootstrap"), BootWork: str("bootstrap_work"),
		Digest: str("headers_sha256"), LastSync: str("last_sync")}
	var ok1, ok2, ok3, ok4 bool
	m.BootHeight, ok1 = num("bootstrap_height")
	m.BootCount, ok2 = num("bootstrap_count")
	m.Count, ok3 = num("count")
	_, ok4 = o.Members["last_sync"].(canon.String)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, dbRefuse("corrupt: a malformed member")
	}
	if len(o.Members) != len(m.object().Members) {
		return nil, dbRefuse("corrupt: unexpected members")
	}
	return m, nil
}

// Load reads and re-validates the database for network p. now is the reader's clock: a header is re-admitted
// against the later of now and the recorded last sync, so a clock that moved back since the sync does not turn a
// header it admitted then into one too new (the clock rollback is the freshness check's to report, §7).
// ErrNoHeaderDB when there is none; a *HeaderDBError when one is present and refused.
func (d *HeaderDB) Load(p Params, now time.Time) (*Chain, error) {
	f, err := os.Open(d.Path())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoHeaderDB
	}
	if err != nil {
		return nil, dbRefuse("unreadable: %v", err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, dbRefuse("not a regular file")
	} else if fi.Mode().Perm()&0o077 != 0 {
		return nil, dbRefuse("mode %v is readable or writable by others; the database is never trusted with looser permissions than 0600", fi.Mode().Perm())
	}
	br := bufio.NewReaderSize(f, 64<<10)
	line, err := br.ReadSlice('\n')
	if err != nil || len(line) > maxMetaLine {
		return nil, dbRefuse("corrupt: no header line")
	}
	m, err := parseMeta(bytes.TrimSuffix(line, []byte("\n")))
	if err != nil {
		return nil, err
	}
	g, _ := ParseHeader(p.Genesis[:])
	switch {
	case m.Hub != d.loc.Hub:
		return nil, dbRefuse("foreign: written for hub %s, not this hub (%s)", m.Hub, d.loc.Hub)
	case m.Network != p.Network || m.Genesis != g.Hash.String():
		return nil, dbRefuse("written for network %s (genesis %s), not %s", m.Network, short(m.Genesis), p.Network)
	case m.BootCount > m.Count:
		return nil, dbRefuse("corrupt: bootstrap larger than the database")
	}
	h := sha256.New()
	read := func() ([]byte, error) {
		b := make([]byte, HeaderSize)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, dbRefuse("corrupt: truncated (%v)", err)
		}
		h.Write(b)
		return b, nil
	}
	var c *Chain
	if m.BootWork == "" {
		if m.BootCount != 0 {
			return nil, dbRefuse("corrupt: bootstrap headers without bootstrap chainwork")
		}
		if c, err = NewChain(p, m.Provider); err != nil {
			return nil, dbRefuse("genesis: %v", err)
		}
	} else {
		work, ok := new(big.Int).SetString(m.BootWork, 16)
		if !ok {
			return nil, dbRefuse("corrupt: bootstrap chainwork is not hex")
		}
		b := Bootstrap{Height: m.BootHeight, WorkBelow: work}
		for i := int64(0); i < m.BootCount; i++ {
			raw, err := read()
			if err != nil {
				return nil, err
			}
			b.Headers = append(b.Headers, raw)
		}
		if c, err = NewChainFrom(p, m.Provider, b); err != nil {
			return nil, dbRefuse("bootstrap: %v", err)
		}
	}
	if c.bootstrap != m.Bootstrap {
		return nil, dbRefuse("the bootstrap's content hash is not the identity recorded (%s)", m.Bootstrap)
	}
	var last time.Time
	if m.LastSync != "" {
		if last, err = time.Parse(time.RFC3339Nano, m.LastSync); err != nil {
			return nil, dbRefuse("corrupt: last sync %q", m.LastSync)
		}
	}
	admit := now
	if last.After(admit) {
		admit = last
	}
	for i := m.BootCount; i < m.Count; i++ {
		raw, err := read()
		if err != nil {
			return nil, err
		}
		if err := c.Add(raw, admit); err != nil {
			return nil, dbRefuse("header %d of %d does not validate: %v", i+1, m.Count, err)
		}
	}
	if n, _ := br.Read(make([]byte, 1)); n != 0 {
		return nil, dbRefuse("corrupt: trailing bytes after %d headers", m.Count)
	}
	if hex.EncodeToString(h.Sum(nil)) != m.Digest {
		return nil, dbRefuse("corrupt: the header bytes do not hash to the digest recorded")
	}
	if want := m.Count + 1 - m.BootCount; m.BootWork == "" && int64(c.Len()) != want {
		return nil, dbRefuse("corrupt: %d headers held, %d recorded (a duplicate)", c.Len(), want)
	} else if m.BootWork != "" && int64(c.Len()) != m.Count {
		return nil, dbRefuse("corrupt: %d headers held, %d recorded (a duplicate)", c.Len(), m.Count)
	}
	if !last.IsZero() {
		c.MarkSynced(last)
	}
	return c, nil
}

// lock takes the database's write lock (a file created exclusively); a lock older than headerLockStale is a crashed
// sync's and is broken.
func (d *HeaderDB) lock(now time.Time) (func(), error) {
	if err := os.MkdirAll(d.dir, 0o700); err != nil {
		return nil, err
	}
	for _, p := range []string{d.loc.Dir, d.dir} {
		if err := os.Chmod(p, 0o700); err != nil {
			return nil, err
		}
	}
	p := filepath.Join(d.dir, headersLock)
	for try := 0; try < 2; try++ {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d %s\n", os.Getpid(), now.UTC().Format(time.RFC3339Nano))
			f.Close()
			return func() { _ = os.Remove(p) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if now.Sub(fi.ModTime()) <= headerLockStale {
			return nil, ErrHeaderDBLocked
		}
		_ = os.Remove(p)
	}
	return nil, ErrHeaderDBLocked
}

// save writes the chain whole: temporary, sync, rename, directory sync. The caller holds the lock.
func (d *HeaderDB) save(c *Chain) error {
	boot, rest, lastSync := c.held()
	g, _ := ParseHeader(c.p.Genesis[:])
	m := &dbMeta{Version: HeaderDBVersion, Hub: d.loc.Hub, Network: c.p.Network, Genesis: g.Hash.String(),
		Provider: c.provider, Bootstrap: c.bootstrap}
	var body bytes.Buffer
	if boot != nil {
		m.BootHeight, m.BootCount, m.BootWork = boot.Height, int64(len(boot.Headers)), boot.WorkBelow.Text(16)
		for _, raw := range boot.Headers {
			body.Write(raw)
		}
	}
	for _, raw := range rest {
		body.Write(raw)
	}
	m.Count = int64(body.Len() / HeaderSize)
	sum := sha256.Sum256(body.Bytes())
	m.Digest = hex.EncodeToString(sum[:])
	if !lastSync.IsZero() {
		m.LastSync = lastSync.UTC().Format(time.RFC3339Nano)
	}
	tmp, err := os.CreateTemp(d.dir, "tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	w := bufio.NewWriterSize(tmp, 64<<10)
	w.Write(canon.Encode(m.object()))
	w.WriteByte('\n')
	w.Write(body.Bytes())
	if err := w.Flush(); err != nil {
		return fail(err)
	}
	if !d.NoSync {
		if err := tmp.Sync(); err != nil {
			return fail(err)
		}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, d.Path()); err != nil {
		os.Remove(name)
		return err
	}
	if d.NoSync {
		return nil
	}
	df, err := os.Open(d.dir)
	if err != nil {
		return err
	}
	defer df.Close()
	return df.Sync()
}

// SyncOptions bound one sync.
type SyncOptions struct {
	// Provider names the header source in the database and every view (first sync only; a later sync keeps the
	// recorded one).
	Provider string
	// Bootstrap, when set on the first sync, makes the first Bootstrap.Count headers of the input the explicit local
	// trust root (§6.1), at Height with WorkBelow before it. A database that exists keeps its own; naming a
	// different one is refused.
	Bootstrap *BootstrapSpec
	// MaxHeaders bounds how many headers one sync reads (0: DefaultMaxSyncHeaders).
	MaxHeaders int64
	// Now is the clock: header admission (time-too-new) and the recorded sync time.
	Now func() time.Time
}

// BootstrapSpec names a bootstrap taken from the head of a sync's input.
type BootstrapSpec struct {
	Height int64
	Work   *big.Int
	// Count is how many input headers form it (at least 11; 0 means 11).
	Count int
}

// DefaultMaxSyncHeaders bounds one sync: more than mainnet holds today, far less than a file could claim.
const DefaultMaxSyncHeaders = 2_000_000

// SyncResult is what one sync did.
type SyncResult struct {
	Read, Added, AlreadyHeld int64
	// Stopped is the header that ended the sync early (nil when every header read validated), and StoppedAt its
	// 1-based position in the input.
	Stopped   error
	StoppedAt int64
	// Cancelled is true when the context ended the sync; Bounded when MaxHeaders did.
	Cancelled, Bounded bool
	// Synced is true when the sync completed and recorded a new last-sync time.
	Synced bool
	View   *ChainView
}

// ErrBootstrapMismatch is a sync naming a bootstrap other than the database's own.
var ErrBootstrapMismatch = errors.New("the header database was started from another trust root; a sync never replaces it (remove the database to choose again)")

// Sync reads concatenated raw 80-byte headers from r, validates every one through Chain.Add, and persists the
// result. A header that fails validation stops the sync with its reason; what validated before it is kept, and
// the last-sync time is not advanced. Re-running a sync of headers already held changes nothing but the last-sync
// time. A database present but refused is never extended: Sync returns its *HeaderDBError and writes nothing.
func (d *HeaderDB) Sync(ctx context.Context, p Params, r io.Reader, opt SyncOptions) (*SyncResult, error) {
	clock := opt.Now
	if clock == nil {
		clock = time.Now
	}
	max := opt.MaxHeaders
	if max <= 0 {
		max = DefaultMaxSyncHeaders
	}
	unlock, err := d.lock(time.Now()) // lock age is wall-clock file time, whatever clock admits headers
	if err != nil {
		return nil, err
	}
	defer unlock()
	br := bufio.NewReaderSize(r, 64<<10)
	res := &SyncResult{}
	next := func() ([]byte, bool, error) {
		b := make([]byte, HeaderSize)
		n, err := io.ReadFull(br, b)
		switch {
		case err == io.EOF:
			return nil, false, nil
		case err == io.ErrUnexpectedEOF:
			return nil, false, &HeaderError{Reason: "bad-header", Detail: fmt.Sprintf("input ends with %d bytes, not a whole 80-byte header", n)}
		case err != nil:
			return nil, false, err
		}
		res.Read++
		return b, true, nil
	}
	c, err := d.Load(p, clock())
	switch {
	case errors.Is(err, ErrNoHeaderDB):
		provider := opt.Provider
		if provider == "" {
			provider = "headers-file"
		}
		if bs := opt.Bootstrap; bs != nil {
			n := bs.Count
			if n == 0 {
				n = 11
			}
			b := Bootstrap{Height: bs.Height, WorkBelow: bs.Work}
			for i := 0; i < n; i++ {
				raw, ok, err := next()
				if err != nil || !ok {
					return nil, fmt.Errorf("bootstrap needs %d headers at the head of the input: %v", n, err)
				}
				b.Headers = append(b.Headers, raw)
			}
			if c, err = NewChainFrom(p, provider, b); err != nil {
				return nil, fmt.Errorf("bootstrap: %w", err)
			}
		} else if c, err = NewChain(p, provider); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	case opt.Bootstrap != nil:
		// the database exists: the bootstrap it names must be the one already chosen
		n := opt.Bootstrap.Count
		if n == 0 {
			n = 11
		}
		b := Bootstrap{Height: opt.Bootstrap.Height, WorkBelow: opt.Bootstrap.Work}
		for i := 0; i < n; i++ {
			raw, ok, err := next()
			if err != nil || !ok {
				return nil, ErrBootstrapMismatch
			}
			b.Headers = append(b.Headers, raw)
		}
		if b.ID() != c.bootstrap {
			return nil, ErrBootstrapMismatch
		}
	}
	for {
		if res.Read >= max {
			if _, err := br.Peek(1); err == nil {
				res.Bounded = true
			}
			break
		}
		if ctx.Err() != nil {
			res.Cancelled = true
			break
		}
		raw, ok, err := next()
		if err != nil {
			res.Stopped, res.StoppedAt = err, res.Read+1
			break
		}
		if !ok {
			break
		}
		before := c.Len()
		if err := c.Add(raw, clock()); err != nil {
			res.Stopped, res.StoppedAt = err, res.Read
			break
		}
		if c.Len() > before {
			res.Added++
		} else {
			res.AlreadyHeld++
		}
	}
	if res.Stopped == nil && !res.Cancelled && !res.Bounded {
		c.MarkSynced(clock())
		res.Synced = true
	}
	if err := d.save(c); err != nil {
		return nil, err
	}
	res.View = c.Snapshot()
	return res, nil
}

// ReceiptFiles counts the receipt files held at loc without opening (or creating) the receipt store; ok is false
// when there is no receipt directory.
func ReceiptFiles(loc Location) (n int, ok bool) {
	ents, err := os.ReadDir(filepath.Join(loc.Dir, receiptsDir, receiptSubdir))
	if err != nil {
		return 0, false
	}
	for _, e := range ents {
		if e.Type().IsRegular() {
			n++
		}
	}
	return n, true
}
