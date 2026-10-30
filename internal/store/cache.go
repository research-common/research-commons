package store

// Projections and caches (storage note §5).
//
// A projection entry is keyed on, and only on, the components of §5.1: the digests of the statements and
// blobs it read, the policy digest, the evaluator version and the time context. CacheKey has no field for a
// path, a modification time, a size, an inode or a count, so a key cannot be built from one: a same-size,
// same-mtime rewrite of a statement file changes the statement's content digest and therefore misses
// (C-core-129). Entries live under <root>/cache/<projection>/<key digest>; the whole directory is a
// projection (deleting it is a cold start, §5.2) and nothing authoritative is ever read from it.
//
// This is a store-side facility. Nothing in the resolver uses it yet.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
)

var reProjection = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

// CacheKey is the §5.1 key of one projection entry.
type CacheKey struct {
	// Projection names the projection (a directory name: lowercase letters, digits, '_', '.', '-').
	Projection string
	// Query is the question the entry answered ("log of <key>", "resolution of <resource>"). A projection
	// records the query it answered, not only the statements it found (§5.3 item 1).
	Query string
	// Inputs are the digests of everything the projection read: build them with Store.Inputs and
	// Store.StatementSetInputs. Order is irrelevant; they are sorted before hashing.
	Inputs []string
	// Policy is the digest of the reader's trust, admission, execution and reference policy.
	Policy string
	// Evaluator is the version of the code that computed the entry; an entry from another version is dead.
	Evaluator string
	// Time is the reader's evaluation time, in its canonical spelling, for an answer that depends on it
	// (shelf life, finality, the future-timestamp bound). Empty for a time-independent answer.
	Time string
}

func (k CacheKey) object() *canon.Object {
	in := slices.Clone(k.Inputs)
	slices.Sort(in)
	in = slices.Compact(in)
	arr := canon.Array{}
	for _, s := range in {
		arr = append(arr, canon.String(s))
	}
	return &canon.Object{Keys: []string{"evaluator", "inputs", "policy", "projection", "query", "time", "v"},
		Members: map[string]canon.Value{"evaluator": canon.String(k.Evaluator), "inputs": arr,
			"policy": canon.String(k.Policy), "projection": canon.String(k.Projection),
			"query": canon.String(k.Query), "time": canon.String(k.Time), "v": canon.Int(1)}}
}

// Digest is the entry's name: lowercase hex sha256 of the canonical key.
func (k CacheKey) Digest() string {
	h := sha256.Sum256(canon.Encode(k.object()))
	return hex.EncodeToString(h[:])
}

func keyFromObject(o *canon.Object) (CacheKey, bool) {
	str := func(n string) (string, bool) { v, ok := o.Members[n].(canon.String); return string(v), ok }
	var k CacheKey
	var ok1, ok2, ok3, ok4, ok5 bool
	k.Evaluator, ok1 = str("evaluator")
	k.Policy, ok2 = str("policy")
	k.Projection, ok3 = str("projection")
	k.Query, ok4 = str("query")
	k.Time, ok5 = str("time")
	arr, ok6 := o.Members["inputs"].(canon.Array)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) {
		return k, false
	}
	for _, v := range arr {
		s, ok := v.(canon.String)
		if !ok {
			return k, false
		}
		k.Inputs = append(k.Inputs, string(s))
	}
	return k, true
}

// Inputs returns the input digests for the given statement ids and blob digests, as the cache key wants
// them. A statement's digest is the sha256 of the bytes of the file the store holds under that id, read now
// (never its size or modification time); a statement not held is "absent", so its arrival is a changed
// input. A blob is its content address plus whether it is held (a fetch changes availability, and with it
// every answer that depends on it); the bytes of a blob are not re-hashed here (OpenBlob and fsck do that).
func (s *Store) Inputs(stmts []string, blobs []Digest) ([]string, error) {
	var out []string
	for _, id := range stmts {
		in, err := s.StatementInput(id)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	for _, d := range blobs {
		if _, ok := d.hex(); !ok {
			return nil, refusal.Malformed("digest %q is not sha256: + 64 lowercase hex", d)
		}
		st := "absent"
		if s.HasBlob(d) {
			st = "held"
		}
		out = append(out, "blob:"+string(d)+":"+st)
	}
	slices.Sort(out)
	return out, nil
}

// StatementInput is the input digest of one statement id (see Inputs).
func (s *Store) StatementInput(id string) (string, error) {
	if !reHex.MatchString(id) {
		return "", refusal.Malformed("statement id %q is not 64 lowercase hex", id)
	}
	signers, err := os.ReadDir(s.dir("statements"))
	if err != nil {
		return "", err
	}
	var digs []string
	for _, sd := range signers {
		b, err := os.ReadFile(s.dir("statements", sd.Name(), id))
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrInvalid) {
			continue
		}
		if err != nil {
			var pe *fs.PathError
			if errors.As(err, &pe) && !sd.IsDir() {
				continue
			}
			return "", err
		}
		h := sha256.Sum256(b)
		digs = append(digs, hex.EncodeToString(h[:]))
	}
	if len(digs) == 0 {
		return "stmt:" + id + ":absent", nil
	}
	slices.Sort(digs)
	return "stmt:" + id + ":" + strings.Join(digs, "+"), nil
}

// StatementSetInputs returns the input digests of every statement installed under one signer directory
// name (signer "" = every signer). It is what a projection over "all statements of key X" records, so that
// a new statement by X is a new input and the entry misses (§5.3 item 1).
func (s *Store) StatementSetInputs(signer string) ([]string, error) {
	dirs, err := os.ReadDir(s.dir("statements"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, sd := range dirs {
		if !sd.IsDir() || (signer != "" && sd.Name() != signerDir(signer)) {
			continue
		}
		ents, err := os.ReadDir(s.dir("statements", sd.Name()))
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			if !reHex.MatchString(e.Name()) {
				continue
			}
			in, err := s.StatementInput(e.Name())
			if err != nil {
				return nil, err
			}
			out = append(out, in)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Projection is a named projection the store can rebuild cold: Key computes the key it would have now,
// Build computes its value from blobs and statements alone. fsck compares a warm entry with Build (drift)
// and `--rebuild <name>` runs Build.
type Projection struct {
	Name  string
	Key   func(*Store) (CacheKey, error)
	Build func(*Store) ([]byte, error)
}

// Cache is the projection cache of one store.
type Cache struct {
	s   *Store
	mu  sync.Mutex
	reg map[string]Projection
}

// NewCache returns the projection cache of s.
func NewCache(s *Store) *Cache { return &Cache{s: s, reg: map[string]Projection{}} }

func (c *Cache) dir(parts ...string) string { return c.s.dir(append([]string{"cache"}, parts...)...) }

func checkProjection(name string) error {
	if !reProjection.MatchString(name) {
		return fmt.Errorf("projection name %q: want lowercase letters, digits, '_', '.', '-' (at most 64)", name)
	}
	return nil
}

// Register adds a rebuildable projection.
func (c *Cache) Register(p Projection) error {
	if err := checkProjection(p.Name); err != nil {
		return err
	}
	if p.Key == nil || p.Build == nil {
		return fmt.Errorf("projection %q: Key and Build are required", p.Name)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reg[p.Name] = p
	return nil
}

// Registered lists the registered projection names, sorted.
func (c *Cache) Registered() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for n := range c.reg {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// publish writes b at dst through a temporary on the store's filesystem and renames it into place. A cache
// file may be replaced (it is a projection); no fsync (a lost cache file is a cold start).
func (c *Cache) publish(dst string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.s.dir("tmp"), "cache-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

func (c *Cache) entryPath(k CacheKey) string { return c.dir(k.Projection, k.Digest()) }

func latestName(query string) string {
	h := sha256.Sum256([]byte(query))
	return "latest-" + hex.EncodeToString(h[:8])
}

// Put stores value under k.
func (c *Cache) Put(k CacheKey, value []byte) error {
	if err := checkProjection(k.Projection); err != nil {
		return err
	}
	chk := sha256.Sum256(value)
	e := &canon.Object{Keys: []string{"check", "key", "value"}, Members: map[string]canon.Value{
		"check": canon.String(hex.EncodeToString(chk[:])), "key": k.object(), "value": canon.String(hex.EncodeToString(value))}}
	d := k.Digest()
	if err := c.publish(c.entryPath(k), append(canon.Encode(e), '\n')); err != nil {
		return err
	}
	// The pointer to the newest entry of this (projection, query) is only used to explain a miss (Why).
	return c.publish(c.dir(k.Projection, latestName(k.Query)), []byte(d+"\n"))
}

// read loads and checks the entry at path: its name must be the digest of its own key and its value must
// match its check digest. Anything else is not an entry.
func readEntry(path string) (CacheKey, []byte, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return CacheKey{}, nil, false
	}
	v, err := canon.Parse(bytes.TrimSuffix(b, []byte("\n")))
	if err != nil {
		return CacheKey{}, nil, false
	}
	o, ok := v.(*canon.Object)
	if !ok {
		return CacheKey{}, nil, false
	}
	ko, ok1 := o.Members["key"].(*canon.Object)
	chk, ok2 := o.Members["check"].(canon.String)
	val, ok3 := o.Members["value"].(canon.String)
	if !ok1 || !ok2 || !ok3 {
		return CacheKey{}, nil, false
	}
	k, ok := keyFromObject(ko)
	if !ok || k.Digest() != filepath.Base(path) {
		return CacheKey{}, nil, false
	}
	raw, err := hex.DecodeString(string(val))
	if err != nil {
		return CacheKey{}, nil, false
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != string(chk) {
		return CacheKey{}, nil, false
	}
	return k, raw, true
}

// Get returns the value stored under exactly k. A missing, unreadable or inconsistent entry is a miss: the
// caller recomputes.
func (c *Cache) Get(k CacheKey) ([]byte, bool, error) {
	if err := checkProjection(k.Projection); err != nil {
		return nil, false, err
	}
	_, v, ok := readEntry(c.entryPath(k))
	return v, ok, nil
}

// Compute returns the cached value for k or runs build, stores its result and returns that. hit says which.
func (c *Cache) Compute(k CacheKey, build func() ([]byte, error)) (value []byte, hit bool, err error) {
	if v, ok, err := c.Get(k); err != nil || ok {
		return v, ok, err
	}
	v, err := build()
	if err != nil {
		return nil, false, err
	}
	return v, false, c.Put(k, v)
}

// Invalidate drops every entry of the named projections (§5.3 item 6). A name with no entries is fine.
func (c *Cache) Invalidate(names ...string) error {
	for _, n := range names {
		if err := checkProjection(n); err != nil {
			return err
		}
		if err := os.RemoveAll(c.dir(n)); err != nil {
			return err
		}
	}
	return nil
}

// Clear drops every projection and the verification cache: a cold start (§5.2).
func (c *Cache) Clear() error { return os.RemoveAll(c.dir()) }

// Why explains a miss for k: the components that differ from the newest entry recorded for the same
// projection and query. An empty slice means k is the newest entry's key (a hit, or an entry that is gone);
// "no earlier entry" means the question was never answered here.
func (c *Cache) Why(k CacheKey) []string {
	b, err := os.ReadFile(c.dir(k.Projection, latestName(k.Query)))
	if err != nil {
		return []string{"no earlier entry for this query"}
	}
	old, _, ok := readEntry(c.dir(k.Projection, strings.TrimSpace(string(b))))
	if !ok {
		return []string{"the earlier entry is unreadable"}
	}
	var out []string
	if old.Policy != k.Policy {
		out = append(out, fmt.Sprintf("policy digest changed (%s → %s)", old.Policy, k.Policy))
	}
	if old.Evaluator != k.Evaluator {
		out = append(out, fmt.Sprintf("evaluator version changed (%s → %s)", old.Evaluator, k.Evaluator))
	}
	if old.Time != k.Time {
		out = append(out, fmt.Sprintf("time context changed (%q → %q)", old.Time, k.Time))
	}
	oldIn, newIn := inputMap(old.Inputs), inputMap(k.Inputs)
	var names []string
	for n := range oldIn {
		names = append(names, n)
	}
	for n := range newIn {
		if _, ok := oldIn[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range slices.Compact(names) {
		o, n1 := oldIn[n], newIn[n]
		switch {
		case o == n1:
		case o == "":
			out = append(out, fmt.Sprintf("new input %s (%s)", n, n1))
		case n1 == "":
			out = append(out, fmt.Sprintf("input %s is no longer read (was %s)", n, o))
		case o == "absent":
			out = append(out, fmt.Sprintf("input %s arrived (%s)", n, n1))
		case n1 == "absent":
			out = append(out, fmt.Sprintf("input %s is gone (was %s)", n, o))
		default:
			out = append(out, fmt.Sprintf("input %s changed (%s → %s)", n, o, n1))
		}
	}
	return out
}

func inputMap(in []string) map[string]string {
	m := map[string]string{}
	for _, s := range in {
		i := strings.LastIndex(s, ":")
		if i < 0 {
			m[s] = ""
			continue
		}
		m[s[:i]] = s[i+1:]
	}
	return m
}

// Rebuilt is one projection `--rebuild` recomputed.
type Rebuilt struct {
	Name, Key string
	Bytes     int
}

// Rebuild drops and recomputes the named registered projections cold (all registered ones when no name is
// given). An unknown name is an error naming the registered ones.
func (c *Cache) Rebuild(names ...string) ([]Rebuilt, error) {
	ps, err := c.lookup(names)
	if err != nil {
		return nil, err
	}
	var out []Rebuilt
	for _, p := range ps {
		if err := c.Invalidate(p.Name); err != nil {
			return out, err
		}
		k, err := p.Key(c.s)
		if err != nil {
			return out, fmt.Errorf("projection %s: key: %w", p.Name, err)
		}
		v, err := p.Build(c.s)
		if err != nil {
			return out, fmt.Errorf("projection %s: build: %w", p.Name, err)
		}
		if err := c.Put(k, v); err != nil {
			return out, err
		}
		out = append(out, Rebuilt{Name: p.Name, Key: k.Digest(), Bytes: len(v)})
	}
	return out, nil
}

func (c *Cache) lookup(names []string) ([]Projection, error) {
	if len(names) == 0 {
		names = c.Registered()
	}
	var out []Projection
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, n := range names {
		p, ok := c.reg[n]
		if !ok {
			var have []string
			for r := range c.reg {
				have = append(have, r)
			}
			sort.Strings(have)
			return nil, fmt.Errorf("unknown projection %q (registered: %s)", n, strings.Join(have, ", "))
		}
		out = append(out, p)
	}
	return out, nil
}

// Drift is a warm entry that differs from a cold rebuild.
type Drift struct {
	Name, Key  string
	Warm, Cold Digest
}

// Drift compares, for each named registered projection (all when none is named), the entry under its
// current key with a cold Build. An absent entry is a cold start, not drift.
func (c *Cache) Drift(names ...string) ([]Drift, error) {
	ps, err := c.lookup(names)
	if err != nil {
		return nil, err
	}
	var out []Drift
	for _, p := range ps {
		k, err := p.Key(c.s)
		if err != nil {
			return out, fmt.Errorf("projection %s: key: %w", p.Name, err)
		}
		warm, ok, err := c.Get(k)
		if err != nil || !ok {
			if err != nil {
				return out, err
			}
			continue
		}
		cold, err := p.Build(c.s)
		if err != nil {
			return out, fmt.Errorf("projection %s: build: %w", p.Name, err)
		}
		if !bytes.Equal(warm, cold) {
			out = append(out, Drift{Name: p.Name, Key: k.Digest(), Warm: digestBytes(warm), Cold: digestBytes(cold)})
		}
	}
	return out, nil
}

func digestBytes(b []byte) Digest {
	h := sha256.Sum256(b)
	return Digest("sha256:" + hex.EncodeToString(h[:]))
}

// ---------------------------------------------------------------------------------------------------------
// The signature-verification cache (§5.3 item 7, C-core-129a).

// Verdict is all a verification cache holds: never a value.
type Verdict string

const (
	Verified Verdict = "verified"
	Failed   Verdict = "failed"
)

// VerifyFunc verifies one received line and returns a typed refusal when it fails. Any other error is an
// operational failure of the verification itself and is never cached.
type VerifyFunc func(line []byte) error

// VerifyMode selects whether the cache may answer.
type VerifyMode int

const (
	// UseCache answers from an entry when there is one: daily use.
	UseCache VerifyMode = iota
	// Cold ignores every entry and verifies in this run, then refreshes the entry. A conformance run uses it:
	// every verification it reports is computed in the run under test, so a "verified" entry planted for an
	// invalid statement is never reported (§5.3, decided 4).
	Cold
)

// VerifyCache caches "verified" or "failed" per (line digest, verifier version). Changing the version
// misses every entry. It never holds a value and never decides anything a cold run would not.
type VerifyCache struct {
	s       *Store
	version string
	verify  VerifyFunc
	Mode    VerifyMode

	hits, computed atomic.Int64
}

// NewVerifyCache returns a verification cache for the named verifier version. verify is the function that
// computes a verdict; the version must change whenever its behaviour does.
func (s *Store) NewVerifyCache(version string, verify VerifyFunc) (*VerifyCache, error) {
	if version == "" || verify == nil {
		return nil, errors.New("verification cache: a verifier version and a verify function are required")
	}
	return &VerifyCache{s: s, version: version, verify: verify}, nil
}

// Stats reports how many answers came from an entry and how many were computed.
func (v *VerifyCache) Stats() (hits, computed int64) { return v.hits.Load(), v.computed.Load() }

func (v *VerifyCache) path(line []byte) string {
	ld := sha256.Sum256(line)
	h := sha256.Sum256([]byte("rc-verify/1\n" + v.version + "\n" + hex.EncodeToString(ld[:])))
	return v.s.dir("cache", "verify", hex.EncodeToString(h[:]))
}

// Check returns the verdict for line. For a failure the error is the typed refusal (from the verifier on a
// computed verdict; class and reason only, from an entry).
func (v *VerifyCache) Check(line []byte) (Verdict, error) {
	p := v.path(line)
	if v.Mode == UseCache {
		if b, err := os.ReadFile(p); err == nil {
			parts := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
			switch {
			case len(parts) == 1 && parts[0] == string(Verified):
				v.hits.Add(1)
				return Verified, nil
			case len(parts) == 3 && parts[0] == string(Failed):
				v.hits.Add(1)
				return Failed, &refusal.Refusal{Class: refusal.Class(parts[1]), Reason: parts[2],
					Detail: "cached verdict; verify without the cache for the detail"}
			}
			// anything else is not an entry: fall through and compute
		}
	}
	v.computed.Add(1)
	err := v.verify(line)
	var entry string
	switch {
	case err == nil:
		entry = string(Verified) + "\n"
	default:
		var r *refusal.Refusal
		if !errors.As(err, &r) {
			return "", err
		}
		entry = string(Failed) + "\n" + string(r.Class) + "\n" + r.Reason + "\n"
	}
	c := &Cache{s: v.s}
	if perr := c.publish(p, []byte(entry)); perr != nil {
		return "", perr
	}
	if err != nil {
		return Failed, err
	}
	return Verified, nil
}
