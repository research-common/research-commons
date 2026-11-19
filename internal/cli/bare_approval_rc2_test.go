package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// mixedCollection is a collection whose genesis names {identity: I} and {key: K2}: root holds I's root key,
// worker signed the genesis (its first line) and holds a grant from I for `edition` on the resource, backup is K2.
type mixedCollection struct {
	root, worker, backup *idHome
	ident, gid, grant    string
}

func newMixedCollection(t *testing.T, alg, rule string) *mixedCollection {
	t.Helper()
	m := &mixedCollection{root: newIDHome(t, alg), worker: newIDHome(t, alg), backup: newIDHome(t, alg)}
	m.ident = string(m.root.ok("identity", "new").Members["identity"].(canon.String))
	m.worker.pullFrom(m.root)
	m.gid = firstID(t, m.worker.ok("publish", "--draft", m.worker.file("g.json",
		`{"kind":"genesis","body":{"type":"collection","name":"mixed","controllers":[{"identity":"`+m.ident+`"},{"key":"`+m.backup.signer+`"}],"rule":`+rule+`}}`)))
	m.root.pullFrom(m.worker)
	m.grant = firstID(t, m.root.ok("identity", "grant", "--identity", m.ident, "--delegate", m.worker.signer, "--delegate-inception", m.gid,
		"--permissions", `[{"kind":"edition","targets":{"resources":["`+m.gid+`"]}},{"kind":"withdraw_approval","targets":{"resources":["`+m.gid+`"]}}]`))
	m.worker.pullFrom(m.root)
	m.backup.pullFrom(m.worker)
	return m
}

// edition writes an edition draft off the genesis in h's key directory, listing one member per digit d (content
// sha256 of 64 d's).
func (m *mixedCollection) edition(h *idHome, name string, digits ...string) string {
	ms := make([]string, len(digits))
	for i, d := range digits {
		ms[i] = `{"content":"sha256:` + strings.Repeat(d, 64) + `","role":"dataset"}`
	}
	return h.file(name, `{"kind":"edition","body":{"resource":"`+m.gid+`","predecessors":["`+m.gid+`"],"contents":{"members":[`+strings.Join(ms, ",")+`],"selection":"curated"}}}`)
}

// view is the resource view a reader holding all three stores sees.
func (m *mixedCollection) view(t *testing.T) (*idHome, *canon.Object) {
	t.Helper()
	reader := newIDHome(t, wire.AlgEd25519)
	for _, h := range []*idHome{m.worker, m.root, m.backup} {
		reader.pullFrom(h)
	}
	return reader, members(t, jsonOf(t, reader.read("show", m.gid)), "resource_view")
}

// nonGenesis returns the view's edition rows other than the genesis.
func (m *mixedCollection) nonGenesis(rv *canon.Object) []*canon.Object {
	var out []*canon.Object
	for _, x := range rv.Members["editions"].(canon.Array) {
		e := x.(*canon.Object)
		if e.Members["edition"] != canon.String(m.gid) {
			out = append(out, e)
		}
	}
	return out
}

// TestBareApprovalOfTypedResourceCombines: a k_of_n 2 collection of {identity I, key K2}. I's approval (--as) and
// K2's bare approval of the same draft share one edition id (identity profile §2.1: approvals of one edition share
// the major and the body bytes; §2.3: a marker-only rc/2 line is a bare key's approval of an identity-aware body), so
// the edition is authorized and current and verify exits 0.
func TestBareApprovalOfTypedResourceCombines(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			m := newMixedCollection(t, alg, `{"k_of_n":{"k":2}}`)
			d := m.edition(m.worker, "e.json")
			m.worker.ok("publish", "--draft", d, "--as", m.ident, "--grant", m.grant)
			m.backup.pullFrom(m.worker)
			m.backup.pullFrom(m.root)
			m.backup.ok("publish", "--draft", m.edition(m.backup, "e.json"))
			reader, rv := m.view(t)
			eds := m.nonGenesis(rv)
			if len(eds) != 1 {
				t.Fatalf("two approvals of one draft are %d editions: %s", len(eds), canon.Encode(rv))
			}
			e := eds[0]
			if e.Members["state"] != canon.String("edition") || len(e.Members["approvals"].(canon.Array)) != 2 || rv.Members["current"] != e.Members["edition"] {
				t.Fatalf("co-approved edition: %s", canon.Encode(rv))
			}
			if r := reader.read("verify", m.gid); r.code != ExitOK {
				t.Fatalf("verify: %d %s", r.code, r.stdout)
			}
		})
	}
}

// markerOnly fails unless line is a bare key's rc/2 line: rc/2, crit [x_identity_v1], the marker {}, no actor.
func markerOnly(t *testing.T, line string) {
	t.Helper()
	for _, want := range []string{`"rc":"rc/2"`, `"crit":["x_identity_v1"]`, `"x_identity_v1":{}`} {
		if !strings.Contains(line, want) {
			t.Fatalf("not a marker-only rc/2 line (lacks %s): %s", want, line)
		}
	}
	if strings.Contains(line, wire.ActorField) {
		t.Fatalf("a bare key's line carries an actor: %s", line)
	}
}

// TestBareEditionOfTypedResourceAnyOne: under any_one, K2 alone publishes an edition of a resource whose genesis is
// rc/2: authorized and current as before, now written rc/2 marker-only.
func TestBareEditionOfTypedResourceAnyOne(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			m := newMixedCollection(t, alg, `{"any_one":true}`)
			id := firstID(t, m.backup.ok("publish", "--draft", m.edition(m.backup, "e.json")))
			markerOnly(t, lineOf(t, m.backup.store, id))
			reader, rv := m.view(t)
			eds := m.nonGenesis(rv)
			if len(eds) != 1 || eds[0].Members["state"] != canon.String("edition") || rv.Members["current"] != eds[0].Members["edition"] {
				t.Fatalf("K2's edition under any_one: %s", canon.Encode(rv))
			}
			if r := reader.read("verify", m.gid); r.code != ExitOK {
				t.Fatalf("verify: %d %s", r.code, r.stdout)
			}
		})
	}
}

// pinnedKey writes an Ed25519 key file with a fixed seed (Ed25519 signing is deterministic, so its lines are too).
func pinnedKey(t *testing.T) (string, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pinned.key")
	if err := os.WriteFile(p, []byte(`{"alg":"ed25519","format":"rc-key/0","seed":"`+strings.Repeat("3d", 32)+`"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runIn(filepath.Dir(p), nil, "key", "show", p, "--json")
	if r.code != ExitOK {
		t.Fatalf("key show: %d %s", r.code, r.stdout)
	}
	return p, string(jsonOf(t, r).Members["signer"].(canon.String))
}

// The rc/1 edition a bare key writes for a collection whose genesis is rc/1 (key controllers only), captured from
// the writer before typed resources were routed by their genesis's major (origin/next at 8b61959).
const (
	keyOnlyEditionLine = `{"alg":"ed25519","body":{"contents":{"members":[],"selection":"curated"},"predecessors":["0592066bd02a3c433a0f64c53edf507b2be5e612769467e464f54a198a5d6e62"],"resource":"0592066bd02a3c433a0f64c53edf507b2be5e612769467e464f54a198a5d6e62"},"kind":"edition","prev":"0592066bd02a3c433a0f64c53edf507b2be5e612769467e464f54a198a5d6e62","rc":"rc/1","seq":1,"sig":"d565a362d22deed09f74a298adaf3aad525e9486e04250809e6f184e154fb25be73d4d252bd0a1b3a69b145e340ddec26852f4630b59098982315725c42c110d","signer":"ed25519:70df9e2279adbec6d12bf2921184c9222eb24ed852005bf640139f52e59cd9ae","ts":"2026-11-18T00:00:01Z"}`
	keyOnlyEditionID   = "c6458746a6aaa0dd63ec3b5763e22b83b79094d45bd3910185bfa591f259cbb4"
)

// TestBareEditionOfKeyOnlyResourceBytes: a bare key's edition of a collection whose genesis is rc/1 stays rc/1, no
// marker and no crit, byte for byte as before.
func TestBareEditionOfKeyOnlyResourceBytes(t *testing.T) {
	key, signer := pinnedKey(t)
	st := drillStore(t)
	run := func(args ...string) *canon.Object {
		t.Helper()
		r := runIn(st, nil, append(args, "--key", key, "--json")...)
		if r.code != ExitOK {
			t.Fatalf("%v: %d %s", args, r.code, r.stdout)
		}
		return jsonOf(t, r)
	}
	dir := t.TempDir()
	g := filepath.Join(dir, "g.json")
	os.WriteFile(g, []byte(`{"kind":"genesis","body":{"type":"collection","name":"plain","controllers":["`+signer+`"],"rule":{"any_one":true}}}`), 0o644)
	gid := firstID(t, run("publish", "--draft", g, "--ts", "2026-11-18T00:00:00Z"))
	e := filepath.Join(dir, "e.json")
	os.WriteFile(e, []byte(`{"kind":"edition","body":{"resource":"`+gid+`","predecessors":["`+gid+`"],"contents":{"members":[],"selection":"curated"}}}`), 0o644)
	id := firstID(t, run("publish", "--draft", e, "--ts", "2026-11-18T00:00:01Z"))
	line := lineOf(t, st, id)
	if !strings.Contains(line, `"rc":"rc/1"`) || strings.Contains(line, "crit") || strings.Contains(line, wire.IdentityCrit) {
		t.Fatalf("an edition of a key-only collection is not plain rc/1: %s", line)
	}
	if line != keyOnlyEditionLine || id != keyOnlyEditionID {
		t.Fatalf("rc/1 edition bytes moved\n got %s\n id %s", line, id)
	}
}

// state is the state of the non-genesis edition whose approvals include statement id.
func (m *mixedCollection) stateOf(t *testing.T, rv *canon.Object, id string) (string, string) {
	t.Helper()
	for _, e := range m.nonGenesis(rv) {
		for _, a := range e.Members["approvals"].(canon.Array) {
			if a.(*canon.Object).Members["statement"] == canon.String(id) {
				return string(e.Members["state"].(canon.String)), string(e.Members["edition"].(canon.String))
			}
		}
	}
	t.Fatalf("no edition carries approval %s: %s", id, canon.Encode(rv))
	return "", ""
}

// TestBareApprovalAfterRootRevoke: the recovery path after a root compromise. The identity's root revokes its key
// (key_compromise, nothing kept), so every approval made for the identity stops counting (identity profile §1: root
// compromise is total and retroactive). Under k_of_n 2, an edition approved by both I and K2 is pending again: K2's
// approval alone is one of two. Under any_one, K2 alone publishes an edition off the genesis and it is current.
func TestBareApprovalAfterRootRevoke(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			revokeRoot := func(m *mixedCollection) {
				t.Helper()
				m.root.ok("revoke", "--reason", "key_compromise", "--last-good", "none")
			}

			// k_of_n 2: co-approved, then the root is revoked: pending
			m := newMixedCollection(t, alg, `{"k_of_n":{"k":2}}`)
			m.worker.ok("publish", "--draft", m.edition(m.worker, "e.json"), "--as", m.ident, "--grant", m.grant)
			m.backup.pullFrom(m.worker)
			k2 := firstID(t, m.backup.ok("publish", "--draft", m.edition(m.backup, "e.json")))
			if _, rv := m.view(t); rv.Members["current"] == canon.String(m.gid) {
				t.Fatalf("co-approved edition is not current before the revoke: %s", canon.Encode(rv))
			}
			revokeRoot(m)
			reader, rv := m.view(t)
			if st, _ := m.stateOf(t, rv, k2); st != "pending" || rv.Members["current"] != canon.String(m.gid) {
				t.Fatalf("k_of_n 2 after the root revoke: %s %s", st, canon.Encode(rv))
			}
			_ = reader // verify exits 0 here: the genesis is the current authority, a valid state (no FORK)

			// any_one: the identity's edition is current, the root is revoked, K2 alone carries on off the genesis
			m = newMixedCollection(t, alg, `{"any_one":true}`)
			wid := firstID(t, m.worker.ok("publish", "--draft", m.edition(m.worker, "e.json", "a"), "--as", m.ident, "--grant", m.grant))
			revokeRoot(m)
			m.backup.pullFrom(m.worker)
			m.backup.pullFrom(m.root)
			k2 = firstID(t, m.backup.ok("publish", "--draft", m.edition(m.backup, "k2.json", "b")))
			markerOnly(t, lineOf(t, m.backup.store, k2))
			reader, rv = m.view(t)
			st, eid := m.stateOf(t, rv, k2)
			if st != "edition" || rv.Members["current"] != canon.String(eid) {
				t.Fatalf("any_one K2 after the root revoke: %s %s", st, canon.Encode(rv))
			}
			if st, _ := m.stateOf(t, rv, wid); st == "edition" {
				t.Fatalf("the identity's edition still counts after its root's key_compromise revoke: %s", canon.Encode(rv))
			}
			if r := reader.read("verify", m.gid); r.code != ExitOK {
				t.Fatalf("verify: %d %s", r.code, r.stdout)
			}
		})
	}
}

// TestBareWithdrawOfTypedResource: K2 withdraws its own marker-only approval (a bare withdrawal takes back the key's
// bare approvals, identity profile §5.2). The withdrawal is itself written marker-only, and the co-approved
// edition is pending again; the identity's approval is untouched.
func TestBareWithdrawOfTypedResource(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			m := newMixedCollection(t, alg, `{"k_of_n":{"k":2}}`)
			m.worker.ok("publish", "--draft", m.edition(m.worker, "e.json"), "--as", m.ident, "--grant", m.grant)
			m.backup.pullFrom(m.worker)
			m.backup.pullFrom(m.root)
			k2 := firstID(t, m.backup.ok("publish", "--draft", m.edition(m.backup, "e.json")))
			_, rv := m.view(t)
			_, eid := m.stateOf(t, rv, k2)
			if rv.Members["current"] != canon.String(eid) {
				t.Fatalf("co-approved edition not current: %s", canon.Encode(rv))
			}
			w := firstID(t, m.backup.ok("publish", "--draft", m.backup.file("w.json",
				`{"kind":"withdraw_approval","body":{"resource":"`+m.gid+`","edition":"`+eid+`"}}`)))
			markerOnly(t, lineOf(t, m.backup.store, w))
			_, rv = m.view(t)
			if st, _ := m.stateOf(t, rv, k2); st != "pending" || rv.Members["current"] != canon.String(m.gid) {
				t.Fatalf("after K2's withdrawal: %s %s", st, canon.Encode(rv))
			}
			var withdrawn, kept int
			for _, e := range m.nonGenesis(rv) {
				for _, a := range e.Members["approvals"].(canon.Array) {
					if ao := a.(*canon.Object); ao.Members["withdrawn_by"] == canon.String(w) {
						withdrawn++
					} else {
						kept++
					}
				}
			}
			if withdrawn != 1 || kept != 1 {
				t.Fatalf("withdrawn %d kept %d: %s", withdrawn, kept, canon.Encode(rv))
			}
		})
	}
}

// TestBareEditionOfTypedResourceEdges: what a bare key's edition of an rc/2 resource does at the edges. A controller
// change to plain key strings (the rc/1 form, which the rc/2 schema does not read) stays rc/1 as before; a typed
// controller change (keys, or an identity beside a key) is written marker-only; a draft that already carries the
// marker is refused (the writer adds it); an edition of a resource whose genesis is not held is refused, exit 3,
// naming the resource: its major cannot be guessed; --prepare (external signing) is for acts only and refuses a bare
// edition as before. Every refusal leaves the store byte-identical.
func TestBareEditionOfTypedResourceEdges(t *testing.T) {
	m := newMixedCollection(t, wire.AlgEd25519, `{"any_one":true}`)
	draft := func(name, resource, contents, extra string) string {
		return m.backup.file(name, `{"kind":"edition","body":{"resource":"`+resource+`","predecessors":["`+resource+`"],"contents":{"members":[],"selection":"curated"`+contents+`}`+extra+`}}`)
	}

	before := storeBytes(t, m.backup.store)
	r := m.backup.run("publish", "--draft", draft("m.json", m.gid, "", `,"x_identity_v1":{}`))
	if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "already carries x_identity_v1") {
		t.Fatalf("a draft carrying the marker: %d %s", r.code, r.stdout)
	}
	other := strings.Repeat("e", 64)
	r = m.backup.run("publish", "--draft", draft("n.json", other, "", ""))
	if r.code != ExitCouldNot || !strings.Contains(r.stdout, "problem:resource-not-held") || !strings.Contains(r.stdout, other) {
		t.Fatalf("an edition of a resource not held: %d %s", r.code, r.stdout)
	}
	// external signing prepares only an act for an identity: a bare edition is not prepared, so it has no other form
	r = runIn(m.backup.store, nil, "publish", "--draft", draft("x.json", m.gid, "", ""), "--prepare", filepath.Join(t.TempDir(), "x.pkg"), "--signer", m.backup.signer, "--json")
	if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "publish --prepare needs --as") {
		t.Fatalf("a bare edition prepared: %d %s", r.code, r.stdout)
	}
	if storeBytes(t, m.backup.store) != before {
		t.Fatal("a refused edition changed the store")
	}

	plain := firstID(t, m.backup.ok("publish", "--draft", draft("p.json", m.gid, `,"controllers":["`+m.backup.signer+`"],"rule":{"any_one":true}`, "")))
	if l := lineOf(t, m.backup.store, plain); !strings.Contains(l, `"rc":"rc/1"`) || strings.Contains(l, wire.IdentityCrit) {
		t.Fatalf("a plain-key controller change is not rc/1: %s", l)
	}
	typed := firstID(t, m.backup.ok("publish", "--draft", draft("t.json", m.gid, `,"controllers":[{"key":"`+m.backup.signer+`"}],"rule":{"any_one":true}`, "")))
	markerOnly(t, lineOf(t, m.backup.store, typed))
	// a typed controller change naming an identity is written too: the resource is already identity-aware (its
	// genesis is rc/2); a key-controlled collection's edition naming an identity is still refused (KNOWN-LIMITS L-21)
	ctrl := []string{`{"identity":"` + m.ident + `"}`, `{"key":"` + m.backup.signer + `"}`}
	if ctrl[0] > ctrl[1] {
		ctrl[0], ctrl[1] = ctrl[1], ctrl[0]
	}
	ident := firstID(t, m.backup.ok("publish", "--draft", draft("i.json", m.gid, `,"controllers":[`+strings.Join(ctrl, ",")+`],"rule":{"k_of_n":{"k":2}}`, "")))
	markerOnly(t, lineOf(t, m.backup.store, ident))
}
