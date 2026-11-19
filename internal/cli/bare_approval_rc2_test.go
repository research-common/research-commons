package cli

import (
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

// edition writes an edition draft off the genesis listing members (strings) in h's key directory.
func (m *mixedCollection) edition(h *idHome, name string, members ...string) string {
	ms := make([]string, len(members))
	for i, s := range members {
		ms[i] = `"` + s + `"`
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
