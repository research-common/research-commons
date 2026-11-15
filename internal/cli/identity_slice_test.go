package cli

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/wire"
)

// Identity command slice: the consumer requirements of fixed-root identity profile §1 and §4.1 as the commands
// print them. C-id-09 (a bundle omitting a cut reads eligible relative to held evidence, freshness not_established,
// no claim that no cut exists), C-id-10 (a delegate's own revoke/rotate closes no grant: the two axes side by side)
// and C-id-23 (a cut that drops a key's anchor but keeps its claim: authority and time quality are two outcomes).

func str(v canon.Value) string { s, _ := v.(canon.String); return string(s) }

// grantsOf is the `grants` (or other list member) of an output, each row an object.
func grantsOf(t *testing.T, o *canon.Object, k string) []*canon.Object {
	t.Helper()
	a, _ := o.Members[k].(canon.Array)
	var out []*canon.Object
	for _, v := range a {
		out = append(out, v.(*canon.Object))
	}
	return out
}

// freshOK: the identity answer carries freshness not_established and its note.
func freshOK(t *testing.T, where string, o *canon.Object) {
	t.Helper()
	if str(o.Members["freshness"]) != "not_established" || str(o.Members["freshness_note"]) != freshnessNote {
		t.Fatalf("%s: no freshness: %s", where, canon.Encode(o))
	}
}

// TestIdentitySliceStaleBundle (C-id-09): the root cuts G (keep nothing). A reader holding the full set reads the
// act denied and the grant `cut null`; a reader given a bundle that omits the cut entirely reads the act eligible
// and the grant open, both relative to held evidence: freshness not_established, "no claim that no cut exists", on
// show and explain of the act and of the key. Direct store and pulled store alike.
func TestIdentitySliceStaleBundle(t *testing.T) {
	conformance.Covers(t, "C-id-09")
	w := newWorld(t)
	w.worker("K")
	i, a := w.identityOf("I", "IR", canon.Bool(true), "K")
	g := a["K"][1]
	w.ids["G"] = g
	act := w.signRC2("A", "K", "authored", licBody("X", "MIT"), a["K"])
	w.signRC2("C", "IR", "identity_cut", nullCut(i, g), [2]string{})
	key := w.key("K").Signer()
	check := func(t *testing.T, d *world, wantAct, wantGrant string) {
		t.Helper()
		sh := showJSON(t, d, act)
		ac, _ := sh.Members["actor"].(*canon.Object)
		if ac == nil || str(ac.Members["state"]) != wantAct {
			t.Fatalf("act: %s", canon.Encode(sh))
		}
		freshOK(t, "show act", ac)
		ex := jsonOf(t, d.run("explain", act, "--json"))
		freshOK(t, "explain act", ex.Members["actor"].(*canon.Object))
		for _, cmd := range []string{"show", "explain"} {
			r := d.run(cmd, key, "--json")
			if r.code != ExitOK {
				t.Fatalf("%s key: %d %s%s", cmd, r.code, r.stdout, r.stderr)
			}
			ko := jsonOf(t, r)
			gs := grantsOf(t, ko, "grants")
			if len(gs) != 1 || str(gs[0].Members["grant"]) != g || str(gs[0].Members["identity"]) != i || str(gs[0].Members["state"]) != wantGrant {
				t.Fatalf("%s key grants: %s", cmd, r.stdout)
			}
			freshOK(t, cmd+" key grant", gs[0])
			if str(member(ko, "bare_key", "state")) != "no key event" {
				t.Fatalf("%s key bare_key: %s", cmd, r.stdout)
			}
		}
		// the human form says the same, in words
		if r := d.run("show", act); !strings.Contains(r.stdout, freshnessNote) || !strings.Contains(r.stdout, "not_established") {
			t.Fatalf("human show act lacks freshness:\n%s", r.stdout)
		}
	}
	for how, d := range readers(holding(t, w, "first:K", "I", "G", "A", "C")) {
		t.Run("full/"+how, func(t *testing.T) { check(t, d, "denied", "cut null") })
	}
	for how, d := range readers(holding(t, w, "first:K", "I", "G", "A")) {
		t.Run("stale/"+how, func(t *testing.T) { check(t, d, "eligible", "open") })
	}
}

// TestIdentitySliceSelfRevokeRotate (C-id-10), through the commands: the worker publishes an act for I under G, then
// revokes its own key. The revoke (dry run and signed) lists G by id as not closed; show of the act stays eligible
// with the delegate_self_event warning; show <key> prints the two axes side by side: bare_key self-revoked (each
// event's effect) and grant G open. A rotation does the same. A root cut is what closes G, and show <key> then
// reads it `cut null` while the bare-key axis is unchanged.
func TestIdentitySliceSelfRevokeRotate(t *testing.T) {
	conformance.Covers(t, "C-id-10")
	perms := `[{"kind":"authored","targets":{"any_content":true},"amend":true}]`
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg+"/revoke", func(t *testing.T) {
			root, worker, ident, _, grant := idSetup(t, alg, perms)
			act := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("c1", "act one"), "--licence", "CC0-1.0", "--as", ident, "--grant", grant))
			notClosed := func(o *canon.Object, state string) {
				t.Helper()
				gs := grantsOf(t, o, "grants_not_closed")
				if len(gs) != 1 || str(gs[0].Members["grant"]) != grant || str(gs[0].Members["state"]) != state || !strings.Contains(str(o.Members["grants_note"]), "closes none of the grants") {
					t.Fatalf("grants_not_closed: %s", canon.Encode(o))
				}
				freshOK(t, "grants_not_closed", gs[0])
			}
			before := storeBytes(t, worker.store)
			notClosed(worker.ok("revoke", "--reason", "superseded", "--dry-run"), "open")
			if storeBytes(t, worker.store) != before {
				t.Fatal("dry run wrote")
			}
			notClosed(worker.ok("revoke", "--reason", "superseded"), "open")
			sh := jsonOf(t, worker.read("show", act))
			if str(member(sh, "actor", "state")) != "eligible" || str(sh.Members["counted"]) != "counted" || !strings.Contains(string(canon.Encode(member(sh, "actor", "reasons"))), "warning delegate_self_event") {
				t.Fatalf("act after self-revoke: %s", canon.Encode(sh))
			}
			ko := jsonOf(t, worker.read("show", worker.signer))
			if str(member(ko, "bare_key", "state")) != "self-revoked" || !strings.Contains(string(canon.Encode(member(ko, "bare_key", "events"))), "self-revoked (soft)") {
				t.Fatalf("bare-key axis: %s", canon.Encode(ko))
			}
			if gs := grantsOf(t, ko, "grants"); len(gs) != 1 || str(gs[0].Members["state"]) != "open" || !strings.Contains(string(canon.Encode(gs[0].Members["reasons"])), "delegate_self_event") {
				t.Fatalf("grant axis: %s", canon.Encode(ko))
			}
			// only the root closes G
			root.pullFrom(worker)
			root.ok("identity", "cut", "--identity", ident, "--grant", grant, "--last-good", "none", "--reason", "superseded")
			worker.pullFrom(root)
			ko = jsonOf(t, worker.read("show", worker.signer))
			if gs := grantsOf(t, ko, "grants"); len(gs) != 1 || str(gs[0].Members["state"]) != "cut null" || str(member(ko, "bare_key", "state")) != "self-revoked" {
				t.Fatalf("after the root's cut: %s", canon.Encode(ko))
			}
			if str(member(jsonOf(t, worker.read("show", act)), "actor", "state")) != "denied" {
				t.Fatal("act counts after the root's null cut")
			}
		})
		t.Run(alg+"/rotate", func(t *testing.T) {
			_, worker, ident, _, grant := idSetup(t, alg, perms)
			act := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("c1", "act one"), "--licence", "CC0-1.0", "--as", ident, "--grant", grant))
			_, succ := newKeyFile(t, t.TempDir(), alg)
			o := worker.ok("rotate", "--successor", succ)
			if gs := grantsOf(t, o, "grants_not_closed"); len(gs) != 1 || str(gs[0].Members["grant"]) != grant || str(gs[0].Members["state"]) != "open" {
				t.Fatalf("rotate grants_not_closed: %s", canon.Encode(o))
			}
			if str(member(jsonOf(t, worker.read("show", act)), "actor", "state")) != "eligible" {
				t.Fatal("act lost eligibility on rotation")
			}
			ko := jsonOf(t, worker.read("show", worker.signer))
			if str(member(ko, "bare_key", "state")) != "self-revoked" || !strings.Contains(string(canon.Encode(member(ko, "bare_key", "events"))), "rotated") {
				t.Fatalf("bare-key axis after rotation: %s", canon.Encode(ko))
			}
			// the successor inherits no grant
			if gs := grantsOf(t, jsonOf(t, worker.read("show", succ)), "grants"); len(gs) != 0 {
				t.Fatalf("successor inherited grants: %v", gs)
			}
		})
	}
}

// TestIdentitySliceKeyArgument: show <key> of a key nobody granted (a bare-key store, no rc/2 line) prints the
// bare-key axis and no grants; a key-shaped argument with uppercase hex is malformed (exit 2), never looked up.
func TestIdentitySliceKeyArgument(t *testing.T) {
	w := newWorld(t)
	w.blob("X", []byte("X"))
	w.authored("A", "K", "X")
	r := w.run("show", w.key("K").Signer(), "--json")
	o := jsonOf(t, r)
	if r.code != ExitOK || str(member(o, "bare_key", "state")) != "no key event" || len(grantsOf(t, o, "grants")) != 0 || o.Members["lines"] != canon.Int(1) {
		t.Fatalf("bare key: %d %s", r.code, r.stdout)
	}
	bad := strings.ToUpper(w.key("K").Signer())
	if r := w.run("show", bad, "--json"); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "malformed-argument") {
		t.Fatalf("uppercase key: %d %s", r.code, r.stdout)
	}
}

// TestIdentitySliceCutDropsAnchor (C-id-23), end to end over a synced chain: K holds G (authored any content, and
// anchors of its own log) for I; K's act A for I is covered by K's anchor N for I, verified at height 10. Without a
// cut, show of the blob reads I the sole author and the claimant's time quality bitcoin from N. The root cuts G at
// last_good A: A keeps its authority (I still the sole author, A counted), N is outside A's history (denied,
// cut_excluded), and the bound from N is lost: the claimant's time quality is none. show prints the two outcomes
// as two members, authorship and time.
func TestIdentitySliceCutDropsAnchor(t *testing.T) {
	conformance.Covers(t, "C-id-23")
	w := newWorld(t)
	w.blob("X", []byte("X"))
	w.worker("K")
	i := w.signRC2("I", "IR", "identity_inception", obj("profile", wire.FixedRootProfile), [2]string{})
	perms := canon.Array{obj("kind", "authored", "targets", obj("any_content", true), "amend", true), obj("kind", "anchors")}
	g := w.signRC2("G", "IR", "identity_grant", obj("identity", i, "delegate", obj("key", w.signer("K"), "inception", w.ids["first:K"]), "permissions", perms), [2]string{})
	act := [2]string{i, g}
	a := w.signRC2("A", "K", "authored", licBody("X", "MIT"), act)
	cov, _ := hex.DecodeString(a)
	att := append([]byte{0x00}, btctime.TagBitcoin[:]...)
	payload := uvar(10)
	att = append(att, append(uvar(uint64(len(payload))), payload...)...)
	proof := append(append(append([]byte{}, btctime.HeaderMagic...), 0x01, 0x08), cov...)
	proofBytes := append(proof, att...)
	pd := w.blob("proof:N", proofBytes)
	n := w.signRC2("N", "K", "anchors", obj("covered", a, "proof", pd, "proof_format", btctime.ProofFormat), act)
	w.signRC2("C", "IR", "identity_cut", cutAt(i, g, a), [2]string{})

	raw, tip := testChain(20, map[int64][]byte{10: cov})
	hf := filepath.Join(t.TempDir(), "chain.headers")
	if err := os.WriteFile(hf, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	now := tip.Add(10 * time.Minute)
	useTestChain(t, &now, 0)
	x := dig("X")
	claimant := func(t *testing.T, d *world, env map[string]string) (*canon.Object, *canon.Object) {
		t.Helper()
		r := runIn(d.root, env, "show", x, "--json")
		if r.code != ExitOK {
			t.Fatalf("show blob: %d %s%s", r.code, r.stdout, r.stderr)
		}
		o := jsonOf(t, r)
		cs, _ := o.Members["claimants"].(canon.Array)
		if len(cs) != 1 {
			t.Fatalf("claimants: %s", r.stdout)
		}
		return o, cs[0].(*canon.Object)
	}
	for _, tc := range []struct {
		name    string
		held    []string
		quality string
		anchor  string // the anchor's actor state
	}{
		{"no cut", []string{"first:K", "I", "G", "A", "N"}, "bitcoin", "eligible"},
		{"cut at A", []string{"first:K", "I", "G", "A", "N", "C"}, "none", "denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := holding(t, w, tc.held...)
			d.blob("proof:N", proofBytes) // holding copies statements only; the anchor's proof is a blob
			env := map[string]string{StateDirEnv: t.TempDir()}
			if r := runIn(d.root, env, "anchor", "headers", "sync", "--from", hf, "--json"); r.code != ExitOK {
				t.Fatalf("sync: %d %s", r.code, r.stdout)
			}
			o, c := claimant(t, d, env)
			if str(o.Members["authorship"]) != "sole author" || str(member(c, "time", "quality")) != tc.quality {
				t.Fatalf("authorship %q, time %s:\n%s", str(o.Members["authorship"]), canon.Encode(c.Members["time"]), canon.Encode(o))
			}
			if !strings.Contains(string(canon.Encode(c)), i) {
				t.Fatalf("claimant is not identity I: %s", canon.Encode(c))
			}
			sa := jsonOf(t, runIn(d.root, env, "show", a, "--json"))
			if str(member(sa, "actor", "state")) != "eligible" || str(sa.Members["counted"]) != "counted" {
				t.Fatalf("act: %s", canon.Encode(sa))
			}
			sn := jsonOf(t, runIn(d.root, env, "show", n, "--json"))
			if str(member(sn, "actor", "state")) != tc.anchor {
				t.Fatalf("anchor: %s", canon.Encode(sn))
			}
			if tc.anchor == "denied" && !strings.Contains(string(canon.Encode(member(sn, "actor", "reasons"))), "cut_excluded") {
				t.Fatalf("anchor not cut_excluded: %s", canon.Encode(sn))
			}
		})
	}
}
