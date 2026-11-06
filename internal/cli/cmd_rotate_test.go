package cli

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// rotate runs the command with the world's key file.
// rawDescribe signs a describes line with the world's key file and commits it without the writer's checks: how
// a line signed elsewhere (another machine, an older tool) arrives in this store.
func (p *pubWorld) rawDescribe(t *testing.T, note string, seq int64, prev string) string {
	t.Helper()
	k, prob := loadKey(p.key, "test")
	if prob != nil {
		t.Fatal(prob.Title)
	}
	line, id := wire.Sign(wire.Draft{Kind: "describes", Seq: seq, Prev: prev, TS: "2026-10-16T03:00:00Z",
		Body: obj("about", obj("content", dig("a")), "note", note)}, k.Key)
	if _, err := p.s.Commit("publish", [][]byte{line}, nil); err != nil {
		t.Fatal(err)
	}
	return id
}

func (p *pubWorld) rotate(args ...string) result {
	return runIn(p.root, nil, append([]string{"rotate", "--key", p.key, "--json"}, args...)...)
}

// TestRotateE2Vector: the command reproduces the published E2 vector byte for byte. The store holds E1 (the
// Ed25519 log's first line); rotate with the vector's key file, ts and successor signs E2's id and sig.
func TestRotateE2Vector(t *testing.T) {
	v, err := conformance.LoadVectors()
	if err != nil {
		t.Fatal(err)
	}
	var e1, e2 conformance.Vector
	for _, x := range v.EdPositive {
		switch x.Name {
		case "E1":
			e1 = x
		case "E2":
			e2 = x
		}
	}
	if e1.Name == "" || e2.Name == "" {
		t.Fatal("E1/E2 not in the vectors file")
	}
	w := newWorld(t)
	if _, err := w.s.Commit("publish", [][]byte{vectorLine(t, e1)}, nil); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(v.Ed25519Seed)
	key := filepath.Join(t.TempDir(), "e.key")
	if err := os.WriteFile(key, keyFileBytes(wire.AlgEd25519, seed), 0o600); err != nil {
		t.Fatal(err)
	}
	body := vectorBody(t, e2)
	ts := string(body.Members["ts"].(canon.String))
	succ := string(body.Members["body"].(*canon.Object).Members["successor"].(canon.String))
	r := runIn(w.root, nil, "rotate", "--key", key, "--successor", succ, "--ts", ts, "--json")
	if r.code != 0 {
		t.Fatalf("rotate: %d %s", r.code, r.stdout)
	}
	o := outObj(t, r)
	if ids := idsOf(o); len(ids) != 1 || ids[0] != e2.ID {
		t.Fatalf("id %v, want E2 %s: %s", ids, e2.ID, r.stdout)
	}
	lines, err := w.s.Statements()
	if err != nil || lines[e2.ID] == nil {
		t.Fatalf("E2 not held after the rotation: %v", err)
	}
	if got, err := wire.Read(lines[e2.ID]); err != nil || got.Sig != e2.Sig || string(got.SignedString) != e2.SignedString {
		t.Fatalf("E2 differs from the vector: %v", err)
	}
}

// vectorBody parses the PAE body of a vector's signed string.
func vectorBody(t *testing.T, x conformance.Vector) *canon.Object {
	t.Helper()
	parts := strings.SplitN(x.SignedString, " ", 5)
	if len(parts) != 5 {
		t.Fatalf("%s: not a PAE string", x.Name)
	}
	v, err := canon.Parse([]byte(parts[4]))
	if err != nil {
		t.Fatal(err)
	}
	return v.(*canon.Object)
}

// vectorLine is the delivered line of a vector: its body with sig added.
func vectorLine(t *testing.T, x conformance.Vector) []byte {
	t.Helper()
	o := vectorBody(t, x)
	o.Keys = append(o.Keys, "sig")
	o.Members["sig"] = canon.String(x.Sig)
	return canon.Encode(o)
}

// TestRotateAcrossAlgorithms: C-core-144 (a) through the commands. An authored by an Ed25519 key file, a
// rotate_key by that key naming a secp256k1 successor read from its key file (never printed), then an authored by
// the successor: all three verify, the rotation chains after the authored, and the successor's line is its seq 0.
func TestRotateAcrossAlgorithms(t *testing.T) {
	conformance.Partial(t, "C-core-144", "(a) through the commands, one implementation: checked here; (b), (c) and the second Ed25519 library: see the wire and sig tests")
	p := newPubWorld(t) // Ed25519
	succKey, succ := newKeyFile(t, p.dir, wire.AlgEIP191)
	a := p.publish("--kind", "authored", "--content", p.file("a.bin", "old key's bytes"), "--licence", "CC0-1.0", "--description", "a")
	if a.code != 0 {
		t.Fatalf("authored: %d %s", a.code, a.stdout)
	}
	aIDs := idsOf(outObj(t, a)) // the authored and its holds, one unit
	a1, head := aIDs[0], aIDs[len(aIDs)-1]
	r := p.rotate("--successor-key", succKey)
	if r.code != 0 {
		t.Fatalf("rotate: %d %s", r.code, r.stdout)
	}
	if strings.Contains(r.stdout, secretOf(t, succKey)) || strings.Contains(r.stdout, secretOf(t, p.key)) {
		t.Fatal("key material printed")
	}
	o := outObj(t, r)
	s := statementsOf(o)[0]
	rot := string(s.Members["statement"].(canon.String))
	if s.Members["prev"] != canon.String(head) || o.Members["successor"] != canon.String(succ) ||
		!strings.Contains(string(o.Members["successor_log"].(canon.String)), "seq 0") {
		t.Fatalf("rotation: %s", r.stdout)
	}
	b := runIn(p.root, nil, "publish", "--key", succKey, "--json", "--kind", "authored", "--content", p.file("b.bin", "successor's bytes"),
		"--licence", "CC0-1.0", "--description", "b")
	if b.code != 0 || statementsOf(outObj(t, b))[0].Members["seq"] != canon.Int(0) {
		t.Fatalf("successor's first line: %d %s", b.code, b.stdout)
	}
	b1 := idsOf(outObj(t, b))[0]
	for _, id := range []string{a1, rot, b1} {
		if r := p.run("verify", id, "--json"); r.code != 0 {
			t.Fatalf("verify %s: %d %s", keylog.Short(id), r.code, r.stdout)
		}
		if c := counted(t, p, id); c != "counted" {
			t.Fatalf("%s: %s", keylog.Short(id), c)
		}
	}
}

// TestRotateRetiresKey: the CLI half of C-core-127b's variant. After a rotation, a line of the old key after it
// (extending the rotation) and one on a sibling branch (extending an earlier line) count toward nothing; the
// lines in the rotation's history keep counting. A merged fork is in that history. Nothing is rewritten.
func TestRotateRetiresKey(t *testing.T) {
	conformance.Partial(t, "C-core-127b", "rotation through the command: lines of the old key after it or on a sibling branch count toward nothing, its history counts; the gap half (L delivered late) is keylog.TestRotationWaitsForMergedTip")
	p := newPubWorld(t)
	a1 := p.describe(t, "A1")
	a2 := p.describe(t, "A2")
	b := p.describe(t, "B", a1) // a fork: the owner's own second branch, merged by the rotation
	r := p.rotate("--successor", testKey("S").Signer(), "--prev", a2)
	if r.code != 0 {
		t.Fatalf("rotate: %d %s", r.code, r.stdout)
	}
	o := outObj(t, r)
	rot := idsOf(o)[0]
	if !strings.Contains(r.stdout, `"merges"`) || !strings.Contains(r.stdout, b) || o.Members["stop_counting"] != nil {
		t.Fatalf("the fork's other tip should be merged and nothing cut: %s", r.stdout)
	}
	// the writer now refuses both lines (key-already-retired); sign them directly to check the reader's half
	for _, prev := range []string{rot, a2} {
		if r := p.publish("--kind", "describes", "--about", dig("a"), "--note", "late", "--prev", prev); r.code != 1 || !strings.Contains(r.stdout, "key-already-retired") {
			t.Fatalf("publish after the rotation: %d %s", r.code, r.stdout)
		}
	}
	after := p.rawDescribe(t, "after", 3, rot)
	sibling := p.rawDescribe(t, "sibling", 2, a2)
	for id, want := range map[string]string{a1: "counted", a2: "counted", b: "counted", rot: "counted", after: "not counted", sibling: "not counted"} {
		if c := counted(t, p, id); c != want {
			t.Fatalf("%s: %s, want %s", keylog.Short(id), c, want)
		}
	}
}

// TestRotateRefusals: the request alone (exit 2): no successor, both options, the successor is the signing key,
// a successor key file with group-readable mode. Over the held logs (exit 1, reader policy, nothing written): a
// tip carrying a foreign key event (the soft-merge rule, C-core-127c, worded for a rotation); the history
// extended already holding an in-force key event; a successor whose log carries a key event, in force or
// detached. A dry run signs nothing.
func TestRotateRefusals(t *testing.T) {
	conformance.Covers(t, "C-core-127c")
	p := newPubWorld(t)
	a1 := p.describe(t, "A1")
	before := snapshot(t, p.root)
	succKey, succ := newKeyFile(t, p.dir, wire.AlgEIP191)
	loose := filepath.Join(p.dir, "loose.key")
	os.WriteFile(loose, mustRead(t, succKey), 0o640)
	for _, a := range [][]string{{}, {"--successor", succ, "--successor-key", succKey}, {"--successor", p.signer}, {"--successor-key", p.key}, {"--successor-key", loose}} {
		if r := p.rotate(a...); r.code != 2 || snapshot(t, p.root) != before {
			t.Fatalf("%v: exit %d %s", a, r.code, r.stdout)
		}
	}
	// dry run: the would-be line, nothing written
	r := p.rotate("--successor", succ, "--dry-run")
	if o := outObj(t, r); r.code != 0 || o.Members["committed"] != canon.Bool(false) || statementsOf(o)[0].Members["prev"] != canon.String(a1) {
		t.Fatalf("dry run: %d %s", r.code, r.stdout)
	}
	if snapshot(t, p.root) != before {
		t.Fatal("a dry run or refused invocation wrote something")
	}

	t.Run("foreign key event on a tip", func(t *testing.T) {
		p := newPubWorld(t)
		a1 := p.describe(t, "A1")
		a2 := p.describe(t, "A2")
		other := p.rotateFrom(t, a1)
		before := snapshot(t, p.root)
		r := p.rotate("--successor", testKey("S").Signer(), "--prev", a2)
		o := outObj(t, r)
		if r.code != 1 || o.Members["class"] != canon.String("reader policy") || !strings.Contains(string(o.Members["title"].(canon.String)), keylog.SoftMergeKeyEvent) ||
			!strings.Contains(r.stdout, other) || !strings.Contains(string(o.Members["detail"].(canon.String)), "rotation") || snapshot(t, p.root) != before {
			t.Fatalf("exit %d %s", r.code, r.stdout)
		}
	})

	t.Run("key already retired", func(t *testing.T) {
		p := newPubWorld(t)
		p.describe(t, "A1")
		if r := p.rotate("--successor", testKey("S").Signer()); r.code != 0 {
			t.Fatalf("first rotation: %d %s", r.code, r.stdout)
		}
		before := snapshot(t, p.root)
		for _, a := range [][]string{{"--successor", testKey("U").Signer()}, {"--successor", testKey("U").Signer(), "--dry-run"}} {
			r := p.rotate(a...)
			if r.code != 1 || !strings.Contains(r.stdout, "key-already-retired") || !strings.Contains(r.stdout, "rotate_key") || snapshot(t, p.root) != before {
				t.Fatalf("%v: exit %d %s", a, r.code, r.stdout)
			}
		}
		q := newPubWorld(t)
		q.describe(t, "A1")
		if r := q.revoke("--reason", "superseded"); r.code != 0 {
			t.Fatalf("revoke: %d %s", r.code, r.stdout)
		}
		if r := q.rotate("--successor", testKey("U").Signer()); r.code != 1 || !strings.Contains(r.stdout, "revoke_key") {
			t.Fatalf("rotation after a revocation: exit %d %s", r.code, r.stdout)
		}
	})

	t.Run("successor retired", func(t *testing.T) {
		p := newPubWorld(t)
		p.describe(t, "A1")
		sk, s := newKeyFile(t, t.TempDir(), wire.AlgEd25519)
		if r := runIn(p.root, nil, "revoke", "--key", sk, "--reason", "cessation_of_operation", "--json"); r.code != 0 {
			t.Fatalf("successor revoke: %d %s", r.code, r.stdout)
		}
		before := snapshot(t, p.root)
		r := p.rotate("--successor", s)
		if r.code != 1 || !strings.Contains(r.stdout, "successor-retired") || !strings.Contains(r.stdout, "revoke_key") || snapshot(t, p.root) != before {
			t.Fatalf("in force: exit %d %s", r.code, r.stdout)
		}
		// detached: the successor's rotate_key at seq 5, its earlier lines not held here
		z := testKey("Z")
		line, _ := wire.Sign(wire.Draft{Kind: "rotate_key", Seq: 5, Prev: strings.Repeat("ab", 32), TS: "2026-10-16T02:00:00Z",
			Body: obj("successor", testKey("S").Signer())}, z)
		if _, err := p.s.Commit("publish", [][]byte{line}, nil); err != nil {
			t.Fatal(err)
		}
		before = snapshot(t, p.root)
		r = p.rotate("--successor", z.Signer())
		if r.code != 1 || !strings.Contains(r.stdout, "successor-retired") || !strings.Contains(r.stdout, "detached") || snapshot(t, p.root) != before {
			t.Fatalf("detached: exit %d %s", r.code, r.stdout)
		}
	})
}

// TestPublishAfterKeyEvent: once the key's log holds a rotate_key or revoke_key, every writer that would sign an
// ordinary line refuses (exit 1, reader policy, key-already-retired, nothing written): such a line is outside every
// key event's history and counts toward nothing (claims-model note §4.1, C-core-143). That holds for publish from
// options, from a draft, with --dry-run, with --prev on a sibling branch, for publish task, and for a key event
// still detached (in force once its gap fills). A key event itself is not refused here: one signed later counts
// where it is stricter.
func TestPublishAfterKeyEvent(t *testing.T) {
	refused := func(t *testing.T, p *pubWorld, r result, what string) {
		t.Helper()
		o := outObj(t, r)
		if r.code != 1 || o.Members["class"] != canon.String("reader policy") || !strings.Contains(r.stdout, "key-already-retired") {
			t.Fatalf("%s: exit %d %s", what, r.code, r.stdout)
		}
	}
	p := newPubWorld(t)
	a1 := p.describe(t, "A1")
	if r := p.rotate("--successor", testKey("S").Signer()); r.code != 0 {
		t.Fatalf("rotate: %d %s", r.code, r.stdout)
	}
	before := snapshot(t, p.root)
	refused(t, p, p.publish("--kind", "describes", "--about", dig("a"), "--note", "late"), "publish")
	refused(t, p, p.publish("--kind", "describes", "--about", dig("a"), "--note", "late", "--dry-run"), "dry run")
	refused(t, p, p.publish("--kind", "describes", "--about", dig("a"), "--note", "sibling", "--prev", a1), "sibling branch")
	refused(t, p, p.publish("--draft", p.file("d.json", `{"kind":"retracts","body":{"of":"`+a1+`"}}`)), "draft")
	ct := p.file("c.json", `{"profile":"`+resolve.ProvisionalProfile+`","beneficiary":"`+p.signer+`","any_issuer":true}`)
	refused(t, p, runIn(p.root, nil, "publish", "task", "--key", p.key, "--name", "t", "--contract", ct, "--json"), "publish task")
	if snapshot(t, p.root) != before {
		t.Fatal("a refused publish wrote something")
	}
	// a stricter key event after the rotation is still signed: a revoke_key draft
	rv := p.file("rv.json", `{"kind":"revoke_key","body":{"reason":"key_compromise","last_good":"`+a1+`"}}`)
	if r := p.publish("--draft", rv); r.code != 0 {
		t.Fatalf("revoke_key draft after the rotation: %d %s", r.code, r.stdout)
	}

	t.Run("detached key event", func(t *testing.T) {
		p := newPubWorld(t)
		p.describe(t, "A1")
		k, prob := loadKey(p.key, "test")
		if prob != nil {
			t.Fatal(prob.Title)
		}
		line, _ := wire.Sign(wire.Draft{Kind: "revoke_key", Seq: 5, Prev: strings.Repeat("ab", 32), TS: "2026-10-16T02:00:00Z",
			Body: obj("reason", "key_compromise", "last_good", strings.Repeat("ab", 32))}, k.Key)
		if _, err := p.s.Commit("publish", [][]byte{line}, nil); err != nil {
			t.Fatal(err)
		}
		r := p.publish("--kind", "describes", "--about", dig("a"), "--note", "late")
		refused(t, p, r, "detached revoke")
		if !strings.Contains(r.stdout, "detached") {
			t.Fatalf("the refusal should say the event is detached: %s", r.stdout)
		}
	})
}
