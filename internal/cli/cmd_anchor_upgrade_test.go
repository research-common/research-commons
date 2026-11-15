package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// anchor upgrade tests: every calendar is a loopback httptest TLS server reached through the real calendar client;
// nothing else is dialled.

// upCal is a calendar that stamps (POST /digest: a nonce append, sha256, a pending attestation naming itself) and
// upgrades (GET /timestamp/<hex>: the answer set for that commitment, else 404).
type upCal struct {
	srv     *httptest.Server
	uri     string
	nonce   []byte
	mu      sync.Mutex
	answers map[string][]byte // hex commitment -> body
	status  int               // non-zero: every upgrade request answers this status
	posts   atomic.Int64
	gets    atomic.Int64
}

func newUpCal(t *testing.T, name string) *upCal {
	c := &upCal{nonce: []byte("nonce-" + name + "-0123456789")[:16], answers: map[string][]byte{}}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/digest":
			c.posts.Add(1)
			w.Write(c.stampAnswer())
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/timestamp/"):
			c.gets.Add(1)
			c.mu.Lock()
			st := c.status
			b, ok := c.answers[strings.TrimPrefix(r.URL.Path, "/timestamp/")]
			c.mu.Unlock()
			switch {
			case st != 0:
				http.Error(w, "down", st)
			case !ok:
				http.NotFound(w, r)
			default:
				w.Write(b)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	c.uri = c.srv.URL
	t.Cleanup(c.srv.Close)
	return c
}

func (c *upCal) pendingTS() []byte {
	out := append([]byte{0xf0, byte(len(c.nonce))}, c.nonce...)
	out = append(out, 0x08, 0x00)
	out = append(out, btctime.TagPending[:]...)
	return append(out, byte(len(c.uri)+1), byte(len(c.uri)))
}

// stampAnswer is pendingTS with the URI bytes (the attestation payload is varbytes(varbytes(uri))).
func (c *upCal) stampAnswer() []byte { return append(c.pendingTS(), []byte(c.uri)...) }

// commitment is the message at this calendar's pending node for a covered id: sha256(raw id ‖ nonce).
func (c *upCal) commitment(covered string) []byte {
	raw, _ := hex.DecodeString(covered)
	h := sha256.Sum256(append(raw, c.nonce...))
	return h[:]
}

// attest makes the calendar answer covered's commitment with sha256 then a Bitcoin attestation at height; it
// returns the digest the attestation commits to (the header's Merkle root at that height).
func (c *upCal) attest(covered string, height byte) []byte {
	cm := c.commitment(covered)
	root := sha256.Sum256(cm)
	c.mu.Lock()
	c.answers[hex.EncodeToString(cm)] = append(append([]byte{0x08, 0x00}, btctime.TagBitcoin[:]...), 0x01, height)
	c.mu.Unlock()
	return root[:]
}

func (c *upCal) answer(covered string, body []byte) {
	c.mu.Lock()
	c.answers[hex.EncodeToString(c.commitment(covered))] = body
	c.mu.Unlock()
}

func upBuilder(cals ...*upCal) CalendarBuilder {
	tcs := make([]testCal, len(cals))
	for i, c := range cals {
		tcs[i] = testCal{srv: c.srv, hits: &atomic.Int64{}}
	}
	return builder(tcs...)
}

func runUpgrade(root string, b CalendarBuilder, env map[string]string, args ...string) result {
	var o, e bytes.Buffer
	if !slices.Contains(args, "--human") {
		args = append([]string{"--json"}, args...)
	} else {
		args = slices.DeleteFunc(slices.Clone(args), func(a string) bool { return a == "--human" })
	}
	code := Main(append([]string{"anchor", "upgrade"}, args...), &Env{Stdout: &o, Stderr: &e, Getenv: func(k string) string { return env[k] },
		Getwd: func() (string, error) { return root, nil }, Build: Build{Version: "test", Commit: "0000000"}, Calendars: b})
	return result{code, o.String(), e.String()}
}

func (p *pubWorld) upgrade(b CalendarBuilder, args ...string) result {
	return runUpgrade(p.root, b, nil, append([]string{"--key", p.key}, args...)...)
}

func calArgs(cals ...*upCal) []string {
	var a []string
	for _, c := range cals {
		a = append(a, "--calendar", c.uri)
	}
	return append(a, "--allow-private")
}

func headsOf(t *testing.T, r result) []*canon.Object {
	t.Helper()
	var out []*canon.Object
	for _, h := range outObj(t, r).Members["heads"].(canon.Array) {
		out = append(out, h.(*canon.Object))
	}
	return out
}

func proofOf(t *testing.T, p *pubWorld, id string) (*btctime.Proof, []byte) {
	t.Helper()
	d := bodyString(heldStatement(t, p, id).Body, "proof")
	b, err := os.ReadFile(filepath.Join(p.root, "blobs", "sha256", strings.TrimPrefix(d, "sha256:")))
	if err != nil {
		t.Fatal(err)
	}
	pr, err := btctime.ParseProof(b, btctime.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return pr, b
}

// TestAnchorStampMultiCalendar: two calendars answer a stamp: one proof blob holds both pending attestations (a
// union at the root, in the reference writer's order), and services names both.
func TestAnchorStampMultiCalendar(t *testing.T) {
	p, a := stampWorld(t)
	c1, c2 := newUpCal(t, "one"), newUpCal(t, "two")
	r := p.stamp(upBuilder(c1, c2), calArgs(c1, c2)...)
	if r.code != 0 {
		t.Fatalf("stamp: %d %s", r.code, r.stdout)
	}
	an := heldStatement(t, p, idsOf(outObj(t, r))[0])
	if svc := string(canon.Encode(an.Body.Members["services"])); svc != `["`+c1.uri+`","`+c2.uri+`"]` {
		t.Fatalf("services %s", svc)
	}
	pr, b := proofOf(t, p, an.ID)
	raw, _ := hex.DecodeString(a)
	if pr.PendingCount != 2 || !bytes.Equal(pr.FileDigest[:], raw) {
		t.Fatalf("proof: %d pending, digest %x", pr.PendingCount, pr.FileDigest)
	}
	uris := map[string]bool{}
	for _, x := range pr.Pending {
		uris[x.URI] = true
	}
	if !uris[c1.uri] || !uris[c2.uri] {
		t.Fatalf("pending %+v", pr.Pending)
	}
	// the union of the two single-calendar proofs, in canonical order (independent of which answered first)
	f1 := append(append(append(append([]byte{}, btctime.HeaderMagic...), 0x01, 0x08), raw...), c1.stampAnswer()...)
	f2 := append(append(append(append([]byte{}, btctime.HeaderMagic...), 0x01, 0x08), raw...), c2.stampAnswer()...)
	want, err := btctime.UnionProofs([][]byte{f2, f1}, btctime.Limits{})
	if err != nil || !bytes.Equal(b, want) {
		t.Fatalf("blob is not the union: %v", err)
	}
}

// TestAnchorUpgradeEndToEnd: publish → stamp (two loopback calendars) → upgrade. A dry run contacts nothing; while
// every calendar says 404 nothing is appended (exit 0, pending); once one calendar answers with a Bitcoin path, one
// journal record lands: the merged proof (pending attestations kept) and an anchors line {covered: the same head,
// proof, proof_format, services: the calendar that answered} after the old anchor. Then `anchor headers sync` over a
// synthetic chain whose header at that height commits to the proof's digest, and show/verify read the head's bound
// verified at that height, quality bitcoin. A second upgrade finds nothing to do and contacts nothing.
func TestAnchorUpgradeEndToEnd(t *testing.T) {
	// C-btc-03b (a), (b), (d) here; (c), (e) in TestAnchorUpgradeOutcomes. C-btc-03 (stamp before transport) needs
	// the push gate through a command, which is not built.
	conformance.Covers(t, "C-btc-03b")
	const n, height = 20, 10
	now := testChainStart.Add(time.Duration(n+1) * 600 * time.Second)
	useTestChain(t, &now, 0)
	p, a := stampWorld(t)
	c1, c2 := newUpCal(t, "one"), newUpCal(t, "two")
	r := p.stamp(upBuilder(c1, c2), calArgs(c1, c2)...)
	if r.code != 0 {
		t.Fatalf("stamp: %d %s", r.code, r.stdout)
	}
	old := idsOf(outObj(t, r))[0]
	b := upBuilder(c1, c2)

	// dry run: lists both commitments, contacts nothing
	r = p.upgrade(b, append(calArgs(c1, c2), "--dry-run")...)
	if r.code != 0 || c1.gets.Load()+c2.gets.Load() != 0 || !strings.Contains(r.stdout, "would ask") || strings.Count(r.stdout, `"commitment"`) != 2 {
		t.Fatalf("dry run: %d %s", r.code, r.stdout)
	}
	// every calendar still pending: exit 0, pending, nothing appended
	before := snapshot(t, p.root)
	r = p.upgrade(b, calArgs(c1, c2)...)
	hs := headsOf(t, r)
	if r.code != 0 || len(hs) != 1 || hs[0].Members["result"] != canon.String("pending") || hs[0].Members["covered"] != canon.String(a) ||
		outObj(t, r).Members["committed"] != canon.Bool(false) || c1.gets.Load() != 1 || c2.gets.Load() != 1 {
		t.Fatalf("pending: %d %s", r.code, r.stdout)
	}
	if snapshot(t, p.root) != before {
		t.Fatal("a pending upgrade changed the store")
	}
	// calendar two has the Bitcoin path now
	root := c2.attest(a, height)
	r = p.upgrade(b, calArgs(c1, c2)...)
	if r.code != 0 {
		t.Fatalf("upgrade: %d %s", r.code, r.stdout)
	}
	o := outObj(t, r)
	hs = headsOf(t, r)
	sts := statementsOf(o)
	if o.Members["committed"] != canon.Bool(true) || len(sts) != 1 || hs[0].Members["result"] != canon.String("upgraded") ||
		sts[0].Members["prev"] != canon.String(old) || sts[0].Members["kind"] != canon.String("anchors") {
		t.Fatalf("output: %s", r.stdout)
	}
	if _, ok := o.Members["warnings"]; ok {
		t.Fatalf("a still-pending calendar is not a failure: %s", r.stdout)
	}
	nw := heldStatement(t, p, idsOf(o)[0])
	if bodyString(nw.Body, "covered") != a || bodyString(nw.Body, "proof_format") != btctime.ProofFormat ||
		string(canon.Encode(nw.Body.Members["services"])) != `["`+c2.uri+`"]` || nw.Signer != p.signer {
		t.Fatalf("new anchors line: %s", nw.Line())
	}
	pr, _ := proofOf(t, p, nw.ID)
	if len(pr.Bitcoin) != 1 || pr.Bitcoin[0].Height != height || !bytes.Equal(pr.Bitcoin[0].Digest, root) || pr.PendingCount != 2 {
		t.Fatalf("merged proof: %+v", pr)
	}
	// the old anchors line stays
	heldStatement(t, p, old)

	// the reader: sync a chain whose header at `height` commits to the proof's digest, then read the bound
	raw, _ := testChain(n, map[int64][]byte{height: root})
	hf := filepath.Join(t.TempDir(), "chain.headers")
	os.WriteFile(hf, raw, 0o644)
	env := map[string]string{StateDirEnv: t.TempDir()}
	if r := runIn(p.root, env, "anchor", "headers", "sync", "--from", hf, "--json"); r.code != 0 {
		t.Fatalf("sync: %d %s", r.code, r.stdout)
	}
	sh := runIn(p.root, env, "show", nw.ID, "--json")
	tm := string(canon.Encode(jsonOf(t, sh).Members["time"]))
	if !strings.Contains(tm, `"quality":"bitcoin"`) || !strings.Contains(tm, `"time_state":"verified`) {
		t.Fatalf("show of the new anchor: %s", tm)
	}
	cl := string(canon.Encode(jsonOf(t, runIn(p.root, env, "show", dig2("the content"), "--json")).Members["claimants"]))
	if !strings.Contains(cl, `"anchor":"`+nw.ID+`"`) || !strings.Contains(cl, `"quality":"bitcoin"`) {
		t.Fatalf("the head's claimant time: %s", cl)
	}
	// verify of the sole-authored blob passes (a sole author needs no bound); verify of the anchors line reads it
	// verified
	if v := runIn(p.root, env, "verify", dig2("the content"), "--json"); v.code != 0 {
		t.Fatalf("verify blob: %d %s", v.code, v.stdout)
	}
	if v := runIn(p.root, env, "verify", nw.ID, "--json"); !strings.Contains(v.stdout, `"quality":"bitcoin"`) {
		t.Fatalf("verify anchors line: %d %s", v.code, v.stdout)
	}
	// naming the upgraded anchor: already carries a Bitcoin attestation, nothing contacted, exit 0
	gets0 := c1.gets.Load() + c2.gets.Load()
	r = p.upgrade(b, append(calArgs(c1, c2), nw.ID)...)
	if r.code != 0 || !strings.Contains(r.stdout, "already carries a Bitcoin attestation") || c1.gets.Load()+c2.gets.Load() != gets0 {
		t.Fatalf("named upgraded anchor: %d %s", r.code, r.stdout)
	}
	// the human surface prints the outcome per head
	if h := runUpgrade(p.root, b, nil, append([]string{"--human", "--key", p.key, "--dry-run", old}, calArgs(c1, c2)...)...); h.code != 0 ||
		!strings.Contains(h.stdout, "would ask") || !strings.Contains(h.stdout, "dry run") {
		t.Fatalf("human dry run: %d %s", h.code, h.stdout)
	}
	// nothing left to upgrade: no calendar contacted
	gets := c1.gets.Load() + c2.gets.Load()
	r = p.upgrade(b, calArgs(c1, c2)...)
	if r.code != 0 || len(headsOf(t, r)) != 0 || c1.gets.Load()+c2.gets.Load() != gets {
		t.Fatalf("second upgrade: %d %s", r.code, r.stdout)
	}
}

// TestAnchorUpgradeOutcomes: the exits other than success. Every calendar failing (exit 3, nothing appended); a
// pending attestation naming a calendar outside the policy (not contacted, exit 3); a refused answer scoped to its
// calendar beside one that answers (upgraded, services names only the one merged, a warning); naming the old anchor
// explicitly.
func TestAnchorUpgradeOutcomes(t *testing.T) {
	conformance.Covers(t, "C-btc-03b")
	p, a := stampWorld(t)
	c1, c2 := newUpCal(t, "one"), newUpCal(t, "two")
	if r := p.stamp(upBuilder(c1, c2), calArgs(c1, c2)...); r.code != 0 {
		t.Fatalf("stamp: %d %s", r.code, r.stdout)
	}
	b := upBuilder(c1, c2)
	before := snapshot(t, p.root)
	// every calendar fails
	c1.status, c2.status = 500, 503
	r := p.upgrade(b, calArgs(c1, c2)...)
	if r.code != ExitCouldNot || headsOf(t, r)[0].Members["result"] != canon.String("failed") || !strings.Contains(r.stdout, "HTTP 503") {
		t.Fatalf("all fail: %d %s", r.code, r.stdout)
	}
	// only a third calendar in the policy: neither pending attestation names it; nothing contacted
	c3 := newUpCal(t, "three")
	gets := c1.gets.Load() + c2.gets.Load()
	r = p.upgrade(upBuilder(c1, c2, c3), calArgs(c3)...)
	if r.code != ExitCouldNot || strings.Count(r.stdout, "not in local calendar policy") != 2 || c1.gets.Load()+c2.gets.Load()+c3.gets.Load() != gets {
		t.Fatalf("not in policy: %d %s", r.code, r.stdout)
	}
	if snapshot(t, p.root) != before {
		t.Fatal("a failed upgrade changed the store")
	}
	// the env names the policy too; the trailing slash matches
	c1.status, c2.status = 0, 0
	c1.answer(a, []byte{0x08, 0x00, 0x01}) // trailing junk: refused for c1 only
	c2.attest(a, 7)
	r = runUpgrade(p.root, b, map[string]string{CalendarsEnv: c1.uri + "/, " + c2.uri + "/"}, "--key", p.key, "--allow-private")
	o := outObj(t, r)
	if r.code != 0 || o.Members["committed"] != canon.Bool(true) {
		t.Fatalf("one refused, one answered: %d %s", r.code, r.stdout)
	}
	if _, ok := o.Members["warnings"]; !ok || !strings.Contains(r.stdout, `"result":"refused"`) {
		t.Fatalf("no warning or refusal named: %s", r.stdout)
	}
	nw := heldStatement(t, p, idsOf(o)[0])
	if svc := string(canon.Encode(nw.Body.Members["services"])); svc != `["`+c2.uri+`"]` { // the client's URI: one trailing slash dropped, as stamp records it
		t.Fatalf("services %s", svc)
	}
}

// TestAnchorUpgradeExitTwo: refused before anything is dialled or written: no calendar named (naming --calendar and
// the environment variable); the statement named is not an anchors line (the head itself); a statement nobody
// holds; an anchors line whose proof_format is not ots-detached-v1; a calendar URL that is not https.
func TestAnchorUpgradeExitTwo(t *testing.T) {
	p, a := stampWorld(t)
	c1 := newUpCal(t, "one")
	b := upBuilder(c1)
	draft := p.file("anchor.json", `{"kind":"anchors","body":{"covered":"`+a+`","proof":"`+dig2("x")+`","proof_format":"other-v1"}}`)
	r := p.publish("--draft", draft)
	if r.code != 0 {
		t.Fatalf("publish other-format anchors: %d %s", r.code, r.stdout)
	}
	other := idsOf(outObj(t, r))[0]
	before := snapshot(t, p.root)
	for _, c := range []struct {
		name, want string
		args       []string
	}{
		{"no calendar", "--calendar", nil},
		{"not an anchors line", "not an anchors statement", append(calArgs(c1), a)},
		{"not held", "holds no statement", append(calArgs(c1), strings.Repeat("ab", 32))},
		{"other proof format", "not ots-detached-v1", append(calArgs(c1), other)},
		{"http calendar", "not https", []string{"--calendar", "http://cal.test"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := p.upgrade(b, c.args...)
			if r.code != ExitDidNotStart || !strings.Contains(r.stdout+r.stderr, c.want) {
				t.Fatalf("exit %d: %s %s", r.code, r.stdout, r.stderr)
			}
		})
	}
	if r := p.upgrade(b); !strings.Contains(r.stdout+r.stderr, CalendarsEnv) {
		t.Fatalf("no-calendar problem does not name %s: %s", CalendarsEnv, r.stdout+r.stderr)
	}
	if c1.gets.Load() != 0 || snapshot(t, p.root) != before {
		t.Fatal("an exit-2 refusal dialled or wrote")
	}
	// no anchors line at all with no argument: nothing to upgrade, exit 0, nothing contacted
	q, _ := stampWorld(t)
	if r := q.upgrade(b, calArgs(c1)...); r.code != 0 || !strings.Contains(r.stdout, "nothing to upgrade") || c1.gets.Load() != 0 {
		t.Fatalf("nothing to upgrade: %d %s", r.code, r.stdout)
	}
}

// TestAnchorUpgradeTwoHeads: with no argument, every pending head is upgraded: two heads stamped, both answered,
// two new anchors lines in one journal record, the second chained after the first, each naming its own head.
func TestAnchorUpgradeTwoHeads(t *testing.T) {
	p, a := stampWorld(t)
	c1 := newUpCal(t, "one")
	b := upBuilder(c1)
	if r := p.stamp(b, calArgs(c1)...); r.code != 0 {
		t.Fatalf("stamp 1: %d %s", r.code, r.stdout)
	}
	r := p.publish("--kind", "authored", "--content", p.file("d", "more content"), "--no-holds")
	if r.code != 0 {
		t.Fatalf("publish 2: %d %s", r.code, r.stdout)
	}
	a2 := idsOf(outObj(t, r))[0]
	if r := p.stamp(b, calArgs(c1)...); r.code != 0 {
		t.Fatalf("stamp 2: %d %s", r.code, r.stdout)
	}
	c1.attest(a, 5)
	c1.attest(a2, 6)
	r = p.upgrade(b, calArgs(c1)...)
	o := outObj(t, r)
	sts := statementsOf(o)
	if r.code != 0 || len(sts) != 2 || sts[1].Members["prev"] != canon.String(idsOf(o)[0]) || !strings.Contains(r.stdout, `"did":`) ||
		strings.Count(string(canon.Encode(o.Members["did"])), "in one journal record") != 1 {
		t.Fatalf("two heads: %d %s", r.code, r.stdout)
	}
	got := map[string]bool{}
	for _, id := range idsOf(o) {
		got[bodyString(heldStatement(t, p, id).Body, "covered")] = true
	}
	if !got[a] || !got[a2] {
		t.Fatalf("covered heads %v", got)
	}
}
