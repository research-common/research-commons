package cli

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/otscal"
	"github.com/research-common/research-commons/internal/wire"
)

// anchor stamp tests: every calendar is a loopback httptest TLS server reached through the real calendar client;
// nothing else is dialled.

// calendarTS is a calendar's bare pending answer: append a nonce, sha256, one pending attestation naming uri.
func calendarTS(uri string) []byte {
	nonce := []byte("nonce-0123456789")
	out := append([]byte{0xf0, byte(len(nonce))}, nonce...)
	out = append(out, 0x08, 0x00)
	out = append(out, btctime.TagPending[:]...)
	return append(out, byte(len(uri)+1), byte(len(uri)))
}

type testCal struct {
	srv  *httptest.Server
	hits *atomic.Int64
}

// newTestCal is a calendar whose handler h answers POST /digest.
func newTestCal(t *testing.T, h func(w http.ResponseWriter, digest []byte)) testCal {
	n := &atomic.Int64{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		b, _ := io.ReadAll(r.Body)
		h(w, b)
	}))
	t.Cleanup(srv.Close)
	return testCal{srv, n}
}

func okCal(t *testing.T) testCal {
	return newTestCal(t, func(w http.ResponseWriter, _ []byte) {
		ts := calendarTS("https://cal.test")
		w.Write(append(ts, []byte("https://cal.test")...))
	})
}

func failCal(t *testing.T) testCal {
	return newTestCal(t, func(w http.ResponseWriter, _ []byte) { http.Error(w, "down", http.StatusInternalServerError) })
}

// builder is the binary's calendar factory with the test servers' certificates trusted.
func builder(cals ...testCal) CalendarBuilder {
	pool := x509.NewCertPool()
	for _, c := range cals {
		pool.AddCert(c.srv.Certificate())
	}
	return func(u string, c CalendarConfig) (btctime.Calendar, error) {
		return otscal.New(u, otscal.Config{AllowPrivate: c.AllowPrivate, Timeout: c.Timeout, RootCAs: pool})
	}
}

func runStamp(root string, b CalendarBuilder, env map[string]string, args ...string) result {
	var o, e bytes.Buffer
	code := Main(append([]string{"anchor", "stamp", "--json"}, args...), &Env{Stdout: &o, Stderr: &e, Getenv: func(k string) string { return env[k] },
		Getwd: func() (string, error) { return root, nil }, Build: Build{Version: "test", Commit: "0000000"}, Calendars: b})
	return result{code, o.String(), e.String()}
}

// stampWorld: a key file and a store holding one authored by it, without provenance and without holds (its
// standing: anchor required).
func stampWorld(t *testing.T) (*pubWorld, string) {
	p := newPubWorld(t)
	r := p.publish("--kind", "authored", "--content", p.file("c", "the content"), "--no-holds")
	if r.code != 0 {
		t.Fatalf("publish: %d %s", r.code, r.stdout)
	}
	return p, idsOf(outObj(t, r))[0]
}

func (p *pubWorld) stamp(b CalendarBuilder, args ...string) result {
	return runStamp(p.root, b, nil, append([]string{"--key", p.key}, args...)...)
}

// diffLines is what after holds that before does not, and what before holds that after does not.
func diffLines(before, after string) (added, removed []string) {
	b, a := map[string]bool{}, map[string]bool{}
	for _, l := range strings.Split(before, "\n") {
		b[l] = true
	}
	for _, l := range strings.Split(after, "\n") {
		a[l] = true
		if !b[l] {
			added = append(added, l)
		}
	}
	for l := range b {
		if !a[l] {
			removed = append(removed, l)
		}
	}
	return
}

func heldStatement(t *testing.T, p *pubWorld, id string) *wire.Statement {
	t.Helper()
	lines, err := p.s.Statements()
	if err != nil {
		t.Fatal(err)
	}
	st, err := wire.ReadStored(lines[id])
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return st
}

// TestAnchorStamp: one calendar answers. One journal record lands: the proof blob, whose bytes are the detached
// file built from the calendar's answer, and one anchors statement {covered, proof, proof_format, services} that
// extends the head; nothing else in the store changes. The reader reads the anchor
// as pending, quality local, through the reader as it is; a second stamp on the same head appends a second line.
func TestAnchorStamp(t *testing.T) {
	p, a := stampWorld(t)
	cal := okCal(t)
	before := snapshot(t, p.root)
	r := p.stamp(builder(cal), "--calendar", cal.srv.URL, "--allow-private")
	if r.code != 0 {
		t.Fatalf("stamp: %d %s", r.code, r.stdout)
	}
	o := outObj(t, r)
	sts := statementsOf(o)
	if o.Members["committed"] != canon.Bool(true) || o.Members["covered"] != canon.String(a) || len(sts) != 1 ||
		sts[0].Members["kind"] != canon.String("anchors") || sts[0].Members["prev"] != canon.String(a) || sts[0].Members["seq"] != canon.Int(1) {
		t.Fatalf("output: %s", r.stdout)
	}
	if _, ok := o.Members["warnings"]; ok {
		t.Fatalf("warnings with every calendar answering: %s", r.stdout)
	}
	raw, _ := hex.DecodeString(a)
	ts := append(calendarTS("https://cal.test"), []byte("https://cal.test")...)
	file := append(append(append(append([]byte{}, btctime.HeaderMagic...), 0x01, 0x08), raw...), ts...)
	h := sha256.Sum256(file)
	proof := "sha256:" + hex.EncodeToString(h[:])
	if o.Members["proof"] != canon.String(proof) {
		t.Fatalf("proof %v, want %s", o.Members["proof"], proof)
	}
	got, err := os.ReadFile(filepath.Join(p.root, "blobs", "sha256", hex.EncodeToString(h[:])))
	if err != nil || !bytes.Equal(got, file) {
		t.Fatalf("proof blob: %v %x", err, got)
	}
	an := heldStatement(t, p, idsOf(o)[0])
	if string(canon.Encode(an.Body)) != `{"covered":"`+a+`","proof":"`+proof+`","proof_format":"ots-detached-v1","services":["`+cal.srv.URL+`"]}` ||
		an.Signer != p.signer || an.Prev != a || an.Seq != 1 {
		t.Fatalf("anchors statement: %s", an.Line())
	}
	added, removed := diffLines(before, snapshot(t, p.root))
	var other []string
	for _, l := range added {
		f := strings.Fields(l)[0]
		switch {
		case f == filepath.Join("blobs", "sha256", hex.EncodeToString(h[:])):
		case strings.HasPrefix(f, filepath.Join("statements", strings.ReplaceAll(p.signer, ":", "-"))) && strings.Contains(f, idsOf(o)[0]):
		default:
			other = append(other, l)
		}
	}
	if len(other) > 0 || len(added) != 2 || len(removed) != 0 {
		t.Fatalf("the store changed beyond the blob and one line:\nadded %v\nremoved %v", added, removed)
	}
	// the reader as it is: pending, quality local
	timeOf := func(cmd, id string) string {
		t.Helper()
		o, _ := canon.Parse(bytes.TrimSpace([]byte(w2(t, p, cmd, id))))
		return string(canon.Encode(o.(*canon.Object).Members["time"]))
	}
	for _, cmd := range []string{"show", "explain"} {
		if tm := timeOf(cmd, an.ID); !strings.Contains(tm, `"quality":"local"`) || !strings.Contains(tm, `"time_state":"pending"`) ||
			!strings.Contains(tm, "a calendar's promise grants nothing") {
			t.Fatalf("%s of the anchors line: %s", cmd, tm)
		}
	}
	claim := func() string {
		o, _ := canon.Parse(bytes.TrimSpace([]byte(w2(t, p, "show", dig2("the content")))))
		return string(canon.Encode(o.(*canon.Object).Members["claimants"]))
	}
	if c := claim(); !strings.Contains(c, `"time":{"anchor":"`+an.ID+`","quality":"local","time_state":"pending"}`) {
		t.Fatalf("the head's claimant time: %s", c)
	}
	// verify of the sole-authored blob: unchanged by a pending anchor (a sole author needs no bound)
	if v := p.run("verify", dig2("the content"), "--json"); v.code != 0 {
		t.Fatalf("verify: %d %s", v.code, v.stdout)
	}
	// a second stamp of the same head (named) appends a second anchors line after the first
	r = p.stamp(builder(cal), "--calendar", cal.srv.URL, "--allow-private", a)
	if r.code != 0 || statementsOf(outObj(t, r))[0].Members["prev"] != canon.String(an.ID) || outObj(t, r).Members["covered"] != canon.String(a) {
		t.Fatalf("second stamp: %d %s", r.code, r.stdout)
	}
	// the reader as it is with two anchors of one head: it reads the bound of the anchor with the lower id
	// (resolve: a deterministic choice among unverified bounds); both stay in the log
	t.Logf("claimant time after a second stamp: %s", claim())
	if cal.hits.Load() != 2 {
		t.Fatalf("calendar hit %d times", cal.hits.Load())
	}
}

func w2(t *testing.T, p *pubWorld, cmd, id string) string {
	t.Helper()
	r := p.run(cmd, id, "--json")
	if r.code == 2 {
		t.Fatalf("%s %s: %s", cmd, id, r.stdout)
	}
	return r.stdout
}

func dig2(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

// TestAnchorStampPartialFailure: one calendar fails, one answers: appended, a warning, services names only the
// calendar that answered, and the failure is named.
func TestAnchorStampPartialFailure(t *testing.T) {
	p, _ := stampWorld(t)
	bad, good := failCal(t), okCal(t)
	r := p.stamp(builder(bad, good), "--calendar", bad.srv.URL, "--calendar", good.srv.URL, "--allow-private")
	if r.code != 0 {
		t.Fatalf("stamp: %d %s", r.code, r.stdout)
	}
	o := outObj(t, r)
	if _, ok := o.Members["warnings"]; !ok || !strings.Contains(r.stdout, "HTTP 500") {
		t.Fatalf("no warning or failure named: %s", r.stdout)
	}
	an := heldStatement(t, p, idsOf(o)[0])
	if svc := canon.Encode(an.Body.Members["services"]); string(svc) != `["`+good.srv.URL+`"]` {
		t.Fatalf("services %s", svc)
	}
}

// TestAnchorStampAllFail: every calendar fails (an HTTP error, an oversize answer, a proof rooted at another
// digest, an answer with no pending attestation, a calendar on loopback without --allow-private): nothing is
// appended (the store byte-identical), exit 3, each failure named, and the head's standing printed: anchor
// required for an authored without provenance, anchor: none for a holds.
func TestAnchorStampAllFail(t *testing.T) {
	other := sha256.Sum256([]byte("another"))
	otherFile := append(append(append(append([]byte{}, btctime.HeaderMagic...), 0x01, 0x08), other[:]...), calendarTS("")...)
	for _, c := range []struct {
		name, want string
		cal        func(t *testing.T) testCal
		private    bool
	}{
		{"HTTP 500", "HTTP 500", failCal, true},
		{"oversize", "over 10000 bytes", func(t *testing.T) testCal {
			return newTestCal(t, func(w http.ResponseWriter, _ []byte) { w.Write(bytes.Repeat([]byte{0}, otscal.MaxResponseBytes+1)) })
		}, true},
		{"rooted at another digest", "rooted at another digest", func(t *testing.T) testCal {
			return newTestCal(t, func(w http.ResponseWriter, _ []byte) { w.Write(otherFile) })
		}, true},
		{"no pending attestation", "no pending attestation", func(t *testing.T) testCal {
			return newTestCal(t, func(w http.ResponseWriter, _ []byte) {
				w.Write(append(append([]byte{0x00}, btctime.TagBitcoin[:]...), 0x01, 0x05))
			})
		}, true},
		{"loopback without --allow-private", "refusing to connect", okCal, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _ := stampWorld(t)
			cal := c.cal(t)
			before := snapshot(t, p.root)
			args := []string{"--calendar", cal.srv.URL}
			if c.private {
				args = append(args, "--allow-private")
			}
			r := p.stamp(builder(cal), args...)
			o := outObj(t, r)
			if r.code != ExitCouldNot || o.Members["committed"] != canon.Bool(false) || !strings.Contains(r.stdout, c.want) {
				t.Fatalf("exit %d: %s", r.code, r.stdout)
			}
			st := o.Members["standing"].(*canon.Object)
			if st.Members["if_every_calendar_fails"] != canon.String("anchor required") || !strings.Contains(string(st.Members["decided_by"].(canon.String)), "without provenance") {
				t.Fatalf("standing: %s", canon.Encode(st))
			}
			if after := snapshot(t, p.root); after != before {
				t.Fatalf("the store changed:\n%s\n%s", before, after)
			}
			if !c.private && cal.hits.Load() != 0 {
				t.Fatal("the dial guard let the request through")
			}
		})
	}
	// a holds head: anchor: none
	p := newPubWorld(t)
	if r := p.publish("--kind", "authored", "--content", p.file("c", "held bytes")); r.code != 0 {
		t.Fatal(r.stdout)
	}
	cal := failCal(t)
	r := p.stamp(builder(cal), "--calendar", cal.srv.URL, "--allow-private")
	st := outObj(t, r).Members["standing"].(*canon.Object)
	if r.code != ExitCouldNot || st.Members["if_every_calendar_fails"] != canon.String("anchor: none") {
		t.Fatalf("holds head: %d %s", r.code, r.stdout)
	}
	// human surface names the standing too
	h := runStamp(p.root, builder(cal), nil, "--key", p.key, "--calendar", cal.srv.URL, "--allow-private")
	if !strings.Contains(h.stdout, "anchor: none") || h.code != ExitCouldNot {
		t.Fatalf("human: %d %s", h.code, h.stdout)
	}
}

// TestAnchorStampExitTwo: refused before anything is dialled or written: no calendar named; a non-https calendar; a
// calendar named twice; a URL with a query; a covered id of another key; an id nobody holds. Dry run and a build
// without calendars dial nothing either.
func TestAnchorStampExitTwo(t *testing.T) {
	p, a := stampWorld(t)
	cal := okCal(t)
	b := builder(cal)
	other := p.sign("O", "K7", "describes", obj("about", canon.Value(obj("content", dig("x"))), "note", "x"))
	before := snapshot(t, p.root)
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"no calendar", nil, "no-calendar"},
		{"http calendar", []string{"--calendar", strings.Replace(cal.srv.URL, "https", "http", 1)}, "calendar-refused"},
		{"twice", []string{"--calendar", cal.srv.URL, "--calendar", cal.srv.URL}, "calendar-refused"},
		{"query", []string{"--calendar", cal.srv.URL + "/?x=1"}, "calendar-refused"},
		{"another key's statement", []string{"--calendar", cal.srv.URL, "--allow-private", other}, "another key"},
		{"not held", []string{"--calendar", cal.srv.URL, "--allow-private", strings.Repeat("ab", 32)}, "no statement with this id"},
	} {
		r := p.stamp(b, c.args...)
		if r.code != ExitDidNotStart || !strings.Contains(r.stdout, c.want) {
			t.Fatalf("%s: %d %s", c.name, r.code, r.stdout)
		}
	}
	if snapshot(t, p.root) != before || cal.hits.Load() != 0 {
		t.Fatalf("a refused invocation dialled (%d) or wrote", cal.hits.Load())
	}
	// the environment names calendars when no option does (comma or space separated); dry run dials nothing
	r := runStamp(p.root, b, map[string]string{CalendarsEnv: cal.srv.URL + ", https://second.cal.test"}, "--key", p.key, "--dry-run")
	o := outObj(t, r)
	if r.code != 0 || o.Members["committed"] != canon.Bool(false) || o.Members["covered"] != canon.String(a) ||
		len(o.Members["calendars"].(canon.Array)) != 2 || !strings.Contains(r.stdout, "anchor required") {
		t.Fatalf("dry run: %d %s", r.code, r.stdout)
	}
	if snapshot(t, p.root) != before || cal.hits.Load() != 0 {
		t.Fatal("dry run dialled or wrote")
	}
	// a build without a calendar client: an http calendar is still refused before anything else (exit 2), and an
	// https one answers that calendars are not available here (exit 3)
	if r := runStamp(p.root, nil, nil, "--key", p.key, "--calendar", "http://cal.test"); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "calendar-refused") {
		t.Fatalf("http calendar, no client: %d %s", r.code, r.stdout)
	}
	r = runStamp(p.root, nil, nil, "--key", p.key, "--calendar", cal.srv.URL)
	if r.code != ExitCouldNot || !strings.Contains(r.stdout, "not available in this build") || snapshot(t, p.root) != before {
		t.Fatalf("no calendars in the build: %d %s", r.code, r.stdout)
	}
}

// TestAnchorStampFork: a forked log is refused without --prev (exit 3, nothing dialled); a named head on one branch
// extends that branch's tip; --prev naming a line whose history lacks the head is refused (exit 2).
func TestAnchorStampFork(t *testing.T) {
	p, a := stampWorld(t)
	cal := okCal(t)
	b := builder(cal)
	r1 := p.publish("--kind", "describes", "--about", a, "--note", "one")
	r2 := p.publish("--kind", "describes", "--about", a, "--note", "two", "--prev", a)
	if r1.code != 0 || r2.code != 0 {
		t.Fatalf("fork: %s %s", r1.stdout, r2.stdout)
	}
	t1, t2 := idsOf(outObj(t, r1))[0], idsOf(outObj(t, r2))[0]
	if r := p.stamp(b, "--calendar", cal.srv.URL, "--allow-private"); r.code != ExitCouldNot || cal.hits.Load() != 0 {
		t.Fatalf("forked log without --prev: %d %s", r.code, r.stdout)
	}
	if r := p.stamp(b, "--calendar", cal.srv.URL, "--allow-private", t1, "--prev", t2); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "head-not-in-prefix") {
		t.Fatalf("head outside --prev's history: %d %s", r.code, r.stdout)
	}
	r := p.stamp(b, "--calendar", cal.srv.URL, "--allow-private", t2)
	if r.code != 0 || statementsOf(outObj(t, r))[0].Members["prev"] != canon.String(t2) {
		t.Fatalf("named head on a branch: %d %s", r.code, r.stdout)
	}
}
