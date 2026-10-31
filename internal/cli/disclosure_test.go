package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/run"
	"github.com/research-common/research-commons/internal/store"
)

func disclosureOf(t *testing.T, o *canon.Object, name string) *canon.Object {
	t.Helper()
	ds, ok := o.Members["disclosures"].(*canon.Object)
	if !ok {
		t.Fatalf("no disclosures in %s", canon.Encode(o))
	}
	d, ok := ds.Members[name].(*canon.Object)
	if !ok {
		t.Fatalf("no %s disclosure in %s", name, canon.Encode(ds))
	}
	return d
}

// TestAvailabilitySurfaces: C-core-68 on every surface. Redistribution permitted with bytes not obtainable, and
// the reverse: show, list, verify and explain carry `redistribution` and `obtainable_declared` as two members
// whose values are the declared ones, and the human surface prints both words.
func TestAvailabilitySurfaces(t *testing.T) {
	conformance.Covers(t, "C-core-68")
	for _, c := range []struct {
		red        string
		obtainable bool
	}{{"permitted", false}, {"restricted", true}} {
		w := newWorld(t)
		w.blob("x", []byte("x"))
		w.authored("A", "K1", "x", "availability", obj("redistribution", c.red, "obtainable", c.obtainable))
		d := dig("x")
		list := jsonOf(t, w.run("list", "--json")).Members["blobs"].(canon.Array)[0].(*canon.Object)
		for _, src := range []*canon.Object{list, jsonOf(t, w.run("show", d, "--json")), jsonOf(t, w.run("verify", d, "--json")), jsonOf(t, w.run("explain", d, "--json"))} {
			av := disclosureOf(t, src, "availability")
			if av.Members["redistribution"] != canon.String(c.red) || av.Members["obtainable_declared"] != canon.Bool(c.obtainable) {
				t.Fatalf("%s/%v: %s", c.red, c.obtainable, canon.Encode(av))
			}
		}
		h := w.run("show", d).stdout
		if !strings.Contains(h, "redistribution: "+c.red) || !strings.Contains(h, "obtainable declared: "+map[bool]string{true: "yes", false: "no"}[c.obtainable]) {
			t.Fatalf("human surface:\n%s", h)
		}
	}
}

// TestShelfLifeSurfaces: C-core-74 at the CLI. Without a chain backend no anchor is verified, so the age is
// unknown on every surface (never computed from the signer-declared ts), the declared validity is shown, the
// exit is the same as without a shelf life, and explain's time context says the answer did not use the clock.
// The age from a verified anchor at an injected read time is the resolver's (internal/resolve.TestShelfLifeAge).
func TestShelfLifeSurfaces(t *testing.T) {
	conformance.Partial(t, "C-core-74", "CLI: declared validity with age unknown (no chain backend configured, so no verified time) and the exit unchanged; the 45-days-past case with a verified anchor and an injected read time is the resolver's, since no command configures a chain backend yet")
	withClock(t, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	for _, shelf := range []bool{false, true} {
		w := newWorld(t)
		w.blob("x", []byte("x"))
		kv := []any{}
		if shelf {
			kv = append(kv, "shelf_life_days", 30)
		}
		w.authored("A", "K1", "x", kv...)
		w.anchor("an", "K1", 800000)
		d := dig("x")
		v := w.run("verify", d, "--json")
		if v.code != 0 {
			t.Fatalf("verify %d %s", v.code, v.stdout)
		}
		sl := disclosureOf(t, jsonOf(t, v), "shelf_life_days")
		if !shelf {
			if sl.Members["state"] != canon.String("undeclared") {
				t.Fatalf("%s", canon.Encode(sl))
			}
			continue
		}
		if sl.Members["declared_days"] != canon.Int(30) || !strings.HasPrefix(string(sl.Members["age"].(canon.String)), "unknown") {
			t.Fatalf("%s", canon.Encode(sl))
		}
		e := jsonOf(t, w.run("explain", d, "--json"))
		if tc := string(e.Members["time_context"].(canon.String)); !strings.HasPrefix(tc, "none") {
			t.Fatalf("time context %q: no age was computed", tc)
		}
	}
}

// TestWithheldReveal: C-core-75 and C-core-76 end to end. The author publishes with availability withheld and
// --no-holds; a second store pulls the statements (no bytes). Before the reveal both read `withheld until …`, not
// obtainable, verify 0, not revealed. The author then publishes the holds with a location; the reader pulls it:
// a holds is the holder's word until the bytes are fetched. A fetch that serves other bytes is refused (intrinsic,
// hash mismatch, scoped to that fetch), installs nothing, and the statement still reads withheld, not revealed.
// A fetch of the right bytes installs them and the reader shows revealed. The held-but-no-holds control: the
// author's own store holds the bytes from the start and does not read as revealed.
func TestWithheldReveal(t *testing.T) {
	conformance.Partial(t, "C-core-75", "publish withheld (--no-holds), pull to a second store, reveal by a later holds, fetch by full hash, revealed: covered through the store's fetch, since no `fetch` command exists; the `anchored` half needs an anchor writer (no command writes one yet)")
	conformance.Covers(t, "C-core-76")
	author := newPubWorld(t)
	data := "season seed 0x5eed with a 128-bit nonce 4f1c9a2e7b3d5a60c8e1f2a3b4c5d6e7"
	c := author.file("seed", data)
	d := run.Digest([]byte(data))
	r := author.publish("--kind", "authored", "--content", c, "--no-holds",
		"--availability", `{"obtainable":false,"redistribution":"withheld","withheld_until":"task T edition 2"}`)
	if r.code != 0 {
		t.Fatalf("publish: %d %s", r.code, r.stdout)
	}
	reveal := func(w *world) string {
		t.Helper()
		av := disclosureOf(t, jsonOf(t, w.run("show", d, "--json")), "availability")
		if av.Members["redistribution"] != canon.String("withheld") || av.Members["obtainable_declared"] != canon.Bool(false) ||
			av.Members["withheld_until"] != canon.String("task T edition 2") {
			t.Fatalf("declared value moved: %s", canon.Encode(av))
		}
		return string(av.Members["reveal"].(canon.String))
	}
	// the author's own store holds the bytes but published no holds: not a reveal
	if got := reveal(author.world); !strings.HasPrefix(got, "not revealed: the bytes are held here") {
		t.Fatalf("author: %q", got)
	}
	reader := newWorld(t)
	pull := func() {
		t.Helper()
		pkg := t.TempDir()
		copyData(t, author.root, pkg)
		trashBlobs(t, pkg) // a statements-only package: the bytes stay with the author
		if r := reader.run("pull", pkg, "--json"); r.code != 0 {
			t.Fatalf("pull: %d %s", r.code, r.stdout)
		}
	}
	pull()
	if got := reveal(reader); got != "not revealed: no holds held" {
		t.Fatalf("reader before: %q", got)
	}
	if v := reader.run("verify", d, "--json"); v.code != 0 {
		t.Fatalf("withheld statement does not verify: %d %s", v.code, v.stdout)
	}
	if reader.s.HasBlob(store.Digest(d)) {
		t.Fatal("bytes reached the reader before the reveal")
	}

	// the reveal: a holds by the author naming a location
	loc := "https://author.example/seed"
	hold := author.file("h.json", `{"kind":"holds","body":{"content":{"digest":"`+d+`","size":`+strconv.Itoa(len(data))+`},"locations":["`+loc+`"]}}`)
	if r := author.publish("--draft", hold); r.code != 0 {
		t.Fatalf("holds: %d %s", r.code, r.stdout)
	}
	pull()
	if got := reveal(reader); !strings.HasPrefix(got, "a holds is published (holder's word)") {
		t.Fatalf("reader after holds, before fetch: %q", got)
	}

	// C-core-76: the location serves other bytes of the same length
	wrong := []byte(strings.Replace(data, "0x5eed", "0x5eee", 1))
	before := snapshot(t, reader.root)
	_, err := reader.s.Fetch(store.Digest(d), store.MapTransport{loc: wrong}, store.FetchOptions{})
	var ref *refusal.Refusal
	if !errors.As(err, &ref) || ref.Class != refusal.Intrinsic || ref.Reason != store.HashMismatch || !strings.Contains(ref.Detail, loc) {
		t.Fatalf("mismatch: %v", err)
	}
	if reader.s.HasBlob(store.Digest(d)) || reader.s.HasBlob(store.Digest(run.Digest(wrong))) {
		t.Fatal("bytes installed on a mismatch")
	}
	if after := snapshot(t, reader.root); after != before {
		t.Fatalf("a refused reveal changed the store:\n%v\n%v", before, after)
	}
	if got := reveal(reader); !strings.HasPrefix(got, "a holds is published (holder's word)") {
		t.Fatalf("after a refused fetch: %q", got)
	}
	if v := reader.run("verify", d, "--json"); v.code != 0 {
		t.Fatalf("a refused reveal moved verify: %d", v.code)
	}

	// C-core-75: the right bytes; fetch verifies by full hash and the reader shows revealed
	res, err := reader.s.Fetch(store.Digest(d), store.MapTransport{loc: []byte(data)}, store.FetchOptions{})
	if err != nil || res.State != store.StateFetched {
		t.Fatalf("fetch: %v %+v", err, res)
	}
	if got := reveal(reader); !strings.HasPrefix(got, "revealed:") {
		t.Fatalf("after fetch: %q", got)
	}
}

// TestRetractionEverywhere: C-core-139. The author retracts X; a second key (a mirror) holds X at a location.
// A reader pulls the statements (no bytes): `retracted` is on every surface that lists X (show, list, verify,
// explain), the mirror is still listed as a holder, the fetch from the mirror succeeds, and after the fetch the
// label is still shown (and the reader's copy shows bytes held here).
func TestRetractionEverywhere(t *testing.T) {
	conformance.Partial(t, "C-core-139", "retracted on show, list, verify and explain in a reader store that pulled the statements; the mirror's holds still serves through the store's fetch; `the mirror shows the token` is checked on the reader's view of the mirror's holds, since the hub view of another hub is not a command")
	src := newWorld(t)
	src.blob("x", []byte("x"))
	a := src.authored("A:x", "K1", "x", "licence", "CC0-1.0")
	src.sign("R:x", "K1", "retracts", obj("of", a, "reason", "superseded"))
	loc := "https://mirror.example/x"
	src.sign("H:mirror", "K2", "holds", obj("content", content("x"), "locations", []string{loc}))
	pkg := t.TempDir()
	copyData(t, src.root, pkg)
	trashBlobs(t, pkg)
	reader := newWorld(t)
	if r := reader.run("pull", pkg, "--json"); r.code != 0 {
		t.Fatalf("pull: %d %s", r.code, r.stdout)
	}
	d := dig("x")
	check := func(stage string) {
		t.Helper()
		list := jsonOf(t, reader.run("list", "--json")).Members["blobs"].(canon.Array)
		var listed *canon.Object
		for _, b := range list {
			if o := b.(*canon.Object); o.Members["digest"] == canon.String(d) {
				listed = o
			}
		}
		for name, src := range map[string]*canon.Object{"list": listed, "show": jsonOf(t, reader.run("show", d, "--json")),
			"verify": jsonOf(t, reader.run("verify", d, "--json")), "explain": jsonOf(t, reader.run("explain", d, "--json"))} {
			if src == nil || !strings.Contains(string(canon.Encode(src.Members["labels"])), `"retracted"`) {
				t.Fatalf("%s: %s lacks the retracted label", stage, name)
			}
		}
		show := jsonOf(t, reader.run("show", d, "--json"))
		if !strings.Contains(string(canon.Encode(show.Members["holders"])), src.signer("K2")) {
			t.Fatalf("%s: the mirror is no longer a holder: %s", stage, canon.Encode(show.Members["holders"]))
		}
	}
	check("before fetch")
	res, err := reader.s.Fetch(store.Digest(d), store.MapTransport{loc: []byte("x")}, store.FetchOptions{})
	if err != nil || res.State != store.StateFetched || res.Attempts[0].Holder != src.ids["H:mirror"] {
		t.Fatalf("fetch from the mirror: %v %+v", err, res)
	}
	check("after fetch")
	if !strings.Contains(reader.run("show", d, "--json").stdout, `"bytes":"held here"`) {
		t.Fatal("fetched bytes not held")
	}
}

// trashBlobs drops the blob bytes from a package directory (a test temporary), so a pull carries statements only.
func trashBlobs(t *testing.T, pkg string) {
	t.Helper()
	if err := os.RemoveAll(filepath.Join(pkg, "blobs")); err != nil {
		t.Fatal(err)
	}
}

// TestWithheldShortWarning: C-core-76a. publish with availability withheld: (a) content one byte under the
// documented threshold prints the warning naming the threshold and the enumeration risk, and publication
// proceeds; (b) content at the threshold, and (c) short content that is not withheld, print none. The signed
// statement is the same either way (the warning is never recorded): the body of (a) carries no member the
// body of a withheld publish at the threshold lacks, and verify exits 0 for both.
func TestWithheldShortWarning(t *testing.T) {
	conformance.Partial(t, "C-core-76a", "warning below the threshold, none at it or when not withheld, nothing recorded, verify unchanged; the threshold (64 bytes) is a proposed value awaiting a decision, documented in the claims-model note as a heuristic")
	withheld := `{"obtainable":false,"redistribution":"withheld","withheld_until":"after the season"}`
	cases := []struct {
		name, data, av string
		warn           bool
	}{
		{"under", strings.Repeat("s", WithheldWarnBelow-1), withheld, true},
		{"at", strings.Repeat("s", WithheldWarnBelow), withheld, false},
		{"not withheld", "s", `{"obtainable":true,"redistribution":"permitted"}`, false},
	}
	var bodies []*canon.Object
	for _, c := range cases {
		p := newPubWorld(t)
		r := p.publish("--kind", "authored", "--content", p.file("c", c.data), "--no-holds", "--availability", c.av)
		if r.code != 0 {
			t.Fatalf("%s: publication did not proceed: %d %s", c.name, r.code, r.stdout)
		}
		o := outObj(t, r)
		w, has := o.Members["warnings"]
		switch {
		case c.warn && !has:
			t.Fatalf("%s: no warning\n%s", c.name, r.stdout)
		case !c.warn && has:
			t.Fatalf("%s: unexpected warning %s", c.name, canon.Encode(w))
		case c.warn:
			msg := string(canon.Encode(w))
			for _, s := range []string{"threshold of 64 bytes", "enumerable against its hash", "nonce", "heuristic", "not recorded"} {
				if !strings.Contains(msg, s) {
					t.Fatalf("%s: warning lacks %q: %s", c.name, s, msg)
				}
			}
			if !strings.Contains(p.publishHuman(t, c), "warnings:") {
				t.Fatalf("%s: warning missing on the human surface", c.name)
			}
		}
		d := run.Digest([]byte(c.data))
		if v := p.run("verify", d); v.code != 0 {
			t.Fatalf("%s: verify %d", c.name, v.code)
		}
		st := jsonOf(t, p.run("show", idsOf(o)[0], "--json")).Members["body"].(*canon.Object)
		bodies = append(bodies, st)
	}
	// the warned statement and the unwarned one at the threshold carry the same members
	if strings.Join(bodies[0].Keys, ",") != strings.Join(bodies[1].Keys, ",") {
		t.Fatalf("the warning was recorded: %v vs %v", bodies[0].Keys, bodies[1].Keys)
	}
	for _, k := range bodies[0].Keys {
		if strings.Contains(k, "warn") {
			t.Fatalf("member %q recorded", k)
		}
	}
}

// publishHuman re-runs the withheld publish on the human surface with --dry-run (nothing written).
func (p *pubWorld) publishHuman(t *testing.T, c struct {
	name, data, av string
	warn           bool
}) string {
	t.Helper()
	r := runIn(p.root, nil, "publish", "--key", p.key, "--kind", "authored", "--content", p.file("c2", c.data), "--no-holds", "--availability", c.av, "--dry-run")
	if r.code != 0 {
		t.Fatalf("human dry run: %d %s", r.code, r.stdout)
	}
	return r.stdout
}
