package cli

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write(b)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return z.Bytes()
}

// TestPullReadsContent: pull gives edition rules the package's blob bytes, as `hub check` does. A statement recording
// intended_for outcome ok over a tar.gz whose member holds the forbidden key is re-applied at pull as `fail`
// (the old behaviour was `unchecked`: content not held); over a clean tar.gz it is `ok`; over a blob the package does not
// carry and the store does not hold, `unchecked`. The same package pulled by two readers differs only in what each holds.
func TestPullReadsContent(t *testing.T) {
	withDialect(t)
	src := newPubWorld(t)
	g, e := src.collection("FORBID secret")
	bad := gzipBytes(t, tarOf(t, [2]string{"a.json", `{"ok":1}`}, [2]string{"b.json", `{"secret":1}`}))
	good := gzipBytes(t, tarOf(t, [2]string{"a.json", `{"ok":1}`}, [2]string{"b.json", `{"fine":1}`}))
	missing := gzipBytes(t, tarOf(t, [2]string{"c.json", `{"secret":2}`}))
	claim := func() *canon.Object { return obj("resource", g, "edition", e, "edition_applied", e, "outcome", "ok") }
	src.blob("bad", bad)
	src.blob("good", good)
	src.authored("Abad", "K1", string(bad), "intended_for", claim())
	src.authored("Agood", "K1", string(good), "intended_for", claim())
	src.authored("Amissing", "K1", string(missing), "intended_for", claim()) // its blob is never installed in src

	blobs, stmts := dataObjects(t, src.root)
	objs := [][2]string{{"rc-store", ""}}
	for _, o := range append(blobs, stmts...) {
		objs = append(objs, [2]string{o, ""})
	}
	for _, gz := range []bool{false, true} {
		pkg := tarPackage(t, src.root, objs, gz)
		dst := newWorld(t)
		r := dst.run("pull", pkg, "--dry-run", "--json")
		if r.code != 0 {
			t.Fatalf("gz=%v: exit %d\n%s", gz, r.code, r.stdout)
		}
		rows := map[string]string{}
		objsOut, _ := jsonOf(t, r).Members["objects"].(canon.Array)
		for _, row := range objsOut {
			ro := row.(*canon.Object)
			id, _ := ro.Members["id"].(canon.String)
			rows[string(id)] = string(canon.Encode(ro))
		}
		for _, name := range []string{"Abad", "Agood", "Amissing"} {
			if rows[src.ids[name]] == "" {
				t.Fatalf("gz=%v: no labelled row for %s: %v", gz, name, r.stdout)
			}
		}
		if got := rows[src.ids["Abad"]]; !strings.Contains(got, ": fail;") {
			t.Fatalf("gz=%v: forbidden key inside the pulled tar.gz was not found by the rule:\n%s", gz, got)
		}
		if got := rows[src.ids["Agood"]]; !strings.Contains(got, ": ok;") || strings.Contains(got, ": fail;") {
			t.Fatalf("gz=%v: clean tar.gz: %s", gz, got)
		}
		if got := rows[src.ids["Amissing"]]; !strings.Contains(got, ": unchecked;") {
			t.Fatalf("gz=%v: blob neither carried nor held: %s", gz, got)
		}
	}

	// a blob the store already holds is read from the store when the package does not carry it
	var rest [][2]string
	for _, o := range objs {
		if !strings.HasSuffix(o[0], strings.TrimPrefix(dig(string(bad)), "sha256:")) {
			rest = append(rest, o)
		}
	}
	dst := newWorld(t)
	dst.blob("bad", bad)
	r := dst.run("pull", tarPackage(t, src.root, rest, false), "--dry-run", "--json")
	if !strings.Contains(r.stdout, ": fail;") {
		t.Fatalf("held blob not read: exit %d\n%s", r.code, r.stdout)
	}
}

// TestGateRuleOutcomeIsTyped: C-core-132 on the gate. The receiver's re-application of a statement's intended_for
// is a typed member of the report row, `intended_for` with a `named` and (when the resource has a current
// edition) a `current` object, each carrying a `state` token that is one of ok, fail, unchecked, and the one-line human
// row prints the same two words beside the labels; the publisher's recorded outcome is a separate member (`publisher_said`) the
// sweep does not read as a state, so a publisher that claims `ok` over bytes that fail still reads `fail`. A rule
// that could not read its content reads `unchecked`, never ok. The label detail keeps its prose.
func TestGateRuleOutcomeIsTyped(t *testing.T) {
	conformance.Partial(t, "C-core-132", "the gate's intended_for re-application is a typed state member of the report row (this test); the case's whole surface sweep is TestClosedVocabulary")
	withDialect(t)
	src := newPubWorld(t)
	g, e := src.collection("FORBID secret")
	bad := gzipBytes(t, tarOf(t, [2]string{"b.json", `{"secret":1}`}))
	good := gzipBytes(t, tarOf(t, [2]string{"b.json", `{"fine":1}`}))
	missing := gzipBytes(t, tarOf(t, [2]string{"c.json", `{"secret":2}`}))
	claim := func() *canon.Object { return obj("resource", g, "edition", e, "edition_applied", e, "outcome", "ok") }
	src.blob("bad", bad)
	src.blob("good", good)
	src.authored("Abad", "K1", string(bad), "intended_for", claim()) // the publisher says ok over bytes that fail
	src.authored("Agood", "K1", string(good), "intended_for", claim())
	src.authored("Amissing", "K1", string(missing), "intended_for", claim())
	want := map[string]string{"Abad": "fail", "Agood": "ok", "Amissing": "unchecked"}

	blobs, stmts := dataObjects(t, src.root)
	objs := [][2]string{{"rc-store", ""}}
	for _, o := range append(blobs, stmts...) {
		objs = append(objs, [2]string{o, ""})
	}
	pkg := tarPackage(t, src.root, objs, false)
	dst := newWorld(t)
	r := dst.run("pull", pkg, "--dry-run", "--json")
	toks := map[string]string{}
	collect(jsonOf(t, r), "", toks)
	for p, v := range toks {
		if !IsToken(v) {
			t.Errorf("%s = %q is not in the closed vocabulary", p, v)
		}
	}
	rows := map[string]*canon.Object{}
	for _, row := range jsonOf(t, r).Members["objects"].(canon.Array) {
		ro := row.(*canon.Object)
		id, _ := ro.Members["id"].(canon.String)
		rows[string(id)] = ro
	}
	human := dst.run("pull", pkg, "--dry-run").stdout
	for name, state := range want {
		ro := rows[src.ids[name]]
		if ro == nil {
			t.Fatalf("%s: no row", name)
		}
		io, ok := ro.Members["intended_for"].(*canon.Object)
		if !ok {
			t.Fatalf("%s: the row has no typed intended_for member: %s", name, canon.Encode(ro))
		}
		named, _ := io.Members["named"].(*canon.Object)
		if named == nil || named.Members["state"] != canon.String(state) {
			t.Fatalf("%s: named state %v, want %s", name, named, state)
		}
		// the collection's current edition is the one the statement names: the second computation agrees
		cur, _ := io.Members["current"].(*canon.Object)
		if cur == nil || cur.Members["state"] != canon.String(state) || cur.Members["edition"] != named.Members["edition"] {
			t.Fatalf("%s: current %v, want state %s on the same edition", name, cur, state)
		}
		if io.Members["publisher_said"] != canon.String("ok") {
			t.Fatalf("%s: the publisher's word is not carried apart: %s", name, canon.Encode(io))
		}
		if !strings.Contains(human, "id: "+src.ids[name]) || !strings.Contains(humanRow(human, src.ids[name]), "intended for named: "+state+" · intended for current: "+state) {
			t.Fatalf("%s: the human row does not print both states as `%s`:\n%s", name, state, human)
		}
		// the prose label detail is still there
		if !strings.Contains(string(canon.Encode(ro.Members["label_details"])), "this receiver's computation") {
			t.Fatalf("%s: the label detail lost its prose", name)
		}
	}
}

// humanRow is the one human line of the gate report that names id.
func humanRow(report, id string) string {
	for _, l := range strings.Split(report, "\n") {
		if strings.Contains(l, "id: "+id) {
			return l
		}
	}
	return ""
}

// TestGateRuleOutcomeResourceNotHeld: C-core-132 on the gate, the unread case. A statement whose intended_for names
// a resource the receiver does not hold (the package carries the statement and its bytes, not the collection) was
// not evaluated at all: the typed member reads `unchecked`, never ok and never the publisher's `ok`.
func TestGateRuleOutcomeResourceNotHeld(t *testing.T) {
	conformance.Partial(t, "C-core-132", "the gate's intended_for outcome when the resource is not held is `unchecked` (this test)")
	withDialect(t)
	src := newPubWorld(t)
	g, e := src.collection("FORBID secret")
	good := gzipBytes(t, tarOf(t, [2]string{"b.json", `{"fine":1}`}))
	src.blob("good", good)
	id := src.authored("Agood", "K1", string(good), "intended_for", obj("resource", g, "edition", e, "edition_applied", e, "outcome", "ok"))
	pkg := t.TempDir()
	rel := stmtPath(src.world.signer("K1"), id)
	os.WriteFile(filepath.Join(pkg, "rc-store"), mustRead(t, filepath.Join(src.root, "rc-store")), 0o644)
	os.MkdirAll(filepath.Join(pkg, filepath.Dir(rel)), 0o755)
	os.WriteFile(filepath.Join(pkg, rel), mustRead(t, filepath.Join(src.root, rel)), 0o644)
	r := newWorld(t).run("pull", pkg, "--dry-run", "--json")
	var ro *canon.Object
	for _, row := range jsonOf(t, r).Members["objects"].(canon.Array) {
		if o := row.(*canon.Object); o.Members["id"] == canon.String(id) {
			ro = o
		}
	}
	if ro == nil {
		t.Fatalf("no row: %s", r.stdout)
	}
	io, _ := ro.Members["intended_for"].(*canon.Object)
	named, _ := io.Members["named"].(*canon.Object)
	if named == nil || named.Members["state"] != canon.String("unchecked") || io.Members["publisher_said"] != canon.String("ok") {
		t.Fatalf("an unheld resource: %s", canon.Encode(ro))
	}
	if _, has := io.Members["current"]; has {
		t.Fatalf("a current edition for a resource not held: %s", canon.Encode(io))
	}
}

// TestGateCompletenessOutcomeIsTyped: C-core-132 on the gate, the refuse_incomplete half. A receiver whose policy
// sets selection.refuse_incomplete judges a pulled edition's completeness claim: a failing claim is refused, one
// that holds is admitted and labelled, one that cannot be read is undecided; each row carries the check as a typed
// `completeness` member whose `state` is ok, fail or unchecked (the same member `show` prints on the resource
// view), and the one-line human row prints the same word.
func TestGateCompletenessOutcomeIsTyped(t *testing.T) {
	conformance.Partial(t, "C-core-132", "the gate's completeness check (refuse_incomplete) is a typed state member of the report row (this test)")
	const station = "urn:example:station-7"
	scope := obj("class", "phenomenon", "source", station, "window", obj("from", "2026-01-01T00:00:00Z", "to", "2026-02-01T00:00:00Z"))
	// each case is its own source (the check reads every reading the evaluated set holds): the readings it holds,
	// the readings the edition lists
	cases := []struct {
		name, state, verdict string
		listed               int  // how many of the positioned readings the edition lists
		noPosition           bool // the source also holds a reading with no time position
	}{
		{"fails", "fail", "refused", 1, false},
		{"holds", "ok", "admitted and labelled", 2, false},
		{"unchecked", "unchecked", "could not check", 2, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := newWorld(t)
			reading := func(name, n, x, at string) string {
				ref := obj("instrument", station, "location", "geo:39.74,-104.99")
				if at != "" {
					ref = obj("instrument", station, "location", "geo:39.74,-104.99", "at", at)
				}
				return src.sign(name, n, "observed", obj("content", canon.Value(content(x)), "class", "phenomenon",
					"referent", canon.Value(ref), "capture", canon.Value(obj("at", "2026-02-02T00:00:00Z", "evidence", "self-asserted"))))
			}
			ms := []string{reading("R1", "O1", "jan-03", "2026-01-03T12:00:00Z"), reading("R2", "O2", "jan-20", "2026-01-20T12:00:00Z")}
			if c.noPosition {
				reading("R3", "O3", "nowhere", "")
			}
			g := src.genesisOf("G", "A", 0, "A")
			var a canon.Array
			for _, m := range ms[:c.listed] {
				a = append(a, obj("statement", m, "role", "member"))
			}
			ed, _ := src.approve("E", "A", obj("resource", g, "predecessors", []string{g},
				"contents", obj("members", canon.Value(a), "selection", "completeness", "completeness", canon.Value(scope))))
			_ = ed
			blobs, stmts := dataObjects(t, src.root)
			objs := [][2]string{{"rc-store", ""}}
			for _, o := range append(blobs, stmts...) {
				objs = append(objs, [2]string{o, ""})
			}
			pkg := tarPackage(t, src.root, objs, false)
			dst := newWorld(t)
			if err := os.WriteFile(filepath.Join(dst.root, PolicyFile), []byte(`{"policy":"rc-hub-policy/1","selection":{"refuse_incomplete":true}}`), 0o644); err != nil {
				t.Fatal(err)
			}
			r := dst.run("pull", pkg, "--dry-run", "--json")
			toks := map[string]string{}
			collect(jsonOf(t, r), "", toks)
			for p, v := range toks {
				if !IsToken(v) {
					t.Errorf("%s = %q is not in the closed vocabulary", p, v)
				}
			}
			var ro *canon.Object
			for _, row := range jsonOf(t, r).Members["objects"].(canon.Array) {
				if o := row.(*canon.Object); o.Members["id"] == canon.String(src.ids["E"]) {
					ro = o
				}
			}
			if ro == nil {
				t.Fatalf("no row for the edition: %s", r.stdout)
			}
			co, _ := ro.Members["completeness"].(*canon.Object)
			if co == nil || co.Members["state"] != canon.String(c.state) || ro.Members["verdict"] != canon.String(c.verdict) {
				t.Fatalf("want %s / %s, row %s", c.verdict, c.state, canon.Encode(ro))
			}
			human := dst.run("pull", pkg, "--dry-run").stdout
			if !strings.Contains(humanRow(human, src.ids["E"]), "completeness state: "+c.state) {
				t.Fatalf("the human row lacks `completeness state: %s`:\n%s", c.state, human)
			}
		})
	}
}
