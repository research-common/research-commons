package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

// gateReportRun is one gate report (pull or hub check) as `--json` printed it.
type gateReportRun struct {
	name string
	rep  *canon.Object
}

// gateReportWorlds runs the gates over every world whose rows carry an evaluation: the intended_for
// re-application (ok, fail, unchecked), the completeness check (fail, ok, unchecked), the series boundary
// (flagged, unchecked), the trust floor with an override, the actor label of hub check (eligible, denied,
// unknown), and the contested fixture on both gates. Each is the gate's own report, exit code not asserted: the
// sweep reads the report, whatever it decided.
func gateReportWorlds(t *testing.T) []gateReportRun {
	t.Helper()
	var out []gateReportRun
	add := func(name string, r result) {
		out = append(out, gateReportRun{name, jsonOf(t, r)})
	}
	pullPkg := func(root string) string {
		blobs, stmts := dataObjects(t, root)
		objs := [][2]string{{"rc-store", ""}}
		for _, o := range append(blobs, stmts...) {
			objs = append(objs, [2]string{o, ""})
		}
		return tarPackage(t, root, objs, false)
	}

	// intended_for: the publisher says ok over bytes that fail / hold / cannot be read
	withDialect(t)
	src := newPubWorld(t)
	g, e := src.collection("FORBID secret")
	bad := gzipBytes(t, tarOf(t, [2]string{"b.json", `{"secret":1}`}))
	good := gzipBytes(t, tarOf(t, [2]string{"b.json", `{"fine":1}`}))
	missing := gzipBytes(t, tarOf(t, [2]string{"c.json", `{"secret":2}`}))
	claim := func() *canon.Object { return obj("resource", g, "edition", e, "edition_applied", e, "outcome", "ok") }
	src.blob("bad", bad)
	src.blob("good", good)
	src.authored("Abad", "K1", string(bad), "intended_for", claim())
	src.authored("Agood", "K1", string(good), "intended_for", claim())
	src.authored("Amissing", "K1", string(missing), "intended_for", claim())
	add("pull intended_for", newWorld(t).run("pull", pullPkg(src.root), "--dry-run", "--json"))

	// completeness: refuse_incomplete over an edition that fails, holds, cannot be read
	const station = "urn:example:station-7"
	scope := obj("class", "phenomenon", "source", station, "window", obj("from", "2026-01-01T00:00:00Z", "to", "2026-02-01T00:00:00Z"))
	for _, c := range []struct {
		name       string
		listed     int
		noPosition bool
	}{{"fails", 1, false}, {"holds", 2, false}, {"unchecked", 2, true}} {
		cs := newWorld(t)
		reading := func(name, n, x, at string) string {
			ref := obj("instrument", station, "location", "geo:39.74,-104.99")
			if at != "" {
				ref = obj("instrument", station, "location", "geo:39.74,-104.99", "at", at)
			}
			return cs.sign(name, n, "observed", obj("content", canon.Value(content(x)), "class", "phenomenon",
				"referent", canon.Value(ref), "capture", canon.Value(obj("at", "2026-02-02T00:00:00Z", "evidence", "self-asserted"))))
		}
		ms := []string{reading("R1", "O1", "jan-03", "2026-01-03T12:00:00Z"), reading("R2", "O2", "jan-20", "2026-01-20T12:00:00Z")}
		if c.noPosition {
			reading("R3", "O3", "nowhere", "")
		}
		gen := cs.genesisOf("G", "A", 0, "A")
		var a canon.Array
		for _, m := range ms[:c.listed] {
			a = append(a, obj("statement", m, "role", "member"))
		}
		cs.approve("E", "A", obj("resource", gen, "predecessors", []string{gen},
			"contents", obj("members", canon.Value(a), "selection", "completeness", "completeness", canon.Value(scope))))
		dst := newWorld(t)
		if err := os.WriteFile(filepath.Join(dst.root, PolicyFile), []byte(`{"policy":"rc-hub-policy/1","selection":{"refuse_incomplete":true}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		add("pull completeness "+c.name, dst.run("pull", pullPkg(cs.root), "--dry-run", "--json"))
	}

	// the series boundary on the gate
	ssrc, prof, pd := settlementPackage(t)
	for _, pin := range []bool{true, false} {
		dst := newWorld(t)
		pol := `{"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":true}}`
		if pin {
			dst.blob("profile", prof)
			pol = profilePin(pd)
		}
		os.WriteFile(filepath.Join(dst.root, PolicyFile), []byte(pol), 0o644)
		name := "pull series unpinned"
		if pin {
			name = "pull series pinned"
		}
		add(name, dst.run("pull", ssrc.root, "--json"))
	}

	// the trust floor: refuse, label, an override naming Z (and the tampered line, which stays refused)
	psrc, _, pkg, zPath, badPath := pullWorld(t)
	pf := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(pf, []byte(readerPolicyDoc(sortedKeys(psrc.signer("K1"), psrc.signer("Y"))...)), 0o644)
	_, d1, _, _, _ := pullWorld(t)
	add("pull trust floor refuse", d1.run("pull", pkg, "--policy", pf, "--below-floor", "refuse", "--json"))
	_, d2, _, _, _ := pullWorld(t)
	add("pull trust floor label", d2.run("pull", pkg, "--policy", pf, "--json"))
	_, d3, _, _, _ := pullWorld(t)
	add("pull trust floor override", d3.run("pull", pkg, "--policy", pf, "--below-floor", "refuse", "--override", "zok="+zPath+","+badPath, "--json"))

	// the contested fixture on both gates (every kind of row the fixture has: anchors, forks, detached lines)
	fx := fixture(t)
	add("pull fixture", newWorld(t).run("pull", fx.pkgDir(), "--dry-run", "--json"))
	add("hub check fixture", fx.run("hub", "check", "--json"))

	// hub check's actor label
	pos, _ := vectorChain(t, "ed")
	for _, c := range []struct {
		name string
		base []string
		add  string
	}{
		{"eligible", []string{"worker-genesis", "inception", "grant"}, "authored"},
		{"denied", []string{"worker-genesis", "inception", "grant", "authored", "cut-last-good"}, "authored-amends"},
		{"unknown", []string{"worker-genesis", "inception"}, "authored"},
	} {
		var base []string
		for _, n := range c.base {
			base = append(base, pos[n].Line)
		}
		w := commitLines(t, base...)
		w.gitHub()
		gitIn(t, w.root, "checkout", "-q", "-b", "change")
		a := pos[c.add]
		rel := stmtPath(a.Signer, a.ID)
		os.MkdirAll(filepath.Dir(filepath.Join(w.root, rel)), 0o755)
		os.WriteFile(filepath.Join(w.root, rel), []byte(a.Line), 0o644)
		gitIn(t, w.root, "add", "-A")
		gitIn(t, w.root, "commit", "-q", "-m", "an act")
		add("hub check actor "+c.name, w.run("hub", "check", "--base", "main", "--json"))
	}
	return out
}

// gateProseAllowed are the report-row members that carry a peer's own outcome word, not this tool's: what the
// publisher recorded in its intended_for (the receiver's re-application is the typed `named`/`current` beside it).
var gateProseAllowed = map[string]bool{".objects[].intended_for.publisher_said": true}

// gateProseBeside are the row members whose prose may name an outcome word, but only a word one of the row's typed
// state members carries (the label detail and the refusal detail restate the evaluation in a sentence beside it).
var gateProseBeside = map[string]bool{".objects[].label_details[]": true, ".objects[].detail": true}

// rowStates is every outcome word the typed members of one gate row carry: the rule re-application (named,
// current, each evaluation, and the publisher's recorded word beside them), the completeness check and the series
// boundary comparison.
func rowStates(row *canon.Object) map[string]bool {
	out := map[string]bool{}
	state := func(v canon.Value) {
		if o, ok := v.(*canon.Object); ok {
			if s, ok := o.Members["state"].(canon.String); ok {
				out[string(s)] = true
			}
		}
	}
	if io, ok := row.Members["intended_for"].(*canon.Object); ok {
		if said, ok := io.Members["publisher_said"].(canon.String); ok {
			out[string(said)] = true // the publisher's own word, typed apart from the receiver's states
		}
		state(io.Members["named"])
		state(io.Members["current"])
		if evs, ok := io.Members["evaluations"].(canon.Array); ok {
			for _, e := range evs {
				state(e)
			}
		}
	}
	state(row.Members["completeness"])
	state(row.Members["series_boundary"])
	return out
}

// gateProseFindings are the places a gate report prints an evaluation outcome as prose with no typed state member
// carrying it: a string outside the token members that holds an outcome word (ok, fail, unchecked, conforms,
// departed, agrees, flagged), except a peer's own recorded word and a detail that only restates a state its row
// carries as a typed member. Every row of every gate is read, the report's own members included.
func gateProseFindings(rep *canon.Object) []string {
	var out []string
	var walk func(v canon.Value, path string, states map[string]bool)
	walk = func(v canon.Value, path string, states map[string]bool) {
		switch x := v.(type) {
		case canon.String:
			words := proseOutcome.FindAllString(string(x), -1)
			if len(words) == 0 || IsTokenKey(path[strings.LastIndex(path, ".")+1:]) || gateProseAllowed[path] {
				return
			}
			if gateProseBeside[path] {
				for _, w := range words {
					if !states[w] {
						out = append(out, fmt.Sprintf("%s = %q names %q, which no typed state member of the row carries", path, string(x), w))
					}
				}
				return
			}
			out = append(out, fmt.Sprintf("%s = %q carries an outcome word as prose; make it a typed state member", path, string(x)))
		case *canon.Object:
			for _, k := range x.Keys {
				walk(x.Members[k], path+"."+k, states)
			}
		case canon.Array:
			for _, e := range x {
				if row, ok := e.(*canon.Object); ok && path == ".objects" {
					walk(row, path+"[]", rowStates(row))
					continue
				}
				walk(e, path+"[]", states)
			}
		}
	}
	walk(rep, "", nil)
	return out
}

// TestGateProseFindingsCatches: the gate sweep can fail. A report whose row restates an outcome in a sentence with
// no typed member, one whose typed member carries a different word than the sentence, and a bare outcome word in
// an untyped member are each a finding; a sentence beside the typed member that carries its word, and the
// publisher's own recorded word, are not.
func TestGateProseFindingsCatches(t *testing.T) {
	parse := func(js string) *canon.Object {
		v, err := canon.Parse([]byte(js))
		if err != nil {
			t.Fatal(err)
		}
		return v.(*canon.Object)
	}
	for _, c := range []struct {
		name, js string
		want     int
	}{
		{"typed beside prose", `{"objects":[{"completeness":{"state":"fail"},"label_details":["a claim, fail (1 reading)"],"verdict":"refused"}]}`, 0},
		{"publisher word", `{"objects":[{"intended_for":{"named":{"state":"fail"},"publisher_said":"ok"},"label_details":["named: fail"]}]}`, 0},
		{"prose, no typed member", `{"objects":[{"label_details":["a claim, fail (1 reading)"]}]}`, 1},
		{"prose differs from typed", `{"objects":[{"completeness":{"state":"ok"},"label_details":["a claim, fail (1 reading)"]}]}`, 1},
		{"untyped member", `{"objects":[{"next":"it is ok now"}]}`, 1},
		{"outside the rows", `{"gate":"pull ok","objects":[]}`, 1},
	} {
		if got := gateProseFindings(parse(c.js)); len(got) != c.want {
			t.Errorf("%s: %d findings, want %d: %v", c.name, len(got), c.want, got)
		}
	}
}
