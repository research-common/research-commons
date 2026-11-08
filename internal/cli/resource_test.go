package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/resolve"
)

// The resource surface (resource.go): show, verify and explain of a resource id (its genesis id), an edition id
// and an approval's statement id.

// genesis signs a collection genesis under any one of the named controllers, or k of them.
func (w *world) genesisOf(name, by string, k int, controllers ...string) string {
	var cs []string
	for _, c := range controllers {
		cs = append(cs, w.signer(c))
	}
	slices.Sort(cs)
	rule := obj("any_one", true)
	if k > 0 {
		rule = obj("k_of_n", obj("k", k))
	}
	return w.sign(name, by, "genesis", obj("type", "collection", "name", "readings", "controllers", cs, "rule", rule))
}

// editionBody is an edition body naming preds (edition ids, or the genesis id) with one member per content tag;
// extra adds contents fields.
func editionBody(resource string, preds []string, members []string, extra ...any) *canon.Object {
	ms := canon.Array{}
	for _, m := range members {
		ms = append(ms, obj("content", dig(m), "role", "member"))
	}
	p := slices.Clone(preds)
	slices.Sort(p)
	contents := obj(append([]any{"members", canon.Value(ms)}, extra...)...)
	return obj("resource", resource, "predecessors", p, "contents", contents)
}

// approve signs body as an edition statement by key n and returns the statement id and the edition id.
func (w *world) approve(name, n string, body *canon.Object) (string, string) {
	return w.sign(name, n, "edition", body), resolve.EditionID(body)
}

func members(t *testing.T, o *canon.Object, path ...string) *canon.Object {
	t.Helper()
	for _, k := range path {
		x, ok := o.Members[k].(*canon.Object)
		if !ok {
			t.Fatalf("no %s in %s", k, canon.Encode(o))
		}
		o = x
	}
	return o
}

func strs(v canon.Value) []string {
	var out []string
	for _, x := range v.(canon.Array) {
		out = append(out, string(x.(canon.String)))
	}
	return out
}

// editionState finds the edition row eid in a resource view and returns its state token.
func editionState(t *testing.T, rv *canon.Object, eid string) (string, *canon.Object) {
	t.Helper()
	for _, x := range rv.Members["editions"].(canon.Array) {
		e := x.(*canon.Object)
		if e.Members["edition"] == canon.String(eid) {
			return string(e.Members["state"].(canon.String)), e
		}
	}
	t.Fatalf("edition %s not in the view: %s", eid, canon.Encode(rv))
	return "", nil
}

// TestResourceChain: C-core-79 (explain lists G → E1 → E2 by hash; the unmatched edition is orphan and never
// current), C-core-78 (an edition id and an approval's statement id both resolve to the one edition), C-core-77
// (the resource id is the genesis statement id).
func TestResourceChain(t *testing.T) {
	conformance.Covers(t, "C-core-79")
	w := newWorld(t)
	g := w.genesisOf("G", "A", 0, "A")
	s1, e1 := w.approve("E1", "A", editionBody(g, []string{g}, []string{"a"}))
	s2, e2 := w.approve("E2", "A", editionBody(g, []string{e1}, []string{"a", "b"}))
	_, eo := w.approve("Eo", "A", editionBody(g, []string{strings.Repeat("ab", 32)}, []string{"z"}))
	// a predecessor spelled as E1's approval statement id names no edition (wire §3): orphan too
	_, es := w.approve("Es", "A", editionBody(g, []string{s1}, []string{"s"}))

	ex := jsonOf(t, w.run("explain", g, "--json"))
	rv := members(t, ex, "resource_view")
	if rv.Members["resource"] != canon.String(g) {
		t.Fatalf("resource id %v, want the genesis id %s", rv.Members["resource"], g)
	}
	if rv.Members["current"] != canon.String(e2) {
		t.Fatalf("current %v, want E2 %s", rv.Members["current"], e2)
	}
	if got := strs(rv.Members["chain"]); !slices.Equal(got, []string{g, e1, e2}) {
		t.Fatalf("chain %v, want G → E1 → E2", got)
	}
	for _, x := range []string{eo, es} {
		if st, _ := editionState(t, rv, x); st != "orphan" {
			t.Fatalf("edition %s: %s, want orphan", x, st)
		}
	}
	if st, row := editionState(t, rv, e2); st != "edition" || !slices.Equal(strs(row.Members["predecessors"]), []string{e1}) {
		t.Fatalf("E2: %s %s", st, canon.Encode(row))
	}
	// explain names the reasoning and lists every approval among its statements
	if _, row := editionState(t, rv, e2); row.Members["reasoning"] == nil {
		t.Fatal("explain lacks the edition's reasoning")
	}
	listed := map[string]bool{}
	for _, x := range ex.Members["statements"].(canon.Array) {
		listed[string(x.(*canon.Object).Members["statement"].(canon.String))] = true
	}
	for _, id := range []string{g, s1, s2} {
		if !listed[id] {
			t.Fatalf("explain does not list %s", id)
		}
	}
	// the human surface prints the chain in order
	h := w.run("explain", g).stdout
	if !strings.Contains(h, "chain: "+g+", "+e1+", "+e2) {
		t.Fatalf("human chain:\n%s", h)
	}
	// C-core-78 on the CLI: the edition id and the approval id both show the resource pinned at E1
	for _, ref := range []string{e1, s1} {
		o := jsonOf(t, w.run("show", ref, "--json"))
		pin := members(t, o, "pinned_edition")
		if pin.Members["edition"] != canon.String(e1) || pin.Members["state"] != canon.String("edition") {
			t.Fatalf("show %s pins %s", ref, canon.Encode(pin))
		}
		if r := w.run("verify", ref); r.code != ExitOK {
			t.Fatalf("verify %s: %d\n%s", ref, r.code, r.stdout)
		}
	}
	// an edition id names no statement: no "no statement held" beside the edition it does name
	if o := jsonOf(t, w.run("show", e1, "--json")); o.Members["status"] != nil {
		t.Fatalf("show <edition id> printed a statement status: %s", canon.Encode(o))
	}
	// the orphan, pinned, does not verify: it is not established as an edition from the statements held
	if r := w.run("verify", eo, "--json"); r.code != ExitCouldNot || !strings.Contains(r.stdout, `"state":"orphan"`) {
		t.Fatalf("verify orphan: %d\n%s", r.code, r.stdout)
	}
	if r := w.run("verify", g); r.code != ExitOK {
		t.Fatalf("verify resource: %d\n%s", r.code, r.stdout)
	}
}

// TestResourceOneApprovalPerBody: C-core-82. Rule 2 of 3: A approves body X, B approves body Y differing in one
// field. Neither is an edition, the tip stays the genesis, and explain shows one approval per body.
func TestResourceOneApprovalPerBody(t *testing.T) {
	conformance.Covers(t, "C-core-82")
	w := newWorld(t)
	g := w.genesisOf("G", "A", 2, "A", "B", "C")
	sx, x := w.approve("X", "A", editionBody(g, []string{g}, []string{"a"}))
	sy, y := w.approve("Y", "B", editionBody(g, []string{g}, []string{"a"}, "selection", "curated"))
	if x == y {
		t.Fatal("bodies differing in one field share an edition id")
	}
	rv := members(t, jsonOf(t, w.run("explain", g, "--json")), "resource_view")
	if rv.Members["current"] != canon.String(g) {
		t.Fatalf("tip moved: %v", rv.Members["current"])
	}
	for _, c := range []struct{ eid, stmt, signer string }{{x, sx, w.signer("A")}, {y, sy, w.signer("B")}} {
		st, row := editionState(t, rv, c.eid)
		if st != "pending" {
			t.Fatalf("%s: %s, want pending", c.eid, st)
		}
		ap := row.Members["approvals"].(canon.Array)
		if len(ap) != 1 {
			t.Fatalf("%s: %d approvals, want one per body", c.eid, len(ap))
		}
		a := ap[0].(*canon.Object)
		if a.Members["statement"] != canon.String(c.stmt) || a.Members["signer"] != canon.String(c.signer) {
			t.Fatalf("%s: approval %s", c.eid, canon.Encode(a))
		}
	}
	if r := w.run("verify", x, "--json"); r.code != ExitCouldNot || !strings.Contains(r.stdout, `"state":"pending"`) {
		t.Fatalf("verify pending edition: %d\n%s", r.code, r.stdout)
	}
	// the resource itself has one current node (the genesis): its verify passes; nothing contested, no FORK
	if r := w.run("verify", g); r.code != ExitOK {
		t.Fatalf("verify resource: %d\n%s", r.code, r.stdout)
	}
	// the second approval of X makes it the edition; one body, two approvals, one edition id
	sx2, x2 := w.approve("X2", "B", editionBody(g, []string{g}, []string{"a"}))
	if x2 != x {
		t.Fatal("byte-identical bodies have two edition ids")
	}
	rv = members(t, jsonOf(t, w.run("show", g, "--json")), "resource_view")
	st, row := editionState(t, rv, x)
	if st != "edition" || len(row.Members["approvals"].(canon.Array)) != 2 || rv.Members["current"] != canon.String(x) {
		t.Fatalf("X after B's approval: %s %s", st, canon.Encode(row))
	}
	_ = sx2
}

// TestResourceFork: C-core-84 on the CLI. Two editions with one predecessor: FORK naming both, no current
// edition, verify exits 3; a merge clears it.
func TestResourceFork(t *testing.T) {
	w := newWorld(t)
	g := w.genesisOf("G", "A", 0, "A", "B")
	_, l := w.approve("L", "A", editionBody(g, []string{g}, []string{"l"}))
	_, r := w.approve("R", "B", editionBody(g, []string{g}, []string{"r"}))
	o := jsonOf(t, w.run("verify", g, "--json"))
	rv := members(t, o, "resource_view")
	if rv.Members["state"] != canon.String("FORK") || rv.Members["current"] != nil {
		t.Fatalf("fork view: %s", canon.Encode(rv))
	}
	tips := strs(rv.Members["tips"])
	want := []string{l, r}
	slices.Sort(want)
	if !slices.Equal(tips, want) {
		t.Fatalf("tips %v, want both branches", tips)
	}
	if w.run("verify", g).code != ExitCouldNot || !strings.Contains(w.run("verify", g).stdout, "FORK") {
		t.Fatal("verify under a FORK does not exit 3 naming FORK")
	}
	// one display whatever the order: the JSON is a function of the held set
	if a, b := w.run("show", g, "--json").stdout, w.run("show", g, "--json").stdout; a != b {
		t.Fatal("two runs differ")
	}
	_, m := w.approve("M", "A", editionBody(g, []string{l, r}, []string{"l", "r"}))
	rv = members(t, jsonOf(t, w.run("show", g, "--json")), "resource_view")
	if rv.Members["current"] != canon.String(m) || w.run("verify", g).code != ExitOK {
		t.Fatalf("merge did not clear the fork: %s", canon.Encode(rv))
	}
	f := rv.Members["forks"].(canon.Array)[0].(*canon.Object)
	if f.Members["cleared_by"] != canon.String(m) {
		t.Fatalf("fork row: %s", canon.Encode(f))
	}
}

// TestResourceCompleteness: the receiver's check of a completeness claim reaches the CLI beside the edition
// (C-core-60's surface), with ok/fail/unchecked as a typed `state` member and the missing reading named; it
// moves no verify exit (I6). A completeness claim over station readings in January 2026 lists one of two.
func TestResourceCompleteness(t *testing.T) {
	const station = "urn:example:station-7"
	w := newWorld(t)
	reading := func(name, n, x, at string) string {
		return w.sign(name, n, "observed", obj("content", canon.Value(content(x)), "class", "phenomenon",
			"referent", canon.Value(obj("instrument", station, "location", "geo:39.74,-104.99", "at", at)),
			"capture", canon.Value(obj("at", "2026-02-02T00:00:00Z", "evidence", "self-asserted"))))
	}
	r1 := reading("R1", "O1", "jan-03", "2026-01-03T12:00:00Z")
	r2 := reading("R2", "O2", "jan-20", "2026-01-20T12:00:00Z")
	g := w.genesisOf("G", "A", 0, "A")
	scope := obj("class", "phenomenon", "source", station, "window", obj("from", "2026-01-01T00:00:00Z", "to", "2026-02-01T00:00:00Z"))
	body := obj("resource", g, "predecessors", []string{g}, "contents", obj("members",
		canon.Value(canon.Array{obj("statement", r1, "role", "member")}), "selection", "completeness", "completeness", canon.Value(scope)))
	_, e := w.approve("E", "A", body)
	o := jsonOf(t, w.run("verify", g, "--json"))
	if o.Members["exit"] != canon.Int(0) {
		t.Fatalf("a failing completeness claim moved the verify exit: %s", canon.Encode(o))
	}
	c := members(t, o, "resource_view", "completeness")
	if c.Members["state"] != canon.String("fail") || !slices.Equal(strs(c.Members["missing"]), []string{r2}) ||
		!slices.Equal(strs(c.Members["listed"]), []string{r1}) {
		t.Fatalf("completeness: %s", canon.Encode(c))
	}
	mb := members(t, o, "resource_view", "membership")
	if mb.Members["edition"] != canon.String(e) || mb.Members["count"] != canon.Int(1) {
		t.Fatalf("membership: %s", canon.Encode(mb))
	}
	// explain lists the readings the check read (I14)
	ex := jsonOf(t, w.run("explain", g, "--json"))
	listed := map[string]bool{}
	for _, x := range ex.Members["statements"].(canon.Array) {
		listed[string(x.(*canon.Object).Members["statement"].(canon.String))] = true
	}
	if !listed[r1] || !listed[r2] {
		t.Fatalf("explain does not list the readings the check read: %s", canon.Encode(ex.Members["statements"]))
	}
}

// TestCorroborationOnEverySurface: C-core-134's corroboration half. One observation, one corroboration and one
// contradiction from other keys: show, list, verify and explain of the blob print the same corroboration status
// for it, and show/verify/explain of the observation's statement print the same counts; the status never moves
// verify's exit (I6).
func TestCorroborationOnEverySurface(t *testing.T) {
	conformance.Covers(t, "C-core-134")
	w := fixture(t)
	ref := obj("chain_id", "bip122:000000000019d6689c085ae165831e93", "block_hash", strings.Repeat("a1", 32), "depth", 3)
	cap := obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted")
	ob := w.sign("O:ob", "K5", "observed", obj("content", canon.Value(content("sole")), "class", "exact-bytes",
		"referent", canon.Value(ref), "capture", canon.Value(cap)))
	before := w.run("verify", ob).code
	w.sign("C:sup", "K6", "corroborates", obj("of", ob, "result", w.ids["A:sole"], "verdict", "supports", "model", "M",
		"cohort", canon.Value(obj("rule", "every station in R"))))
	w.sign("C:con", "K7", "corroborates", obj("of", ob, "result", w.ids["A:sole"], "verdict", "contradicts", "model", "M",
		"cohort", canon.Value(obj("rule", "every station in R"))))
	if after := w.run("verify", ob).code; after != before {
		t.Fatalf("corroboration moved verify's exit: %d → %d", before, after)
	}
	type counts struct{ sum, sup, con string }
	read := func(c *canon.Object) counts {
		return counts{string(canon.Encode(c.Members["summary"])), string(canon.Encode(c.Members["corroborated"])), string(canon.Encode(c.Members["contradicted"]))}
	}
	var seen []counts
	// the blob, on every surface
	listing := jsonOf(t, w.run("list", "--json"))
	for _, b := range listing.Members["blobs"].(canon.Array) {
		if bo := b.(*canon.Object); bo.Members["digest"] == canon.String(dig("sole")) {
			seen = append(seen, read(firstObservation(t, bo, ob)))
		}
	}
	for _, cmd := range []string{"show", "verify", "explain"} {
		seen = append(seen, read(firstObservation(t, jsonOf(t, w.run(cmd, dig("sole"), "--json")), ob)))
		seen = append(seen, read(members(t, jsonOf(t, w.run(cmd, ob, "--json")), "corroboration")))
	}
	if len(seen) != 7 {
		t.Fatalf("%d surfaces printed the status, want 7", len(seen))
	}
	for _, s := range seen[1:] {
		if s != seen[0] {
			t.Fatalf("surfaces disagree: %+v vs %+v", seen[0], s)
		}
	}
	if seen[0].sup != "1" || seen[0].con != "1" || !strings.Contains(seen[0].sum, resolve.ScopeHeld) {
		t.Fatalf("status %+v, want corroborated 1 · contradicted 1 within statements you hold", seen[0])
	}
	// the full form on show of the statement names both statements; explain lists them
	ev := members(t, jsonOf(t, w.run("show", ob, "--json")), "corroboration").Members["evidence"].(canon.Array)
	if len(ev) < 2 {
		t.Fatalf("evidence: %s", canon.Encode(ev))
	}
	ex := jsonOf(t, w.run("explain", ob, "--json"))
	listed := map[string]bool{}
	for _, x := range ex.Members["statements"].(canon.Array) {
		listed[string(x.(*canon.Object).Members["statement"].(canon.String))] = true
	}
	if !listed[w.ids["C:sup"]] || !listed[w.ids["C:con"]] {
		t.Fatal("explain of the observation does not list the corroborations behind its status")
	}
}

func firstObservation(t *testing.T, blob *canon.Object, id string) *canon.Object {
	t.Helper()
	obs, ok := blob.Members["observations"].(canon.Array)
	if !ok {
		t.Fatalf("no observations on %s", canon.Encode(blob))
	}
	for _, x := range obs {
		if o := x.(*canon.Object); o.Members["statement"] == canon.String(id) {
			return members(t, o, "corroboration")
		}
	}
	t.Fatalf("observation %s not on the blob", id)
	return nil
}

// resourceWorld is a store holding every edition state the view prints and an observation with corroborations:
// a linear chain, an orphan, a pending body, a fork and its merge, a completeness claim, a withdrawn approval.
func resourceWorld(t *testing.T) (*world, []string) {
	w := fixture(t)
	g := w.genesisOf("G", "A", 0, "A", "B")
	_, e1 := w.approve("E1", "A", editionBody(g, []string{g}, []string{"a"}))
	_, l := w.approve("L", "A", editionBody(g, []string{e1}, []string{"l"}))
	_, r := w.approve("R", "B", editionBody(g, []string{e1}, []string{"r"}))
	_, eo := w.approve("Eo", "A", editionBody(g, []string{strings.Repeat("cd", 32)}, []string{"o"}))
	g2 := w.genesisOf("G2", "A", 2, "A", "B", "C")
	_, p := w.approve("P", "A", editionBody(g2, []string{g2}, []string{"p"}))
	g3 := w.genesisOf("G3", "A", 0, "A")
	_, m := w.approve("M3", "A", editionBody(g3, []string{g3}, []string{"m"}, "selection", "curated"))
	w.sign("W3", "A", "withdraw_approval", obj("resource", g3, "edition", m))
	ob := w.sign("O:ob", "K5", "observed", obj("content", canon.Value(content("sole")), "class", "exact-bytes",
		"referent", canon.Value(obj("chain_id", "bip122:000000000019d6689c085ae165831e93", "block_hash", strings.Repeat("a1", 32), "depth", 3)),
		"capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted"))))
	w.sign("C:sup", "K6", "corroborates", obj("of", ob, "result", w.ids["A:sole"], "verdict", "supports", "model", "M",
		"cohort", canon.Value(obj("rule", "every station in R"))))
	// a current edition with members and a completeness claim (members role, the claim's class: peer words)
	g4 := w.genesisOf("G4", "A", 0, "A")
	scope := obj("class", "phenomenon", "source", "urn:example:s", "window", obj("from", "2026-01-01T00:00:00Z", "to", "2026-02-01T00:00:00Z"))
	_, e4 := w.approve("E4", "A", obj("resource", g4, "predecessors", []string{g4}, "contents", obj("members",
		canon.Value(canon.Array{obj("statement", ob, "role", "member"), obj("content", dig("sole"), "role", "reading")}),
		"selection", "completeness", "completeness", canon.Value(scope))))
	return w, []string{g, e1, l, r, eo, g2, p, g3, m, w.ids["E1"], w.ids["W3"], ob, dig("sole"), g4, e4}
}

// TestResourceSurfaceSweep: C-core-132, C-core-136 and the P-12 footer over the resource surface. Every ref of the
// resource world on show, verify and explain, in both forms: only closed-vocabulary tokens in token members, each
// also on the human surface, one status_scope footer, the same exit in both forms, and every id show cites by
// `statement`/`statements` among explain's statements (each with its signer) unless it is held by nobody.
func TestResourceSurfaceSweep(t *testing.T) {
	conformance.Partial(t, "C-core-132", "the resource surface (show, verify, explain of a resource, an edition, an approval) and the corroboration status print only table tokens; a rule evaluation is one typed state member")
	w, refs := resourceWorld(t)
	for _, ref := range refs {
		for _, cmd := range []string{"show", "verify", "explain"} {
			j := w.run(cmd, ref, "--json")
			if j.code == 2 || strings.Contains(j.stdout, "internal-error") {
				t.Fatalf("%s %s: %d %s", cmd, ref, j.code, j.stdout)
			}
			o := jsonOf(t, j)
			toks := map[string]string{}
			collect(withoutBodies(o), "", toks)
			h := w.run(cmd, ref)
			if h.code != j.code {
				t.Errorf("%s %s: human exit %d, json %d", cmd, ref, h.code, j.code)
			}
			for path, v := range toks {
				if !IsToken(v) {
					t.Errorf("%s %s: %s = %q is not in the closed vocabulary", cmd, ref, path, v)
				}
				if !strings.Contains(h.stdout, v) {
					t.Errorf("%s %s: token %q missing on the human surface", cmd, ref, v)
				}
			}
			if n := countMember(o, "status_scope"); n != 1 || o.Members["status_scope"] != canon.String(resolve.ScopeHeld) {
				t.Errorf("%s %s: status_scope %d time(s)", cmd, ref, n)
			}
		}
		// what show cites, explain lists
		show := jsonOf(t, w.run("show", ref, "--json"))
		ex := jsonOf(t, w.run("explain", ref, "--json"))
		listed := map[string]bool{}
		for _, x := range ex.Members["statements"].(canon.Array) {
			e := x.(*canon.Object)
			id := string(e.Members["statement"].(canon.String))
			listed[id] = true
			if e.Members["signer"] == nil && e.Members["status"] != canon.String("no statement held") {
				t.Errorf("explain %s: %s without signer", ref, id)
			}
		}
		var walk func(canon.Value)
		walk = func(v canon.Value) {
			switch x := v.(type) {
			case *canon.Object:
				for _, k := range x.Keys {
					if k == "statement" || k == "statements" {
						var ids []string
						switch y := x.Members[k].(type) {
						case canon.String:
							ids = []string{string(y)}
						case canon.Array:
							for _, z := range y {
								if s, ok := z.(canon.String); ok {
									ids = append(ids, string(s))
								}
							}
						}
						for _, id := range ids {
							if !listed[id] {
								t.Errorf("explain %s: show cites %s, explain does not list it", ref, id)
							}
						}
					}
					walk(x.Members[k])
				}
			case canon.Array:
				for _, z := range x {
					walk(z)
				}
			}
		}
		walk(show)
	}
}

// TestResourceEditionStates: every edition state reaches the CLI as its own token, with verify of the pinned
// edition exiting 3 for each state but `edition` (the negative half: the mutation, here a missing approval, a
// withdrawal, a bogus predecessor, a second branch, reaches the edition boundary and shows in its row).
func TestResourceEditionStates(t *testing.T) {
	w, refs := resourceWorld(t)
	g, e1, l, r, eo, g2, p, g3, m := refs[0], refs[1], refs[2], refs[3], refs[4], refs[5], refs[6], refs[7], refs[8]
	for _, c := range []struct {
		res, ed, state string
		exit           int
	}{{g, e1, "edition", ExitOK}, {g, l, "edition", ExitOK}, {g, r, "edition", ExitOK}, {g, eo, "orphan", ExitCouldNot},
		{g2, p, "pending", ExitCouldNot}, {g3, m, "pending", ExitCouldNot}} {
		rv := members(t, jsonOf(t, w.run("show", c.res, "--json")), "resource_view")
		if st, _ := editionState(t, rv, c.ed); st != c.state {
			t.Errorf("%s: %s, want %s", c.ed, st, c.state)
		}
		if got := w.run("verify", c.ed).code; got != c.exit {
			t.Errorf("verify %s (%s): %d, want %d", c.ed, c.state, got, c.exit)
		}
	}
	// the withdrawn approval is shown, not counted, naming the withdrawal
	_, row := editionState(t, members(t, jsonOf(t, w.run("show", g3, "--json")), "resource_view"), m)
	a := row.Members["approvals"].(canon.Array)[0].(*canon.Object)
	if a.Members["counted"] != canon.String("not counted") || a.Members["withdrawn_by"] != canon.String(w.ids["W3"]) {
		t.Fatalf("withdrawn approval: %s", canon.Encode(a))
	}
	// the fork on G: verify 3 naming FORK; G3 (back to its genesis after the withdrawal) passes
	if r := w.run("verify", g, "--json"); r.code != ExitCouldNot || !strings.Contains(r.stdout, `"state":"FORK"`) {
		t.Fatalf("verify fork: %d", r.code)
	}
	if r := w.run("verify", g3); r.code != ExitOK {
		t.Fatalf("verify G3: %d\n%s", r.code, r.stdout)
	}
}

// withoutBodies is v with every `body` member (a statement's raw JSON, the signer's words, rendered inert) dropped:
// a body's own `role` or `class` is not a tool token, whatever its member name (RESVIEW-F1).
func withoutBodies(v canon.Value) canon.Value {
	switch x := v.(type) {
	case *canon.Object:
		o := &canon.Object{Members: map[string]canon.Value{}}
		for _, k := range x.Keys {
			if k == "body" {
				continue
			}
			o.Keys = append(o.Keys, k)
			o.Members[k] = withoutBodies(x.Members[k])
		}
		return o
	case canon.Array:
		a := canon.Array{}
		for _, e := range x {
			a = append(a, withoutBodies(e))
		}
		return a
	}
	return v
}
