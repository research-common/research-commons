package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/sig"
	"github.com/research-common/research-commons/internal/wire"
)

// --- fixture language -------------------------------------------------------------------------------------

func obj(kv ...any) *canon.Object {
	o := &canon.Object{Members: map[string]canon.Value{}}
	for i := 0; i < len(kv); i += 2 {
		k := kv[i].(string)
		o.Keys = append(o.Keys, k)
		switch v := kv[i+1].(type) {
		case string:
			o.Members[k] = canon.String(v)
		case int:
			o.Members[k] = canon.Int(v)
		case bool:
			o.Members[k] = canon.Bool(v)
		case []string:
			a := canon.Array{}
			for _, s := range v {
				a = append(a, canon.String(s))
			}
			o.Members[k] = a
		case canon.Value:
			o.Members[k] = v
		default:
			panic(fmt.Sprintf("obj: %T", v))
		}
	}
	slices.SortFunc(o.Keys, canon.CompareKeys)
	return o
}

func testKey(name string) wire.Key {
	h := sha256.Sum256([]byte("research-commons go test resolve key " + name))
	if len(name)%2 == 0 {
		return wire.EIP191Key{Scalar: h[:]}
	}
	return wire.Ed25519Key{Seed: h[:]}
}

// world signs statements into per-key logs, chaining each key's lines in the order the test writes them.
type world struct {
	t     *testing.T
	keys  map[string]wire.Key
	head  map[string]string
	seq   map[string]int64
	lines [][]byte
	ids   map[string]string // name -> statement id
	by    map[string]string // statement id -> key name
}

func newWorld(t *testing.T) *world {
	return &world{t: t, keys: map[string]wire.Key{}, head: map[string]string{}, seq: map[string]int64{},
		ids: map[string]string{}, by: map[string]string{}}
}

func (w *world) key(n string) wire.Key {
	k, ok := w.keys[n]
	if !ok {
		k = testKey(n)
		w.keys[n] = k
	}
	return k
}

func (w *world) signer(n string) string { return w.key(n).Signer() }

// sign appends a statement to key n's log and names it.
func (w *world) sign(name, n, kind string, body *canon.Object) string {
	k := w.key(n)
	s := w.seq[n]
	line, id := wire.Sign(wire.Draft{Kind: kind, Seq: s, Prev: w.head[n], TS: fmt.Sprintf("2026-10-16T02:%02d:%02dZ", s/60%60, s%60), Body: body}, k)
	w.head[n], w.seq[n] = id, s+1
	w.lines = append(w.lines, line)
	w.ids[name] = id
	w.by[id] = n
	return id
}

// genesis creates a resource; rule k=0 means any_one.
func (w *world) genesis(name, by string, k int, controllers ...string) string {
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

// edition is one approval; members names the content tags; extra adds contents fields.
func (w *world) edition(name, by, resource string, preds []string, members []string, extra ...any) string {
	return w.sign(name, by, "edition", w.editionBody(resource, preds, members, extra...))
}

func (w *world) editionBody(resource string, preds []string, members []string, extra ...any) *canon.Object {
	ms := canon.Array{}
	for _, m := range members {
		d := sha256.Sum256([]byte(m))
		ms = append(ms, obj("content", "sha256:"+hex.EncodeToString(d[:]), "role", "member"))
	}
	p := slices.Clone(preds)
	slices.Sort(p)
	contents := obj(append([]any{"members", canon.Value(ms)}, extra...)...)
	return obj("resource", resource, "predecessors", p, "contents", contents)
}

func (w *world) controllers(names ...string) []string {
	var out []string
	for _, n := range names {
		out = append(out, w.signer(n))
	}
	slices.Sort(out)
	return out
}

// resolve delivers lines (all of them when order is nil) in the given order and resolves resource id.
func (w *world) resolve(id string, order []int) (*Resource, *Resolver) {
	w.t.Helper()
	s := keylog.NewStore()
	if order == nil {
		for i := range w.lines {
			order = append(order, i)
		}
	}
	for _, i := range order {
		st, err := wire.Read(w.lines[i])
		if err != nil {
			w.t.Fatalf("line %d: %v", i, err)
		}
		if _, err := s.Log(st.Signer).Add(w.lines[i]); err != nil {
			w.t.Fatalf("line %d refused: %v", i, err)
		}
	}
	r := New(s)
	res, ok := r.Resource(id)
	if !ok {
		w.t.Fatalf("resource %s not resolved", keylog.Short(id))
	}
	return res, r
}

func editionOf(t *testing.T, res *Resource, stmt string) *Edition {
	t.Helper()
	e, ok := res.Edition(stmt)
	if !ok {
		t.Fatalf("no edition for %s", keylog.Short(stmt))
	}
	return e
}

func wantState(t *testing.T, res *Resource, stmt string, want EditionState, explain string) {
	t.Helper()
	e := editionOf(t, res, stmt)
	if e.State != want {
		t.Fatalf("edition %s: state %s, want %s\n%s", keylog.Short(stmt), e.State, want, res.Render())
	}
	if explain != "" && !strings.Contains(strings.Join(e.Explain, "\n"), explain) {
		t.Fatalf("edition %s: explain %q lacks %q", keylog.Short(stmt), e.Explain, explain)
	}
}

func wantCurrent(t *testing.T, res *Resource, stmt string) {
	t.Helper()
	want := stmt
	if e, ok := res.Edition(stmt); ok {
		want = e.ID
	}
	if res.Current != want {
		t.Fatalf("current %s, want %s\n%s", keylog.Short(res.Current), keylog.Short(want), res.Render())
	}
}

// everyOrder runs check for every delivery order of the world's lines (all of them up to 6 lines, else a
// seeded sample of 400 plus identity and reverse) and requires one rendering across all.
func everyOrder(t *testing.T, w *world, id string, check func(*Resource)) {
	t.Helper()
	n := len(w.lines)
	var orders [][]int
	if n <= 6 {
		orders = permutations(n)
	} else {
		id, rev := make([]int, n), make([]int, n)
		for i := range id {
			id[i], rev[i] = i, n-1-i
		}
		orders = append(orders, id, rev)
		seed := uint64(0x9e3779b97f4a7c15)
		for i := 0; i < 400; i++ {
			seed = seed*6364136223846793005 + 1442695040888963407
			orders = append(orders, shuffle(n, seed))
		}
	}
	var first string
	for _, o := range orders {
		res, _ := w.resolve(id, o)
		check(res)
		got := res.Render()
		if first == "" {
			first = got
		} else if got != first {
			t.Fatalf("order %v changed the answer:\n%s\nvs\n%s", o, got, first)
		}
	}
}

func permutations(n int) [][]int {
	var out [][]int
	a := make([]int, n)
	for i := range a {
		a[i] = i
	}
	var rec func(k int)
	rec = func(k int) {
		if k == n {
			out = append(out, slices.Clone(a))
			return
		}
		for i := k; i < n; i++ {
			a[k], a[i] = a[i], a[k]
			rec(k + 1)
			a[k], a[i] = a[i], a[k]
		}
	}
	rec(0)
	return out
}

func shuffle(n int, seed uint64) []int {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	for i := n - 1; i > 0; i-- {
		seed = seed*6364136223846793005 + 1442695040888963407
		j := int((seed >> 33) % uint64(i+1))
		p[i], p[j] = p[j], p[i]
	}
	return p
}

// --- cases --------------------------------------------------------------------------------------------------

// TestGenesisID: C-core-77. The resource id is the genesis statement's id, the hash of its signed string; a
// genesis differing in one byte is a different resource.
func TestGenesisID(t *testing.T) {
	conformance.Covers(t, "C-core-77")
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A", "B")
	res, _ := w.resolve(g, nil)
	st, _ := wire.Read(w.lines[0])
	if res.ID != g || res.ID != wire.ID(st.SignedString) {
		t.Fatalf("resource id %s, genesis id %s", res.ID, g)
	}
	// one byte of the name changed: a different genesis, a different resource
	w2 := newWorld(t)
	w2.keys = w.keys
	g2 := w2.sign("G", "A", "genesis", obj("type", "collection", "name", "readingt", "controllers", w.controllers("A", "B"), "rule", obj("any_one", true)))
	if g2 == g {
		t.Fatal("mutated genesis has the same id")
	}
	res2, _ := w2.resolve(g2, nil)
	if res2.ID == res.ID || res2.Name != "readingt" {
		t.Fatalf("mutated genesis resolves to %s %q", keylog.Short(res2.ID), res2.Name)
	}
	if _, ok := res2.Edition(g); ok {
		t.Fatal("the original genesis resolves inside the mutated resource")
	}
}

// TestEditionsAndPin: C-core-78, C-core-79. Two editions in sequence; the resource id never changes; edition 1
// pinned by its statement hash returns exactly its members; an edition whose predecessor matches nothing is
// orphan and never current.
func TestEditionsAndPin(t *testing.T) {
	conformance.Covers(t, "C-core-78")
	conformance.Partial(t, "C-core-79", "explain lists G → E1 → E2 by hash: the chain is in the view (Predecessors); the explain surface is not built")
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A")
	e1 := w.edition("E1", "A", g, []string{g}, []string{"a"})
	e2 := w.edition("E2", "A", g, []string{e1}, []string{"a", "b"})
	bogus := strings.Repeat("ab", 32)
	orphan := w.edition("Eo", "A", g, []string{bogus}, []string{"z"})
	everyOrder(t, w, g, func(res *Resource) {
		if res.ID != g {
			t.Fatalf("resource id changed to %s", res.ID)
		}
		wantCurrent(t, res, e2)
		pinned := editionOf(t, res, e1)
		if len(pinned.Members) != 1 {
			t.Fatalf("edition 1 has %d members, want exactly {a}", len(pinned.Members))
		}
		ed2 := editionOf(t, res, e2)
		if !slices.Equal(ed2.Predecessors, []string{pinned.ID}) {
			t.Fatalf("edition 2 predecessors %v, want edition 1 %s", ed2.Predecessors, pinned.ID)
		}
		wantState(t, res, orphan, Orphan, "names nothing held for this resource")
		if res.Current == editionOf(t, res, orphan).ID {
			t.Fatal("orphan is current")
		}
		if res.VerifyExit() != 0 {
			t.Fatal("verify exit not 0 with one current edition")
		}
	})
}

// TestControllerChange: C-core-80. Under E2 (any one of A, B), A adds C; then C alone signs E4.
func TestControllerChange(t *testing.T) {
	conformance.Covers(t, "C-core-80")
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A", "B")
	e2 := w.edition("E2", "B", g, []string{g}, []string{"a"})
	e3 := w.edition("E3", "A", g, []string{e2}, []string{"a"}, "controllers", w.controllers("A", "B", "C"))
	e4 := w.edition("E4", "C", g, []string{e3}, []string{"a", "c"})
	res, _ := w.resolve(g, nil)
	wantState(t, res, e3, Authorized, "authorized under")
	wantState(t, res, e4, Authorized, "")
	wantCurrent(t, res, e4)
	if e := editionOf(t, res, e3); len(e.Controllers) != 3 || e.K != 1 {
		t.Fatalf("E3 authority %v k=%d", e.Controllers, e.K)
	}
}

// TestNoSelfElevation: C-core-81. Non-controller C signs an edition after E2 that names C as controller. It is
// stored in C's log, is not an edition, and every order gives the same answer.
func TestNoSelfElevation(t *testing.T) {
	conformance.Covers(t, "C-core-81")
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A", "B")
	e2 := w.edition("E2", "A", g, []string{g}, []string{"a"})
	bad := w.edition("E3x", "C", g, []string{e2}, []string{"a", "evil"}, "controllers", w.controllers("A", "B", "C"))
	everyOrder(t, w, g, func(res *Resource) {
		wantCurrent(t, res, e2)
		wantState(t, res, bad, Unauthorized, "unauthorized under "+keylog.Short(editionOf(t, res, e2).ID)+": any one of {")
		cur := editionOf(t, res, e2)
		if len(cur.Controllers) != 2 || len(cur.Members) != 1 {
			t.Fatalf("current edition changed: %v %d", cur.Controllers, len(cur.Members))
		}
	})
	_, r := w.resolve(g, nil)
	if p, ok := r.Statement(bad); !ok || p.St.Signer != w.signer("C") {
		t.Fatal("E3' is not stored in C's log")
	}
}

// TestKOfNDifferentBodies: C-core-82. 2-of-3; A approves body X, B approves body Y differing by one field.
func TestKOfNDifferentBodies(t *testing.T) {
	conformance.Partial(t, "C-core-82", "explain surface; the view shows one approval per body")
	w := newWorld(t)
	g := w.genesis("G", "A", 2, "A", "B", "C")
	x := w.edition("X", "A", g, []string{g}, []string{"a"})
	y := w.edition("Y", "B", g, []string{g}, []string{"a"}, "selection", "curated")
	everyOrder(t, w, g, func(res *Resource) {
		wantCurrent(t, res, g)
		for _, s := range []string{x, y} {
			wantState(t, res, s, Pending, "1 of 2 approvals")
			if n := len(editionOf(t, res, s).Approvals); n != 1 {
				t.Fatalf("%d approvals on one body", n)
			}
		}
	})
}

// TestKOfNDuplicates: C-core-83. A's approval of X delivered three times, once with an equivalent signature
// encoding: counted once; X becomes an edition only when a second controller approves the same body.
func TestKOfNDuplicates(t *testing.T) {
	conformance.Covers(t, "C-core-83")
	w := newWorld(t)
	// AA is a secp256k1 key (even-length name), so an equivalent signature encoding exists (wire §4)
	g := w.genesis("G", "AA", 2, "AA", "B", "C")
	x := w.edition("X", "AA", g, []string{g}, []string{"a"})
	xLine := w.lines[len(w.lines)-1]
	reenc := reencode(t, xLine)
	w.lines = append(w.lines, xLine, reenc)
	res, _ := w.resolve(g, nil)
	wantState(t, res, x, Pending, "1 of 2 approvals")
	if n := len(editionOf(t, res, x).Approvals); n != 1 {
		t.Fatalf("duplicate approvals counted %d times", n)
	}
	// B approves the byte-identical body: one edition, two approvals, the tip moves
	xb := w.edition("XB", "B", g, []string{g}, []string{"a"})
	res, _ = w.resolve(g, nil)
	wantState(t, res, x, Authorized, "2 approval(s)")
	if editionOf(t, res, x) != editionOf(t, res, xb) {
		t.Fatal("two approvals of one body are two editions")
	}
	wantCurrent(t, res, x)
}

// reencode returns the line with an equivalent EIP-191 signature encoding (high s), checked to differ.
func reencode(t *testing.T, line []byte) []byte {
	t.Helper()
	v, err := canon.Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	o := v.(*canon.Object)
	s := string(o.Members["sig"].(canon.String))
	if strings.HasPrefix(s, "0x") {
		raw, _ := hex.DecodeString(s[2:])
		o.Members["sig"] = canon.String("0x" + hex.EncodeToString(sig.Equivalents(raw)[0]))
		out := canon.Encode(o)
		if string(out) == string(line) {
			t.Fatal("re-encoding is byte-identical")
		}
		return out
	}
	t.Fatal("reencode needs a secp256k1 signer")
	return nil
}

// TestEditionFork: C-core-84, C-core-86. Two editions with one predecessor, by two controllers and by one
// controller twice: FORK, no tip, verify exit 3, every order alike.
func TestEditionFork(t *testing.T) {
	conformance.Partial(t, "C-core-84", "timestamps tied/skewed/reversed are not read by the resolver at all (no ts in resource.go); file order is covered by delivery permutations")
	conformance.Partial(t, "C-core-86", "two hubs: the union of their statements is resolved here; pull is not built")
	for _, twice := range []bool{false, true} {
		w := newWorld(t)
		g := w.genesis("G", "A", 0, "A", "B")
		e1 := w.edition("E1", "A", g, []string{g}, []string{"a"})
		other := "B"
		if twice {
			other = "A"
		}
		left := w.edition("L", "A", g, []string{e1}, []string{"a", "l"})
		right := w.edition("R", other, g, []string{e1}, []string{"a", "r"})
		everyOrder(t, w, g, func(res *Resource) {
			if res.Current != "" || res.VerifyExit() != 3 {
				t.Fatalf("current %q exit %d under a fork", res.Current, res.VerifyExit())
			}
			if len(res.Forks) != 1 || res.Forks[0].Cleared() || len(res.Forks[0].Branches) != 2 {
				t.Fatalf("forks %+v", res.Forks)
			}
			wantState(t, res, left, Authorized, "")
			wantState(t, res, right, Authorized, "")
			if !strings.Contains(res.Render(), "FORK at") {
				t.Fatal("render lacks FORK")
			}
		})
	}
}

// TestMergeEdition: C-core-85. A merge naming both tips clears the FORK; both branches stay resolvable. The
// merge must be authorized under each predecessor's rule: one branch changed its controllers to {B}, so A's
// approval alone is pending, and only A and B together merge.
func TestMergeEdition(t *testing.T) {
	conformance.Covers(t, "C-core-85")
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A", "B")
	e1 := w.edition("E1", "A", g, []string{g}, []string{"a"})
	left := w.edition("L", "A", g, []string{e1}, []string{"a", "l"})
	right := w.edition("R", "B", g, []string{e1}, []string{"a", "r"})
	m := w.edition("M", "A", g, []string{left, right}, []string{"a", "l", "r"})
	res, _ := w.resolve(g, nil)
	wantState(t, res, m, Authorized, "")
	wantCurrent(t, res, m)
	if len(res.Forks) != 1 || !res.Forks[0].Cleared() {
		t.Fatalf("fork not cleared: %+v", res.Forks)
	}
	for _, b := range []string{left, right} {
		if _, ok := res.Edition(b); !ok {
			t.Fatal("branch edition no longer resolvable")
		}
	}

	// one branch is a controller change to {B} only: A cannot merge alone
	w = newWorld(t)
	g = w.genesis("G", "A", 0, "A", "B")
	e1 = w.edition("E1", "A", g, []string{g}, []string{"a"})
	left = w.edition("L", "A", g, []string{e1}, []string{"a", "l"})
	right = w.edition("R", "B", g, []string{e1}, []string{"a"}, "controllers", w.controllers("B"))
	mergeBody := []any{"controllers", w.controllers("A", "B"), "rule", obj("any_one", true)}
	m = w.edition("M", "A", g, []string{left, right}, []string{"a", "l"}, mergeBody...)
	res, _ = w.resolve(g, nil)
	wantState(t, res, m, Unauthorized, "unauthorized under "+keylog.Short(editionOf(t, res, right).ID))
	if res.Current != "" {
		t.Fatal("an unauthorized merge cleared the fork")
	}
	// B approves the same merge body: authorized under both rules (any one of {A,B}; any one of {B})
	mb := w.edition("MB", "B", g, []string{left, right}, []string{"a", "l"}, mergeBody...)
	res, _ = w.resolve(g, nil)
	wantState(t, res, mb, Authorized, "authorized under "+keylog.Short(editionOf(t, res, right).ID))
	wantCurrent(t, res, mb)
}

// TestMergeAuthorityR2: finding R2. A merge of branches whose authorities differ must declare its own
// controllers and rule, or its successors would have nothing to be evaluated under.
func TestMergeAuthorityR2(t *testing.T) {
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A", "B")
	e1 := w.edition("E1", "A", g, []string{g}, []string{"a"})
	left := w.edition("L", "A", g, []string{e1}, []string{"a", "l"})
	right := w.edition("R", "B", g, []string{e1}, []string{"a"}, "controllers", w.controllers("B"))
	body := w.editionBody(g, []string{left, right}, []string{"a", "l"})
	w.sign("MA", "A", "edition", body)
	w.sign("MB", "B", "edition", body)
	res, _ := w.resolve(g, nil)
	wantState(t, res, w.ids["MA"], Invalid, "must declare both")
	// declaring both is valid and its successors are evaluated under the declaration
	body2 := w.editionBody(g, []string{left, right}, []string{"a", "l"}, "controllers", w.controllers("A"), "rule", obj("any_one", true))
	w.sign("MA2", "A", "edition", body2)
	w.sign("MB2", "B", "edition", body2)
	res, _ = w.resolve(g, nil)
	wantState(t, res, w.ids["MA2"], Authorized, "")
	if e := editionOf(t, res, w.ids["MA2"]); !slices.Equal(e.Controllers, w.controllers("A")) {
		t.Fatalf("merge authority %v", e.Controllers)
	}
	wantCurrent(t, res, w.ids["MA2"])
}

// TestControllerChangeUnsatisfiable: a controller change whose rule no set of its controllers can meet is
// invalid, not an edition (the same check genesis gets at the gate, #89 review).
func TestControllerChangeUnsatisfiable(t *testing.T) {
	w := newWorld(t)
	g := w.genesis("G", "A", 2, "A", "B")
	body := w.editionBody(g, []string{g}, []string{"a"}, "controllers", w.controllers("A"))
	w.sign("EA", "A", "edition", body)
	w.sign("EB", "B", "edition", body)
	res, _ := w.resolve(g, nil)
	wantState(t, res, w.ids["EA"], Invalid, "2 of 1")
	wantCurrent(t, res, g)
}

// TestForkedFrom: C-core-87. A non-controller's new resource declaring forked_from leaves the original alone.
func TestForkedFrom(t *testing.T) {
	conformance.Covers(t, "C-core-87")
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A")
	e1 := w.edition("E1", "A", g, []string{g}, []string{"a"})
	before, _ := w.resolve(g, nil)
	f := w.sign("F", "C", "genesis", obj("type", "collection", "name", "readings-lax", "controllers", w.controllers("C"),
		"rule", obj("any_one", true), "forked_from", g))
	w.edition("F1", "C", f, []string{f}, []string{"a", "x"})
	after, r := w.resolve(g, nil)
	if before.Render() != after.Render() {
		t.Fatalf("original changed:\n%s\nvs\n%s", before.Render(), after.Render())
	}
	wantCurrent(t, after, e1)
	fr, _ := r.Resource(f)
	if fr.ID == g || fr.ForkedFrom != g || !strings.Contains(fr.Render(), "forked-from "+keylog.Short(g)) {
		t.Fatalf("fork resource:\n%s", fr.Render())
	}
}

// TestLostControllerKey: C-core-99. Sole controller A revokes its key. B's edition naming the tip is
// unauthorized, the tip is unchanged, the resource shows no authorized controller, and B's own resource
// forked from it has a new id. A's later edition (after its own revocation) does not count either.
func TestLostControllerKey(t *testing.T) {
	conformance.Covers(t, "C-core-99")
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A")
	e1 := w.edition("E1", "A", g, []string{g}, []string{"a"})
	w.sign("REV", "A", "revoke_key", obj("reason", "key_compromise"))
	eb := w.edition("EB", "B", g, []string{e1}, []string{"a", "b"})
	ea := w.edition("EA", "A", g, []string{e1}, []string{"a", "late"})
	f := w.sign("F", "B", "genesis", obj("type", "collection", "name", "readings", "controllers", w.controllers("B"),
		"rule", obj("any_one", true), "forked_from", g))
	res, r := w.resolve(g, nil)
	wantCurrent(t, res, e1)
	wantState(t, res, eb, Unauthorized, "")
	wantState(t, res, ea, Unauthorized, "after revoke_key")
	if !res.NoController || !strings.Contains(res.Render(), "no authorized controller") {
		t.Fatalf("resource not shown as having no controller:\n%s", res.Render())
	}
	fr, _ := r.Resource(f)
	if fr.ID == g || fr.ForkedFrom != g {
		t.Fatal("R′ is not a new resource forked from R")
	}
	// A's edition from before the revocation still counts (I3: nothing decided earlier is rewritten)
	wantState(t, res, e1, Authorized, "")
}

// TestDetachedEditionWaitsForRevocation: C-core-143 (edition half). K controls a resource; seq n is a
// revoke_key, seq n+1 an edition. Without seq n the edition is detached and not evaluated (tip unchanged);
// when seq n arrives, the edition is evaluated under it: after the revocation, so it does not count.
func TestDetachedEditionWaitsForRevocation(t *testing.T) {
	conformance.Partial(t, "C-core-143", "the edition half at the resolver; the observed half needs observation resolution, and package scope needs pull")
	w := newWorld(t)
	g := w.genesis("G", "K", 0, "K")
	e1 := w.edition("E1", "K", g, []string{g}, []string{"a"})
	w.sign("REV", "K", "revoke_key", obj("reason", "key_compromise"))
	late := w.edition("E2", "K", g, []string{e1}, []string{"a", "b"})
	n := len(w.lines)
	without := []int{0, 1, 3} // everything except the revocation (index 2)
	res, _ := w.resolve(g, without)
	wantState(t, res, late, Detached, "detached")
	wantCurrent(t, res, e1)
	res, _ = w.resolve(g, nil)
	if n != 4 {
		t.Fatal("fixture changed")
	}
	wantState(t, res, late, Unauthorized, "after revoke_key")
	wantCurrent(t, res, e1)

	// control: no revocation at all; the same edition delivered after its gap fills becomes current
	w = newWorld(t)
	g = w.genesis("G", "K", 0, "K")
	e1 = w.edition("E1", "K", g, []string{g}, []string{"a"})
	w.sign("D", "K", "describes", obj("about", obj("resource", g), "note", "spacer"))
	late = w.edition("E2", "K", g, []string{e1}, []string{"a", "b"})
	res, _ = w.resolve(g, []int{0, 1, 3})
	wantState(t, res, late, Detached, "")
	res, _ = w.resolve(g, nil)
	wantState(t, res, late, Authorized, "")
	wantCurrent(t, res, late)
}

// TestResourcePermutationProperty: P-01 over resources. Seeded random histories of genesis, editions (k-of-n
// approvals, forks, merges, controller changes, outsiders) and revocations; every delivery order resolves alike.
func TestResourcePermutationProperty(t *testing.T) {
	conformance.Partial(t, "P-01", "resources: every derived answer of the resource view; other views as they land")
	for seed := uint64(1); seed <= 40; seed++ {
		w := genHistory(t, seed)
		g := w.ids["G"]
		var first string
		for i, o := range append([][]int{nil}, sampleOrders(len(w.lines), seed, 25)...) {
			res, _ := w.resolve(g, o)
			if i == 0 {
				first = res.Render()
				continue
			}
			if got := res.Render(); got != first {
				t.Fatalf("seed %d order %v:\n%s\nvs\n%s", seed, o, got, first)
			}
		}
	}
}

func sampleOrders(n int, seed uint64, k int) [][]int {
	var out [][]int
	for i := 0; i < k; i++ {
		seed = seed*6364136223846793005 + 1442695040888963407
		out = append(out, shuffle(n, seed))
	}
	return out
}

func genHistory(t *testing.T, seed uint64) *world {
	w := newWorld(t)
	rnd := func(n int) int {
		seed = seed*6364136223846793005 + 1442695040888963407
		return int((seed >> 33) % uint64(n))
	}
	names := []string{"A", "BB", "C", "DD"}
	k := 1 + rnd(2)
	g := w.genesis("G", "A", k, "A", "BB", "C")
	nodes := []string{g}
	revoked := map[string]bool{}
	for i := 0; i < 8+rnd(6); i++ {
		switch op := rnd(10); {
		case op == 0 && len(revoked) == 0:
			n := names[rnd(len(names))]
			w.sign(fmt.Sprint("rev", i), n, "revoke_key", obj("reason", "superseded"))
			revoked[n] = true
		default:
			var preds []string
			preds = append(preds, nodes[rnd(len(nodes))])
			if op >= 8 && len(nodes) > 1 {
				if p := nodes[rnd(len(nodes))]; p != preds[0] {
					preds = append(preds, p)
				}
			}
			var extra []any
			if op == 7 {
				extra = []any{"controllers", w.controllers(names[rnd(4)], names[rnd(4)]+"x")}
				if rnd(2) == 0 {
					extra = append(extra, "rule", obj("any_one", true))
				}
			}
			body := w.editionBody(g, preds, []string{fmt.Sprint("m", i)}, extra...)
			approvers := 1 + rnd(3)
			for j := 0; j < approvers; j++ {
				w.sign(fmt.Sprint("e", i, j), names[rnd(len(names))], "edition", body)
			}
			nodes = append(nodes, w.ids[fmt.Sprint("e", i, 0)])
		}
	}
	return w
}

// TestRevocationBranchR3: finding R3. Controller K forks its own log: one branch revokes the key, the other
// (signed with the compromised key, say) carries an edition. The edition is on a branch the revocation does
// not include, so it never counts toward authority; it is still shown and attributed. A line from before the
// fork (in the revocation's history) keeps counting.
func TestRevocationBranchR3(t *testing.T) {
	w := newWorld(t)
	g := w.genesis("G", "K", 0, "K")
	e1 := w.edition("E1", "K", g, []string{g}, []string{"a"})
	fork := w.head["K"]
	forkSeq := w.seq["K"]
	w.sign("REV", "K", "revoke_key", obj("reason", "key_compromise"))
	// rewind K's head: the next line chains after the same predecessor, a fork in K's log
	w.head["K"], w.seq["K"] = fork, forkSeq
	branch := w.edition("EB", "K", g, []string{e1}, []string{"a", "stolen"})
	everyOrder(t, w, g, func(res *Resource) {
		wantCurrent(t, res, e1)
		wantState(t, res, e1, Authorized, "")
		wantState(t, res, branch, Unauthorized, "")
		e := editionOf(t, res, branch)
		if e.Approvals[0].Counted || !strings.Contains(e.Approvals[0].Why, "does not include") {
			t.Fatalf("branch approval counted: %+v", e.Approvals[0])
		}
		if !res.NoController {
			t.Fatal("revoked sole controller still shown as usable")
		}
	})
}

// TestKOfNSameKeyTwice: C-core-83's distinct-controller half. One controller signs the same body in two
// statements (two lines of its log, two statement ids): still one controller, still pending under 2-of-3.
func TestKOfNSameKeyTwice(t *testing.T) {
	w := newWorld(t)
	g := w.genesis("G", "A", 2, "A", "B", "C")
	body := w.editionBody(g, []string{g}, []string{"a"})
	x1 := w.sign("X1", "A", "edition", body)
	x2 := w.sign("X2", "A", "edition", body)
	if x1 == x2 {
		t.Fatal("fixture: one statement")
	}
	res, _ := w.resolve(g, nil)
	wantState(t, res, x1, Pending, "1 of 2 approvals")
	if n := len(editionOf(t, res, x1).Approvals); n != 2 {
		t.Fatalf("%d approvals listed, want both statements shown", n)
	}
	wantCurrent(t, res, g)
}
