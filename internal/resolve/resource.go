package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/dag"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// Resources: collections, tasks, series (claims-model note §8; wire-format note §5 `genesis`, `edition`).
//
// A resource is a genesis statement; its id is the genesis statement id (C-core-77). An edition statement is
// one controller's approval of an edition body. Approvals of byte-identical bodies (the whole canonical body:
// resource, predecessors, contents and any extension fields) are approvals of one proposal (C-core-82, 83).
// A proposal becomes an edition when, for every predecessor it names, the distinct controllers of that
// predecessor who approved it satisfy that predecessor's rule (§8: controller changes are authorized under the
// previous edition's rule; a merge is authorized under each predecessor's rule; nobody elevates themselves).
//
// Edition identity (finding R1 in the PR description; a docs PR follows the decision): an edition's id is EditionID(body), a digest of its body under
// a payload type of its own, so k approvals of one body are one edition whoever signed them. Any approval's
// statement id resolves to the same edition, so under an any-one rule, where an edition is one statement, the
// statement id still names it (wire-format note §3, C-core-78). Predecessors may name either form.
//
// Nothing here reads `ts`, file order or arrival order: the tip is computed from predecessor links alone, two
// editions with one predecessor are a FORK (package dag), and only a merge edition clears it (C-core-84, 85).

// EditionBodyType is the payload type an edition body is hashed under for its edition id. It differs from every
// statement payload type, so an edition id never equals a statement id.
const EditionBodyType = "application/vnd.research-commons.edition-body.v1+json"

// EditionID is the id of the edition a body proposes.
func EditionID(body *canon.Object) string {
	h := sha256.Sum256(wire.PAE(EditionBodyType, canon.Encode(body)))
	return hex.EncodeToString(h[:])
}

// EditionState is what became of a proposal.
type EditionState string

const (
	// Authorized: an edition of the resource.
	Authorized EditionState = "edition"
	// Pending: approved by some controllers of every predecessor, not yet enough for one predecessor's rule.
	Pending EditionState = "pending"
	// Unauthorized: some predecessor's controllers did not approve it at all (C-core-81, C-core-99).
	Unauthorized EditionState = "unauthorized"
	// Orphan: a predecessor names nothing this reader holds as the genesis or an edition of the resource
	// (C-core-79). Never current. Re-evaluated when the predecessor arrives.
	Orphan EditionState = "orphan"
	// Detached: every approval is on a line that has not chained; shown, not evaluated (C-core-143).
	Detached EditionState = "detached"
	// Invalid: authorized approvals, but the edition cannot mean what an edition means: its controller change
	// leaves a rule no set of its controllers can meet, or a merge of predecessors with different controllers
	// names none of its own (finding R2 in the PR description).
	Invalid EditionState = "invalid"
)

// Approval is one edition statement counted (or not) toward a proposal.
type Approval struct {
	Statement string
	Signer    string
	// Counted is false when the line is detached, not valid, or after an in-force revocation of its key.
	Counted bool
	Why     string // why it is not counted; "" when counted
}

// Edition is one proposal of a resource and what became of it.
type Edition struct {
	ID           string
	Resource     string
	Predecessors []string // as edition ids (or the genesis id), sorted
	Body         *canon.Object
	Approvals    []Approval // by signer then statement id
	State        EditionState
	// Explain is one line per reason, citing the rule and the predecessor it was evaluated under.
	Explain []string
	// Controllers and K are the edition's own authority: what its successors are evaluated under. Set for
	// Authorized editions only. K is the number of distinct controllers the rule needs (1 for any_one).
	Controllers []string
	K           int
	// Members, as the edition lists them; nil when absent.
	Members canon.Array
}

// Resource is the view of one resource.
type Resource struct {
	ID         string
	Type, Name string
	ForkedFrom string
	Genesis    *Placed
	// Editions are every proposal naming this resource, by id.
	Editions []*Edition
	// Tips are the heads of the authorized edition graph (the genesis when no edition is authorized).
	Tips []string
	// Forks are the fork points of the authorized edition graph, cleared or not.
	Forks []dag.Fork
	// Current is the one tip when there is exactly one; "" under an uncleared FORK.
	Current string
	// NoController is set when every controller of the current edition has revoked its key, or too few remain
	// for its rule: no further edition can exist (§8 "a lost controller key ends the resource", C-core-99).
	NoController bool
	// RevokedControllers lists the current edition's controllers with an in-force revoke_key, with its id.
	RevokedControllers map[string]string
}

// authority is a node's controllers and rule.
type authority struct {
	controllers []string
	k           int
}

func (a authority) has(key string) bool { return slices.Contains(a.controllers, key) }

func (a authority) describe() string {
	rule := "any one"
	if a.k > 1 {
		rule = fmt.Sprintf("%d of %d", a.k, len(a.controllers))
	}
	short := make([]string, len(a.controllers))
	for i, c := range a.controllers {
		short[i] = shortKey(c)
	}
	return rule + " of {" + strings.Join(short, ",") + "}"
}

// Resource resolves the resource whose genesis statement is id. ok is false when no genesis with that id is
// held, or the held one has not chained or is not valid (it is shown by the log, and resolves nothing yet).
func (r *Resolver) Resource(id string) (*Resource, bool) {
	g, ok := r.byID[id]
	if !ok || g.St.Kind != "genesis" || !g.Evaluable {
		return nil, false
	}
	res := &Resource{ID: id, Genesis: g, RevokedControllers: map[string]string{}}
	res.Type, res.Name, res.ForkedFrom = str(g.St.Body, "type"), str(g.St.Body, "name"), str(g.St.Body, "forked_from")
	genAuth, _ := authorityOf(g.St.Body)

	// Group approvals by body.
	props := map[string]*Edition{}
	alias := map[string]string{} // approval statement id -> edition id
	for _, p := range r.byKind["edition"] {
		if str(p.St.Body, "resource") != id {
			continue
		}
		eid := EditionID(p.St.Body)
		e, ok := props[eid]
		if !ok {
			e = &Edition{ID: eid, Resource: id, Body: p.St.Body}
			if c, ok := p.St.Body.Get("contents"); ok {
				if m, ok := c.(*canon.Object).Get("members"); ok {
					e.Members = m.(canon.Array)
				}
			}
			props[eid] = e
		}
		alias[p.St.ID] = eid
		a := Approval{Statement: p.St.ID, Signer: p.St.Signer, Counted: true}
		switch {
		case !p.Chained:
			a.Counted, a.Why = false, "detached"
		case !p.Evaluable:
			a.Counted, a.Why = false, string(p.St.Status)
		case len(p.RevokedAfter) > 0:
			a.Counted, a.Why = false, "after revoke_key "+keylog.Short(p.RevokedAfter[0])
		case len(p.Revoked) > 0:
			a.Counted, a.Why = false, "on a branch revoke_key "+keylog.Short(p.Revoked[0])+" does not include (finding R3)"
		}
		e.Approvals = append(e.Approvals, a)
	}
	// Predecessors normalised to edition ids (or the genesis id). An id that is neither stays as written and
	// resolves to nothing.
	for _, e := range props {
		slices.SortFunc(e.Approvals, func(a, b Approval) int {
			return strings.Compare(a.Signer+a.Statement, b.Signer+b.Statement)
		})
		for _, v := range ids(e.Body, "predecessors") {
			if to, ok := alias[v]; ok {
				v = to
			}
			e.Predecessors = append(e.Predecessors, v)
		}
		slices.Sort(e.Predecessors)
		e.Predecessors = slices.Compact(e.Predecessors)
	}

	// Authorization is a fixed point: a proposal can become an edition only once every predecessor is the
	// genesis or an edition. Predecessor links go strictly backwards in the set of held bodies (a body names its
	// predecessors' ids, which are hashes over their bodies), so there are no cycles and this terminates.
	auth := map[string]authority{id: genAuth}
	for changed := true; changed; {
		changed = false
		for _, eid := range sortedKeys(props) {
			e := props[eid]
			if e.State == Authorized || e.State == Invalid {
				continue
			}
			if r.evaluate(e, auth, props) {
				changed = true
			}
		}
	}

	graph := map[string]dag.Node{id: {}}
	for _, eid := range sortedKeys(props) {
		e := props[eid]
		res.Editions = append(res.Editions, e)
		if e.State == Authorized {
			graph[eid] = dag.Node{Branch: e.Predecessors}
		}
	}
	res.Tips = dag.Tips(graph)
	res.Forks = dag.Forks(graph)
	if len(res.Tips) == 1 {
		res.Current = res.Tips[0]
		cur := auth[res.Current]
		usable := 0
		for _, c := range cur.controllers {
			if ev, revoked := r.revokedKey(c); revoked {
				res.RevokedControllers[c] = ev
			} else {
				usable++
			}
		}
		res.NoController = usable < cur.k
	}
	return res, true
}

// evaluate decides one proposal against the current authority map. It returns true when the proposal became an
// edition or reached a terminal state, so the fixed point re-runs.
func (r *Resolver) evaluate(e *Edition, auth map[string]authority, props map[string]*Edition) bool {
	e.Explain = nil
	counted := map[string]bool{}
	for _, a := range e.Approvals {
		if a.Counted {
			counted[a.Signer] = true
		}
	}
	if len(counted) == 0 {
		e.State = Detached
		for _, a := range e.Approvals {
			e.Explain = append(e.Explain, fmt.Sprintf("approval %s by %s not counted: %s", keylog.Short(a.Statement), shortKey(a.Signer), a.Why))
		}
		if !allDetached(e.Approvals) {
			e.State = Unauthorized
		}
		return false
	}
	state := Authorized
	worse := func(s EditionState) {
		rank := map[EditionState]int{Authorized: 0, Pending: 1, Unauthorized: 2, Orphan: 3}
		if rank[s] > rank[state] {
			state = s
		}
	}
	var preds []authority
	for _, p := range e.Predecessors {
		pa, ok := auth[p]
		if !ok {
			why := "names nothing held for this resource"
			if q, held := props[p]; held {
				why = "is not an edition (" + string(q.State) + ")"
			}
			e.Explain = append(e.Explain, fmt.Sprintf("predecessor %s %s", keylog.Short(p), why))
			worse(Orphan)
			continue
		}
		preds = append(preds, pa)
		n := 0
		for s := range counted {
			if pa.has(s) {
				n++
			}
		}
		switch {
		case n >= pa.k:
			e.Explain = append(e.Explain, fmt.Sprintf("authorized under %s: %s, %d approval(s)", keylog.Short(p), pa.describe(), n))
		case n > 0:
			e.Explain = append(e.Explain, fmt.Sprintf("pending under %s: %s, %d of %d approvals", keylog.Short(p), pa.describe(), n, pa.k))
			worse(Pending)
		default:
			e.Explain = append(e.Explain, fmt.Sprintf("unauthorized under %s: %s; approved by %s", keylog.Short(p), pa.describe(), signers(counted)))
			worse(Unauthorized)
		}
	}
	if len(e.Predecessors) == 0 {
		e.Explain = append(e.Explain, "names no predecessor")
		worse(Orphan)
	}
	e.State = state
	if state != Authorized {
		return false
	}
	own, err := successorAuthority(e.Body, preds)
	if err != "" {
		e.State = Invalid
		e.Explain = append(e.Explain, err)
		return true
	}
	auth[e.ID] = own
	e.Controllers, e.K = own.controllers, own.k
	return true
}

// successorAuthority is what an authorized edition's successors are evaluated under: its own `controllers` and
// `rule` when it declares them (a controller change), each inherited from its predecessors when they agree.
func successorAuthority(body *canon.Object, preds []authority) (authority, string) {
	contents, _ := body.Get("contents")
	c, _ := contents.(*canon.Object)
	inherit := func() (authority, bool) {
		for _, p := range preds[1:] {
			if !slices.Equal(p.controllers, preds[0].controllers) || p.k != preds[0].k {
				return authority{}, false
			}
		}
		return preds[0], true
	}
	base, agree := inherit()
	_, hasCtrl := c.Get("controllers")
	_, hasRule := c.Get("rule")
	if !agree && !(hasCtrl && hasRule) {
		return authority{}, "invalid: a merge of predecessors with different controllers or rules must declare both (finding R2)"
	}
	out := base
	if hasCtrl {
		out.controllers = keys(c, "controllers")
	}
	if hasRule {
		out.k = ruleK(c.Members["rule"].(*canon.Object))
	}
	if out.k > len(out.controllers) || len(out.controllers) == 0 {
		return authority{}, fmt.Sprintf("invalid: controller change leaves rule %d of %d: no set of its controllers satisfies it", out.k, len(out.controllers))
	}
	return out, ""
}

func authorityOf(body *canon.Object) (authority, bool) {
	a := authority{controllers: keys(body, "controllers")}
	rule, ok := body.Get("rule")
	if !ok {
		return a, false
	}
	a.k = ruleK(rule.(*canon.Object))
	return a, true
}

// ruleK reads a rule object: any_one is k=1; k_of_n is its k.
func ruleK(rule *canon.Object) int {
	if kn, ok := rule.Get("k_of_n"); ok {
		return int(kn.(*canon.Object).Members["k"].(canon.Int))
	}
	return 1
}

func allDetached(as []Approval) bool {
	for _, a := range as {
		if a.Why != "detached" {
			return false
		}
	}
	return true
}

// Edition resolves an edition by its edition id or by the statement id of any of its approvals (C-core-78:
// pinning an edition by its statement hash).
func (res *Resource) Edition(id string) (*Edition, bool) {
	for _, e := range res.Editions {
		if e.ID == id {
			return e, true
		}
		for _, a := range e.Approvals {
			if a.Statement == id {
				return e, true
			}
		}
	}
	return nil, false
}

// VerifyExit is the `verify` exit code for the resource (claims-model note §13): 0 with one current edition,
// 3 under an uncleared FORK (C-core-84: no tip; could not check which edition is current).
func (res *Resource) VerifyExit() int {
	if res.Current == "" {
		return 3
	}
	return 0
}

// Render is the resource display. It is a function of the view only.
func (res *Resource) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %q", res.Type, keylog.Short(res.ID), res.Name)
	if res.ForkedFrom != "" {
		fmt.Fprintf(&b, " forked-from %s", keylog.Short(res.ForkedFrom))
	}
	b.WriteString("\n")
	for _, f := range res.Forks {
		br := shorts(f.Branches)
		if f.Cleared() {
			fmt.Fprintf(&b, "  FORK at %s: editions %s, cleared by %s (merged)\n", keylog.Short(f.At), br, keylog.Short(f.ClearedBy))
		} else {
			fmt.Fprintf(&b, "  FORK at %s: editions %s, tips %s\n", keylog.Short(f.At), br, shorts(f.Tips))
		}
	}
	switch {
	case res.Current == res.ID:
		b.WriteString("  current: genesis (no edition yet)\n")
	case res.Current != "":
		fmt.Fprintf(&b, "  current: %s\n", keylog.Short(res.Current))
	default:
		fmt.Fprintf(&b, "  current: none (FORK; tips %s)\n", shorts(res.Tips))
	}
	if res.NoController {
		b.WriteString("  no authorized controller: no further edition can exist\n")
	}
	for _, c := range sortedKeys(res.RevokedControllers) {
		fmt.Fprintf(&b, "  controller %s revoked by %s\n", shortKey(c), keylog.Short(res.RevokedControllers[c]))
	}
	for _, e := range res.Editions {
		fmt.Fprintf(&b, "  %s %s after %s\n", e.State, keylog.Short(e.ID), shorts(e.Predecessors))
		for _, a := range e.Approvals {
			note := "counted"
			if !a.Counted {
				note = "not counted: " + a.Why
			}
			fmt.Fprintf(&b, "    approval %s by %s (%s)\n", keylog.Short(a.Statement), shortKey(a.Signer), note)
		}
		for _, x := range e.Explain {
			fmt.Fprintf(&b, "    %s\n", x)
		}
	}
	return b.String()
}

// helpers

func str(o *canon.Object, k string) string {
	if o == nil {
		return ""
	}
	if v, ok := o.Get(k); ok {
		if s, ok := v.(canon.String); ok {
			return string(s)
		}
	}
	return ""
}

func ids(o *canon.Object, k string) []string {
	v, ok := o.Get(k)
	if !ok {
		return nil
	}
	var out []string
	for _, x := range v.(canon.Array) {
		out = append(out, string(x.(canon.String)))
	}
	return out
}

func keys(o *canon.Object, k string) []string {
	out := ids(o, k)
	slices.Sort(out) // the schema already refused an unsorted set; sorted here so comparisons are plain
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func signers(m map[string]bool) string {
	var s []string
	for _, k := range sortedKeys(m) {
		s = append(s, shortKey(k))
	}
	return strings.Join(s, ",")
}

func shorts(xs []string) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = keylog.Short(x)
	}
	return strings.Join(s, ",")
}

// shortKey is a display alias for a key: the algorithm prefix kept, 12 characters of the rest.
func shortKey(k string) string {
	if strings.HasPrefix(k, "ed25519:") && len(k) > 20 {
		return k[:20]
	}
	if len(k) > 14 {
		return k[:14]
	}
	return k
}
