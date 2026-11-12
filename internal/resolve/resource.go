package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/dag"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/policy"
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
// Edition identity (wire-format note §3): an edition's id is EditionID(body), a digest of its body under a
// payload type of its own, so k approvals of one body are one edition whoever signed them. Every field that
// names an edition holds its edition id; a statement id there names nothing (the edition is orphan). Only the
// lookup surface (Resource.Edition: pins, arguments, explain) resolves an approval's statement id to its
// edition (C-core-78).
//
// Key events (claims-model note §4.1) reach editions through their approvals. An approval on a line after its
// key's revocation or rotation counts toward nothing (C-core-99). An approval the sibling rule or a hard
// revocation's last_good leaves out also counts toward nothing, but it may have been the key's legitimate
// word: an edition that would be authorized with it is Contested, and so is everything built on it
// (C-core-143e). A contested edition authorizes nothing and is never current; it is always shown, and a
// resource holding one does not pass verify.
//
// Withdrawals (claims-model note §8, C-core-85b) are applied after the graph is resolved, once, to its tips: a
// tip whose counted approvals fall below its rule is pending again. An edition with an authorized successor is
// locked in.
//
// Nothing here reads `ts`, file order or arrival order: the tip is computed from predecessor links alone, two
// editions with one predecessor are a FORK (package dag), and only a merge edition clears it (C-core-84, 85).

// EditionBodyType is the payload type an rc/1 edition body is hashed under for its edition id
// (equal to wire.EditionBodyType(1); a test pins it). It differs from every statement payload type, so an edition id never equals a
// statement id. This resolver reads rc/1 editions only; one that reads rc/2 must take the major from the
// statement (wire.EditionBodyType(major)), never this constant.
const EditionBodyType = "application/vnd.research-commons.edition-body.v1+json"

// EditionID is the id of the rc/1 edition a body proposes.
func EditionID(body *canon.Object) string {
	h := sha256.Sum256(wire.PAE(EditionBodyType, canon.Encode(body)))
	return hex.EncodeToString(h[:])
}

// EditionIDOf is the id of the edition an edition statement approves, in the domain of the statement's own major
// (identity profile §2.2): an rc/1 approval's is EditionID, a candidate rc/2 approval's is hashed under the v2
// edition-body type, so an rc/1 and an rc/2 approval of the same body bytes approve two different editions.
func EditionIDOf(st *wire.Statement) string {
	if major := majorOf(st); major != 1 {
		h := sha256.Sum256(wire.PAE(wire.EditionBodyType(major), canon.Encode(st.Body)))
		return hex.EncodeToString(h[:])
	}
	return EditionID(st.Body)
}

// majorOf is the format major of a statement's rc ("rc/2" is 2); 1 when it does not parse, which no statement a
// reader evaluates can be (the reader refuses an rc that does not).
func majorOf(st *wire.Statement) int {
	if st == nil || !strings.HasPrefix(st.RC, "rc/") {
		return 1
	}
	n, err := strconv.Atoi(st.RC[len("rc/"):])
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// Controller is one controller subject of a resource: a key, or (candidate rc/2 only) an identity. Exactly one of
// Key and Identity is set. An rc/1 resource only ever has key controllers.
type Controller struct {
	Key, Identity string
}

// String is the subject as one word: the key itself for a key (as rc/1 always printed it), identity:<id> for an
// identity.
func (c Controller) String() string {
	if c.Identity != "" {
		return "identity:" + c.Identity
	}
	return c.Key
}

// short is the display alias: shortKey for a key, identity:<12 hex> for an identity.
func (c Controller) short() string {
	if c.Identity != "" {
		return "identity:" + keylog.Short(c.Identity)
	}
	return shortKey(c.Key)
}

// order is the controller set order: the JCS text of the tagged subject (identity profile §3), which for key
// subjects alone is the key order rc/1 has always used.
func (c Controller) order() string {
	if c.Identity != "" {
		return `{"identity":"` + c.Identity + `"}`
	}
	return `{"key":"` + c.Key + `"}`
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
	// or rules does not declare both (claims-model note §8, C-core-85a).
	Invalid EditionState = "invalid"
	// Contested: authorized only when approvals that a key event doubts are counted, or built on an edition
	// that is (claims-model note §4.1, C-core-143e). Never current; authorizes nothing.
	Contested EditionState = "contested"
)

// Approval is one edition statement counted (or not) toward a proposal.
type Approval struct {
	Statement string
	Signer    string
	// Subject is the effective subject the approval fills a slot for (identity profile §5.2): key(Signer) for a
	// bare-key approval, identity(I) for an identity-context approval the actor evaluator binds to I. Zero for an
	// identity-context approval no evaluator binds: it is no subject's word, and never its key's.
	Subject Controller
	// Grant is the grant an identity-context approval acts under; "" for a bare-key approval. Withdrawal is
	// key-and-grant-local (§5.2).
	Grant string
	// Counted is false when the line is detached, not valid, after a key event of its signer, or doubted by one.
	Counted bool
	// Doubted is true when the line is not counted only because a key event doubts it (§4.1): an edition that
	// would be authorized with it is contested, not unauthorized.
	Doubted bool
	// Withdrawn names the signer's withdraw_approval that took this approval back; "" when none counts.
	Withdrawn string
	Why       string // why it is not counted; "" when counted
}

// Edition is one proposal of a resource and what became of it.
type Edition struct {
	ID           string
	Resource     string
	Predecessors []string      // as edition ids (or the genesis id), sorted; nil for an uninterpreted body
	Body         *canon.Object // retained raw body, not necessarily understood
	Approvals    []Approval    // by signer then statement id
	State        EditionState
	// Explain is one line per reason, citing the rule and the predecessor it was evaluated under.
	Explain []string
	// Controllers and K are the edition's own authority: what its successors are evaluated under. Set for
	// Authorized editions only. K is the number of distinct controller subjects the rule needs (1 for any_one).
	Controllers []Controller
	K           int
	// Major is the format major of the edition's approvals (its id domain); 0 for an uninterpreted body.
	Major int
	// Members, as the edition lists them; nil when absent or the body is not understood.
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
	// RevokedControllers lists the current edition's controllers with an in-force revoke_key or rotate_key,
	// with its id (a rotation retires the key; roles do not follow it, §4.1).
	RevokedControllers map[string]string
	// Contested lists the contested editions by id. A resource with one does not pass verify.
	Contested []string
	// GenesisControllers and GenesisK are the genesis's authority: what its first editions are evaluated under.
	GenesisControllers []Controller
	GenesisK           int
}

// authority is a node's controllers and rule.
type authority struct {
	controllers []Controller
	k           int
}

func (a authority) has(c Controller) bool {
	return c != (Controller{}) && slices.Contains(a.controllers, c)
}

func (a authority) describe() string {
	rule := "any one"
	if a.k > 1 {
		rule = fmt.Sprintf("%d of %d", a.k, len(a.controllers))
	}
	short := make([]string, len(a.controllers))
	for i, c := range a.controllers {
		short[i] = c.short()
	}
	return rule + " of {" + strings.Join(short, ",") + "}"
}

// Resource resolves the resource whose genesis statement is id. ok is false when no genesis with that id is
// held, or the held one has not chained or is not valid (it is shown by the log, and resolves nothing yet).
func (r *Resolver) Resource(id string) (*Resource, bool) {
	g, ok := r.byID[id]
	if !ok || g.St.Kind != "genesis" || !g.EvidenceReady() {
		return nil, false
	}
	res := &Resource{ID: id, Genesis: g, RevokedControllers: map[string]string{}}
	res.Type, res.Name, res.ForkedFrom = str(g.St.Body, "type"), str(g.St.Body, "name"), str(g.St.Body, "forked_from")
	genAuth, _ := authorityOf(g.St.Body, majorOf(g.St))
	res.GenesisControllers, res.GenesisK = genAuth.controllers, genAuth.k

	// Group approvals by raw body. A string resource field associates retained evidence for display only;
	// unsupported bodies have not passed the kind's schema and must not supply members or predecessor links.
	props := map[string]*Edition{}
	understood := map[string]bool{} // at least one verified, valid approval has schema-checked this exact body
	alias := map[string]string{}    // approval statement id -> edition id
	for _, p := range r.byKind["edition"] {
		if str(p.St.Body, "resource") != id {
			continue
		}
		eid := EditionIDOf(p.St)
		e, ok := props[eid]
		if !ok {
			e = &Edition{ID: eid, Resource: id, Body: p.St.Body}
			props[eid] = e
		}
		// Schema validity is separate from chaining: well-formed detached proposals keep their display,
		// but no approval counts until it is evaluable and its signer's key events let it count.
		if p.St.Verified && p.St.Status == wire.Valid {
			understood[eid] = true
			e.Major = majorOf(p.St)
		}
		alias[p.St.ID] = eid
		e.Approvals = append(e.Approvals, r.approval(p))
	}
	// Predecessors are edition ids (or the genesis id) as written: a statement id names no edition (§3).
	for _, e := range props {
		slices.SortFunc(e.Approvals, func(a, b Approval) int {
			return strings.Compare(a.Signer+a.Statement, b.Signer+b.Statement)
		})
		if !understood[e.ID] {
			e.Major = 0
		}
		if !understood[e.ID] {
			continue
		}
		if c, ok := e.Body.Get("contents"); ok {
			if m, ok := c.(*canon.Object).Get("members"); ok {
				e.Members = m.(canon.Array)
			}
		}
		e.Predecessors = ids(e.Body, "predecessors")
		slices.Sort(e.Predecessors)
		e.Predecessors = slices.Compact(e.Predecessors)
	}

	// Authorization is a fixed point: a proposal can become an edition only once every predecessor is the
	// genesis or an edition. Predecessor links go strictly backwards in the set of held bodies (a body names its
	// predecessors' ids, which are hashes over their bodies), so there are no cycles and this terminates.
	auth := map[string]authority{id: genAuth}
	contested := map[string]authority{} // the authority a contested edition would have
	for changed := true; changed; {
		changed = false
		for _, eid := range sortedKeys(props) {
			e := props[eid]
			if e.State == Authorized || e.State == Invalid || e.State == Contested {
				continue
			}
			if r.evaluate(e, auth, contested, props, alias) {
				changed = true
			}
		}
	}

	graph := func() map[string]dag.Node {
		g := map[string]dag.Node{id: {}}
		for _, eid := range sortedKeys(props) {
			if props[eid].State == Authorized {
				g[eid] = dag.Node{Branch: props[eid].Predecessors}
			}
		}
		return g
	}
	// Withdrawals: once, to the tips of the graph resolved without them (§8, C-core-85b).
	for _, tip := range dag.Tips(graph()) {
		if e, ok := props[tip]; ok && r.withdraw(e, id, auth) {
			delete(auth, tip)
		}
	}
	final := graph()
	for _, eid := range sortedKeys(props) {
		res.Editions = append(res.Editions, props[eid])
		if props[eid].State == Contested {
			res.Contested = append(res.Contested, eid)
		}
	}
	res.Tips = dag.Tips(final)
	res.Forks = dag.Forks(final)
	if len(res.Tips) == 1 {
		res.Current = res.Tips[0]
		cur := auth[res.Current]
		usable := 0
		for _, c := range cur.controllers {
			// An identity controller's usability is its root's and grants' (identity profile §4), not a key
			// event's: it is counted usable here, and NoController never reads it as lost.
			if ev, revoked := r.retiredKey(c.Key); c.Key != "" && revoked {
				res.RevokedControllers[c.Key] = ev
			} else {
				usable++
			}
		}
		res.NoController = usable < cur.k
	}
	return res, true
}

// evaluate decides one proposal against the authority map. It returns true when the proposal reached a
// terminal state (Authorized, Contested, Invalid), so the fixed point re-runs. A predecessor that is contested
// lends its would-be authority, and the proposal is contested with it (C-core-143e).
func (r *Resolver) evaluate(e *Edition, auth, contested map[string]authority, props map[string]*Edition, alias map[string]string) bool {
	e.Explain = nil
	// Slots are effective subjects (identity profile §5.2): two delegates of one identity fill its one slot, and a
	// key's raw approval and its identity approval are two subjects' words, neither filling the other's slot.
	counted, doubted := map[Controller]bool{}, map[Controller]bool{}
	for _, a := range e.Approvals {
		switch {
		case a.Counted:
			counted[a.Subject] = true
		case a.Doubted:
			doubted[a.Subject] = true
		}
	}
	if len(counted) == 0 && len(doubted) == 0 {
		e.State = Detached
		for _, a := range e.Approvals {
			e.Explain = append(e.Explain, fmt.Sprintf("approval %s by %s not counted: %s", keylog.Short(a.Statement), a.by(), a.Why))
		}
		if !allDetached(e.Approvals) {
			e.State = Unauthorized
		}
		return false
	}
	state := Authorized
	worse := func(s EditionState) {
		rank := map[EditionState]int{Authorized: 0, Contested: 1, Pending: 2, Unauthorized: 3, Orphan: 4}
		if rank[s] > rank[state] {
			state = s
		}
	}
	var preds []authority
	for _, p := range e.Predecessors {
		pa, ok := auth[p]
		if !ok {
			if ca, isC := contested[p]; isC {
				pa = ca
				e.Explain = append(e.Explain, fmt.Sprintf("predecessor %s is contested", keylog.Short(p)))
				worse(Contested)
			} else {
				why := "names nothing held for this resource"
				if q, held := props[p]; held {
					why = "is not an edition (" + string(q.State) + ")"
				} else if to, isStmt := alias[p]; isStmt {
					why = "is the statement id of an approval of " + keylog.Short(to) + ", not an edition id"
				}
				e.Explain = append(e.Explain, fmt.Sprintf("predecessor %s %s", keylog.Short(p), why))
				worse(Orphan)
				continue
			}
		}
		preds = append(preds, pa)
		n, nd := 0, 0
		for s := range counted {
			if pa.has(s) {
				n++
			}
		}
		for s := range doubted {
			if pa.has(s) && !counted[s] {
				nd++
			}
		}
		switch {
		case n >= pa.k:
			e.Explain = append(e.Explain, fmt.Sprintf("authorized under %s: %s, %d approval(s)", keylog.Short(p), pa.describe(), n))
		case n+nd >= pa.k:
			e.Explain = append(e.Explain, fmt.Sprintf("contested under %s: %s, %d counted approval(s) and %d a key event doubts", keylog.Short(p), pa.describe(), n, nd))
			worse(Contested)
		case n+nd > 0:
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
	if state != Authorized && state != Contested {
		e.State = state
		return false
	}
	own, err := successorAuthority(e.Body, e.Major, preds)
	if err != "" {
		e.State = Invalid
		e.Explain = append(e.Explain, err)
		return true
	}
	e.State = state
	if state == Contested {
		for _, a := range e.Approvals {
			if a.Doubted {
				e.Explain = append(e.Explain, fmt.Sprintf("approval %s by %s doubted: %s", keylog.Short(a.Statement), a.by(), a.Why))
			}
		}
		contested[e.ID] = own
		return true
	}
	auth[e.ID] = own
	e.Controllers, e.K = own.controllers, own.k
	return true
}

// approval reads one edition statement as an approval: whose word it is (its effective subject) and whether it
// counts. A bare-key approval (every rc/1 line, and a marker-only rc/2 line) is key(signer)'s, under the bare-key
// gate exactly as before. An identity-context approval is identity(I)'s only when the actor evaluator binds it to
// I (identity profile §5.2), through the counting gate: eligible counts; unknown, or denied by a grant-history cut
// that removes it, is doubted (an edition that needs it is contested, never authorized and never silently
// unauthorized); any other denial counts toward nothing. It never fills its key's slot, whatever the answer, and
// with no evaluator (every production reader) it counts toward nothing with the hook-absent text.
func (r *Resolver) approval(p *Placed) Approval {
	a := Approval{Statement: p.St.ID, Signer: p.St.Signer, Counted: true, Subject: Controller{Key: p.St.Signer}}
	switch {
	case !p.Chained:
		a.Counted, a.Why = false, "detached"
	case !p.EvidenceReady():
		a.Counted, a.Why = false, string(p.St.Status)
	case p.IdentityContext():
		a.Subject, a.Grant = Controller{}, p.St.Actor.Grant
		g := r.gate(p)
		if g.Identity == "" {
			a.Counted, a.Why = false, g.Why
			break
		}
		a.Subject = Controller{Identity: g.Identity}
		switch {
		case g.Counts:
		case g.State == policy.ActorDenied && !cutExcluded(g.Reasons):
			a.Counted, a.Why = false, g.Why
		default:
			a.Counted, a.Doubted, a.Why = false, true, g.Why
		}
	case len(p.After) > 0:
		a.Counted, a.Why = false, p.After[0]
	case len(p.Doubted) > 0:
		a.Counted, a.Doubted, a.Why = false, true, strings.Join(p.Doubted, "; ")
	}
	return a
}

// cutExcluded reports whether an evaluator's denial rests on a grant-history cut that leaves the statement out
// (identity profile §4, §5.2: a cut that removes a required approval makes the edition contested, as a hard
// revocation's last_good does for a key, claims-model note §4.1).
func cutExcluded(reasons []string) bool {
	for _, x := range reasons {
		if x == "cut_excluded" || strings.HasPrefix(x, "cut_excluded:") {
			return true
		}
	}
	return false
}

// by is who an approval is from, for display: its signer, and the identity it acts for when it acts for one.
func (a Approval) by() string {
	if a.Subject.Identity != "" {
		return shortKey(a.Signer) + " for " + a.Subject.short()
	}
	if a.Grant != "" {
		return shortKey(a.Signer) + " (identity context, bound to no identity)"
	}
	return shortKey(a.Signer)
}

// withdraw applies the controllers' withdraw_approval statements to e, a tip of the resolved graph (§8,
// C-core-85b). An approval is withdrawn when its signer has a counting withdrawal of e that no later approval
// of e by the same key follows in that key's log. When the approvals left no longer satisfy some predecessor's
// rule, e is pending again and withdraw returns true.
func (r *Resolver) withdraw(e *Edition, resource string, auth map[string]authority) bool {
	if e.State != Authorized {
		return false
	}
	// A withdrawal is key-and-grant-local (identity profile §5.2): it takes back the approvals its signer made in
	// the same context, a bare-key withdrawal the key's bare-key approvals and an identity withdrawal the key's
	// approvals under the same grant. One delegate never withdraws another's approval, and a new grant never
	// cancels an approval made under another. An identity withdrawal counts only through the actor evaluator.
	type ctx struct{ signer, grant string }
	var ws []*Placed
	wctx := map[string]ctx{}
	for _, p := range r.byKind["withdraw_approval"] {
		if str(p.St.Body, "edition") != e.ID || str(p.St.Body, "resource") != resource {
			continue
		}
		switch {
		case p.IdentityContext():
			if g := r.gate(p); g.Identity == "" || !g.Counts {
				continue
			}
			wctx[p.St.ID] = ctx{p.St.Signer, p.St.Actor.Grant}
		case r.countsAsKey(p):
			wctx[p.St.ID] = ctx{p.St.Signer, ""}
		default:
			continue
		}
		ws = append(ws, p)
	}
	if len(ws) == 0 {
		return false
	}
	withdrawn := map[ctx]string{} // signer and grant -> withdrawal id
	for _, w := range ws {
		c := wctx[w.St.ID]
		followed, signed := false, false
		for _, a := range e.Approvals {
			if !a.Counted || a.Signer != c.signer || a.Grant != c.grant {
				continue
			}
			signed = true
			if r.precedes(a.Signer, w.St.ID, a.Statement) {
				followed = true
			}
		}
		if signed && !followed {
			if prev, ok := withdrawn[c]; !ok || w.St.ID < prev {
				withdrawn[c] = w.St.ID
			}
		}
	}
	if len(withdrawn) == 0 {
		return false
	}
	left := map[Controller]bool{}
	for i, a := range e.Approvals {
		if w, ok := withdrawn[ctx{a.Signer, a.Grant}]; ok && a.Counted {
			e.Approvals[i].Withdrawn = w
			continue
		}
		if a.Counted {
			left[a.Subject] = true
		}
	}
	order := make([]ctx, 0, len(withdrawn))
	for c := range withdrawn {
		order = append(order, c)
	}
	slices.SortFunc(order, func(a, b ctx) int { return strings.Compare(a.signer+"|"+a.grant, b.signer+"|"+b.grant) })
	for _, c := range order {
		by := shortKey(c.signer)
		if c.grant != "" {
			by += " under grant " + keylog.Short(c.grant)
		}
		e.Explain = append(e.Explain, fmt.Sprintf("approval by %s withdrawn by %s", by, keylog.Short(withdrawn[c])))
	}
	for _, p := range e.Predecessors {
		pa := auth[p]
		n := 0
		for s := range left {
			if pa.has(s) {
				n++
			}
		}
		if n < pa.k {
			e.State = Pending
			e.Controllers, e.K = nil, 0
			e.Explain = append(e.Explain, fmt.Sprintf("pending under %s after withdrawal: %s, %d of %d approvals", keylog.Short(p), pa.describe(), n, pa.k))
			return true
		}
	}
	return false
}

// successorAuthority is what an authorized edition's successors are evaluated under: its own `controllers` and
// `rule` when it declares them (a controller change), each inherited from its predecessors when they agree.
func successorAuthority(body *canon.Object, major int, preds []authority) (authority, string) {
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
		out.controllers = controllersOf(c, major)
	}
	if hasRule {
		out.k = ruleK(c.Members["rule"].(*canon.Object))
	}
	if out.k > len(out.controllers) || len(out.controllers) == 0 {
		return authority{}, fmt.Sprintf("invalid: controller change leaves rule %d of %d: no set of its controllers satisfies it", out.k, len(out.controllers))
	}
	return out, ""
}

func authorityOf(body *canon.Object, major int) (authority, bool) {
	a := authority{controllers: controllersOf(body, major)}
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
// 3 under an uncleared FORK (C-core-84: no tip; could not check which edition is current) or with a contested
// edition (§4.1: a key event doubts approvals it needs; contested never reads as pass).
func (res *Resource) VerifyExit() int {
	if res.Current == "" || len(res.Contested) > 0 {
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
	if len(res.Contested) > 0 {
		fmt.Fprintf(&b, "  contested: %s\n", shorts(res.Contested))
	}
	for _, c := range sortedKeys(res.RevokedControllers) {
		fmt.Fprintf(&b, "  controller %s revoked by %s\n", shortKey(c), keylog.Short(res.RevokedControllers[c]))
	}
	for _, e := range res.Editions {
		fmt.Fprintf(&b, "  %s %s after %s\n", e.State, keylog.Short(e.ID), shorts(e.Predecessors))
		for _, a := range e.Approvals {
			note := "counted"
			switch {
			case a.Withdrawn != "":
				note = "withdrawn by " + keylog.Short(a.Withdrawn)
			case !a.Counted:
				note = "not counted: " + a.Why
			}
			fmt.Fprintf(&b, "    approval %s by %s (%s)\n", keylog.Short(a.Statement), a.by(), note)
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

// controllersOf reads o's `controllers`: a set of keys in rc/1, of typed subjects ({key: K} or {identity: I}) in
// the candidate rc/2 (identity profile §2.1). The schema of the body's major already checked the shape; sorted
// here by the profile's subject order so comparisons are plain (for keys alone, the key order rc/1 has always
// used).
func controllersOf(o *canon.Object, major int) []Controller {
	v, ok := o.Get("controllers")
	if !ok {
		return nil
	}
	var out []Controller
	for _, x := range v.(canon.Array) {
		switch y := x.(type) {
		case canon.String:
			if major == 1 {
				out = append(out, Controller{Key: string(y)})
			}
		case *canon.Object:
			if major == 1 {
				continue
			}
			if k, ok := y.Get("key"); ok {
				out = append(out, Controller{Key: string(k.(canon.String))})
			} else if i, ok := y.Get("identity"); ok {
				out = append(out, Controller{Identity: string(i.(canon.String))})
			}
		}
	}
	slices.SortFunc(out, func(a, b Controller) int { return strings.Compare(a.order(), b.order()) })
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

func signers(m map[Controller]bool) string {
	cs := make([]Controller, 0, len(m))
	for c := range m {
		cs = append(cs, c)
	}
	slices.SortFunc(cs, func(a, b Controller) int { return strings.Compare(a.order(), b.order()) })
	var s []string
	for _, c := range cs {
		s = append(s, c.short())
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
