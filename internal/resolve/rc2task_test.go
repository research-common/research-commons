package resolve

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// rc/2 task statements over real signed evidence (fixed-root identity profile §5.3, task-contracts note §3.2):
// identities incepted and granted task-scoped permissions by root keys, rc/2 task editions carrying task_roles,
// intents, submissions and decisions signed by delegate keys, all read by the candidate dual-major reader with
// the real actor evaluator (identity.Actors) over the same bytes. Nothing builds an evaluator answer by hand.

// taskIDWorld is a world with a task genesis G (rc/2, raw key R) and identities incepted on demand.
type taskIDWorld struct {
	*world
	G, last string
}

func newTaskIDWorld(t *testing.T, workers ...string) *taskIDWorld {
	w := newWorld(t)
	for _, k := range workers {
		w.authored(k+"-0", k, k+"-zero") // each worker's seq-0 line: the delegate inception a grant pins
	}
	g := w.signRC2("G", "R", "genesis", obj("type", "task", "name", "t", "controllers", canon.Array{obj("key", w.signer("R"))},
		"rule", obj("any_one", true)), rc2MarkerOnly, [2]string{})
	return &taskIDWorld{world: w, G: g}
}

// incept signs an identity inception by a fresh root key.
func (w *taskIDWorld) incept(name, root string) string {
	return w.signRC2(name, root, "identity_inception", obj("profile", wire.FixedRootProfile), rc2MarkerOnly, [2]string{})
}

// taskGrant signs a grant of identity i (root key root) to worker for kinds over exactly task G.
func (w *taskIDWorld) taskGrant(name, root, i, worker string, kinds ...string) string {
	var perms canon.Array
	for _, k := range kinds {
		perms = append(perms, obj("kind", k, "targets", obj("tasks", []string{w.G})))
	}
	slices.SortFunc(perms, func(a, b canon.Value) int { return canon.CompareKeys(string(canon.Encode(a)), string(canon.Encode(b))) })
	return w.signRC2(name, root, "identity_grant", obj("identity", i,
		"delegate", obj("key", w.signer(worker), "inception", w.firstLine(worker)), "permissions", perms), rc2MarkerOnly, [2]string{})
}

// edition2 signs an rc/2 edition of G by R (raw) after the last edition it signed (the genesis first), so the
// editions form one line; it records and returns the edition id (the v2 edition-body domain over the body as
// signed, marker included).
func (w *taskIDWorld) edition2(name string, roles, contract *canon.Object) string {
	pred := w.G
	if w.last != "" {
		pred = w.last
	}
	b := withMember(obj("resource", w.G, "predecessors", []string{pred}, "contents", obj("contract", contract)),
		wire.IdentityCrit, obj("task_roles", roles))
	w.signRC2(name, "R", "edition", b, rc2MarkerOnly, [2]string{})
	eid := EditionIDOf(&wire.Statement{RC: "rc/2", Body: b})
	w.eid[name] = eid
	w.last = eid
	return eid
}

// roles is a task_roles object; issuers nil means any issuer. A subject name "I"/"J" is that identity (ids),
// anything else a key.
func (w *taskIDWorld) roles(ids map[string]string, ben string, unit string, issuers ...string) *canon.Object {
	subj := func(n string) canon.Value {
		if id, ok := ids[n]; ok {
			return obj("identity", id)
		}
		return obj("key", w.signer(n))
	}
	r := []any{"beneficiary", subj(ben), "counting_unit", unit}
	if len(issuers) == 0 {
		return obj(append(r, "any_issuer", true)...)
	}
	var l canon.Array
	for _, n := range issuers {
		l = append(l, subj(n))
	}
	slices.SortFunc(l, func(a, b canon.Value) int { return canon.CompareKeys(string(canon.Encode(a)), string(canon.Encode(b))) })
	return obj(append(r, "eligible_issuers", l)...)
}

// contract2 is a task-contract-v1 contract in the rc/2 placement (no role fields).
func contract2(kv ...any) *canon.Object {
	return obj(append([]any{"profile", TaskContractV1Profile, "question", "q?"}, kv...)...)
}

// act signs an rc/2 task statement of kind by worker: for identity i under grant (i != ""), else marker-only.
func (w *taskIDWorld) act(name, worker, kind string, body *canon.Object, i, grant string) string {
	if i == "" {
		return w.signRC2(name, worker, kind, body, rc2MarkerOnly, [2]string{})
	}
	return w.signRC2(name, worker, kind, body, rc2Actor, [2]string{i, grant})
}

func (w *taskIDWorld) sub2(name, worker, ed, result, i, grant string) string {
	return w.act(name, worker, "submit", obj("task", w.G, "edition", w.ed(ed), "result", dig(result)), i, grant)
}

// view resolves G over every line through the dual reader, with the real evaluator or none, in sampled orders;
// every order must render the same.
func (w *taskIDWorld) view(withEvaluator bool) *Task {
	w.t.Helper()
	opts := []Option{WithContractReader(ContractProfiles{})}
	if withEvaluator {
		actors, err := identity.NewActors(w.lines)
		if err != nil {
			w.t.Fatal(err)
		}
		opts = append(opts, WithActorEligibility(actors))
	}
	var first *Task
	out := ""
	for _, o := range append([][]int{nil}, sampleOrders(len(w.lines), 0x7a5c, 3)...) {
		in := w.lines
		if o != nil {
			in = make([][]byte, len(o))
			for i, j := range o {
				in[i] = w.lines[j]
			}
		}
		s := dualStore()
		if n := deliverAll(s, in); n != 0 {
			w.t.Fatalf("%d lines refused", n)
		}
		tk, ok := New(s, opts...).Task(w.G)
		if !ok {
			w.t.Fatalf("task %s did not resolve", keylog.Short(w.G))
		}
		if first == nil {
			first, out = tk, tk.Render()
		} else if got := tk.Render(); got != out {
			w.t.Fatalf("delivery order changed the task view: %s", firstDiff(out, got))
		}
	}
	return first
}

func (w *taskIDWorld) wantSub2(tk *Task, name, state, reason string) {
	w.t.Helper()
	s := subOf(w.t, tk, w.ids[name])
	if s.V1 == nil || s.V1.State != state || !strings.Contains(strings.Join(s.V1.Reasons, "; "), reason) {
		w.t.Fatalf("submission %s: %+v, want %s naming %q\n%s", name, s.V1, state, reason, tk.Render())
	}
}

// taskIdentities builds identity I (root IR; workers K1, K2 with submit+intent+progress+withdraw+decide, D with
// intent only) and identity J (root JR; worker K3 with submit and decide) over task G.
func taskIdentities(t *testing.T) (*taskIDWorld, map[string]string) {
	w := newTaskIDWorld(t, "K1", "K2", "K3", "D", "C")
	ids := map[string]string{"I": w.incept("I", "IR"), "J": w.incept("J", "JR")}
	all := []string{"decide", "intent", "progress", "submit", "withdraw"}
	ids["gK1"] = w.taskGrant("gK1", "IR", ids["I"], "K1", all...)
	ids["gK2"] = w.taskGrant("gK2", "IR", ids["I"], "K2", all...)
	ids["gD"] = w.taskGrant("gD", "IR", ids["I"], "D", "intent")
	ids["gK3"] = w.taskGrant("gK3", "JR", ids["J"], "K3", "decide", "submit")
	return w, ids
}

// TestRC2IdentityCounting: C-id-34 over signed rc/2 evidence. Under counting_unit identity (from the edition's
// task_roles), eligible submissions dedupe by I (two delegates of I are one vote); a bare submission is no identity
// vote; a denied actor (D's grant carries no `submit`) and an unresolved one (an actor naming I under a grant no
// one holds) are named and not counted. Without the evaluator the answer is today's: unknown, naming the missing
// profile, and no identity line counts.
func TestRC2IdentityCounting(t *testing.T) {
	conformance.Covers(t, "C-id-34")
	w, ids := taskIdentities(t)
	e1 := w.edition2("E1", w.roles(ids, "R", CountIdentity), contract2("quorum", quorum(2, IndependenceNotRequired)))
	w.sub2("SK1", "K1", e1, "X", ids["I"], ids["gK1"])
	w.sub2("SK2", "K2", e1, "X", ids["I"], ids["gK2"])
	w.sub2("SC", "C", e1, "X", "", "")
	w.sub2("SD", "D", e1, "X", ids["I"], ids["gD"])
	w.sub2("SE", "C", e1, "X", ids["I"], strings.Repeat("ee", 32)) // C claims I under a grant no one holds

	off := w.view(false)
	if rd := wantToken(t, off, w.world, "E1", ReadyUnknown, 3); !slices.ContainsFunc(rd.Why, func(s string) bool { return strings.Contains(s, "no identity profile is registered") }) {
		t.Fatalf("without the evaluator: %v", rd.Why)
	}
	for _, n := range []string{"SK1", "SK2", "SD", "SE"} {
		if s := subOf(t, off, w.ids[n]); s.Counts || !strings.Contains(s.Why, "identity profile not active") {
			t.Fatalf("%s counted without the evaluator: %+v", n, s)
		}
	}
	has(t, off.Render(), "roles from the edition's body.x_identity_v1.task_roles (rc/2)")

	on := w.view(true)
	rd := wantToken(t, on, w.world, "E1", NotReady, 0)
	if rd.N != 1 || rd.Unit != CountedAsIdentities {
		t.Fatalf("one identity: %d %q\n%s", rd.N, rd.Unit, on.Render())
	}
	w.wantSub2(on, "SK1", SubCounted, "")
	w.wantSub2(on, "SK2", SubCounted, "")
	w.wantSub2(on, "SC", SubNotCounted, "a bare-key submission is not an identity vote")
	w.wantSub2(on, "SD", SubNotCounted, "not eligible for identity "+keylog.Short(ids["I"]))
	w.wantSub2(on, "SE", SubNotCounted, "binds it to no identity")

	// a second identity reaches the quorum
	w.sub2("SK3", "K3", e1, "X", ids["J"], ids["gK3"])
	rd = wantToken(t, w.view(true), w.world, "E1", Ready, 0)
	if rd.N != 2 {
		t.Fatalf("two identities: %d", rd.N)
	}
	// one identity's keys disagree: no cross-key order picks a current submission, so I counts in none
	e2 := w.edition2("E2", w.roles(ids, "R", CountIdentity), contract2("quorum", quorum(1, IndependenceNotRequired)))
	w.sub2("FK1", "K1", e2, "X", ids["I"], ids["gK1"])
	w.sub2("FK2", "K2", e2, "Y", ids["I"], ids["gK2"])
	tk := w.view(true)
	w.wantSub2(tk, "FK1", SubNotCounted, "keys disagree")
	w.wantSub2(tk, "FK2", SubNotCounted, "keys disagree")
	wantToken(t, tk, w.world, "E2", NotReady, 0)
}

// TestRC2KeyCountingNoBypass: C-id-35 over signed rc/2 evidence. Under counting_unit key an identity submission
// counts for its key only after the actor's authority passed: D (grant without `submit`) and an unresolved actor
// count for nobody, though a raw submission by the same keys would count. A raw and an identity submission by one
// key count once. Typed eligible issuers admit by subject: {identity: I} admits K1-for-I, not K1 raw.
func TestRC2KeyCountingNoBypass(t *testing.T) {
	conformance.Covers(t, "C-id-35")
	w, ids := taskIdentities(t)
	ek := w.edition2("EK", w.roles(ids, "R", CountKey), contract2("quorum", quorum(4, IndependenceNotRequired)))
	w.sub2("KK1", "K1", ek, "X", ids["I"], ids["gK1"])
	w.sub2("KK1raw", "K1", ek, "X", "", "") // the same key, raw: one unit
	w.sub2("KK2", "K2", ek, "X", ids["I"], ids["gK2"])
	w.sub2("KD", "D", ek, "X", ids["I"], ids["gD"])
	w.sub2("KE", "C", ek, "X", ids["I"], strings.Repeat("ee", 32))
	w.sub2("KK3", "K3", ek, "X", "", "")

	off := w.view(false)
	if rd := wantToken(t, off, w.world, "EK", NotReady, 0); rd.N != 2 { // K1 raw, K3 raw
		t.Fatalf("without the evaluator: %d\n%s", rd.N, off.Render())
	}
	on := w.view(true)
	rd := wantToken(t, on, w.world, "EK", NotReady, 0)
	if rd.N != 3 || rd.Unit != CountedAs { // K1 (once), K2, K3; never D or C-for-I
		t.Fatalf("key counting: %d %q\n%s", rd.N, rd.Unit, on.Render())
	}
	w.wantSub2(on, "KD", SubNotCounted, "not eligible for identity")
	w.wantSub2(on, "KE", SubNotCounted, "never counted as its key")
	w.wantSub2(on, "KK1", SubNotCounted, "superseded by "+keylog.Short(w.ids["KK1raw"]))
	w.wantSub2(on, "KK1raw", SubCounted, "")

	// typed eligible issuers: {identity: I} admits a delegate of I acting for I, not the same key raw
	ei := w.edition2("EI", w.roles(ids, "R", CountKey, "I"), contract2("quorum", quorum(2, IndependenceNotRequired)))
	w.sub2("IK1", "K1", ei, "X", ids["I"], ids["gK1"])
	w.sub2("IK2raw", "K2", ei, "X", "", "")
	w.sub2("IK3", "K3", ei, "X", ids["J"], ids["gK3"])
	tk := w.view(true)
	w.wantSub2(tk, "IK1", SubCounted, "")
	w.wantSub2(tk, "IK2raw", SubNotCounted, "not an eligible issuer")
	w.wantSub2(tk, "IK3", SubNotCounted, "not an eligible issuer")
	if rd := wantToken(t, tk, w.world, "EI", NotReady, 0); rd.N != 1 {
		t.Fatalf("typed issuers: %d", rd.N)
	}
}

// TestRC2DecideAuthority: C-id-42. A decide settles only for the pinned edition's typed beneficiary: K1 for I
// (beneficiary I, a `decide` grant for G) settles; D for I (no `decide` permission) is not eligible; K3 for J holds a
// `decide` grant but J is not the beneficiary; R's raw decide is R's, not I's. Without the evaluator no identity
// decide settles.
func TestRC2DecideAuthority(t *testing.T) {
	conformance.Covers(t, "C-id-42")
	w, ids := taskIdentities(t)
	e := w.edition2("E", w.roles(ids, "I", CountKey), contract2())
	s := w.sub2("S", "K3", e, "X", "", "")
	dec := func(name, by, verdict, i, grant string) string {
		return w.act(name, by, "decide", obj("task", w.G, "edition", w.ed(e), "submissions", []string{s}, "verdict", verdict), i, grant)
	}
	dec("DK1", "K1", "accept", ids["I"], ids["gK1"])
	dec("DD", "D", "reject", ids["I"], ids["gD"])
	dec("DK3", "K3", "reject", ids["J"], ids["gK3"])
	dec("DR", "R", "reject", "", "")
	decision := func(tk *Task, n string) *Decision {
		for _, d := range tk.Decisions {
			if d.Statement == w.ids[n] {
				return d
			}
		}
		t.Fatalf("no decision %s", n)
		return nil
	}
	on := w.view(true)
	for n, why := range map[string]string{"DD": "not eligible for identity", "DK3": "not the edition's beneficiary identity " + keylog.Short(ids["I"]),
		"DR": "not the edition's beneficiary identity"} {
		if d := decision(on, n); d.Counts || !strings.Contains(d.Why, why) {
			t.Fatalf("%s: %+v, want not counted naming %q", n, d, why)
		}
	}
	if d := decision(on, "DK1"); !d.Counts || d.Subject != IdentitySubject(ids["I"]) {
		t.Fatalf("beneficiary decide: %+v", d)
	}
	if v := subOf(t, on, s).Verdict; v != "accept" {
		t.Fatalf("verdict %q\n%s", v, on.Render())
	}
	off := w.view(false)
	if d := decision(off, "DK1"); d.Counts || !strings.Contains(d.Why, "identity profile not active") {
		t.Fatalf("identity decide without the evaluator: %+v", d)
	}
	if v := subOf(t, off, s).Verdict; v != "" {
		t.Fatalf("verdict without the evaluator %q", v)
	}
}

// TestRC2AttemptContinuity: C-id-43. K2 for I continues K1-for-I's exact intent (progress and withdraw pin it);
// a pin to a bare K1 intent does not continue it (another subject); D's progress for I (no `progress` permission)
// continues nothing; a progress after the withdrawal is listed and reopens nothing (the attempt stays withdrawn).
func TestRC2AttemptContinuity(t *testing.T) {
	conformance.Covers(t, "C-id-43")
	w, ids := taskIdentities(t)
	e := w.edition2("E", w.roles(ids, "R", CountKey), contract2())
	ref := func(kv ...any) *canon.Object { return obj(append([]any{"task", w.G, "edition", w.ed(e)}, kv...)...) }
	pin := func(intent string, kv ...any) *canon.Object {
		return withMember(ref(kv...), wire.IdentityCrit, obj("intent", intent))
	}
	in := w.act("IN", "K1", "intent", ref(), ids["I"], ids["gK1"])
	bare := w.act("INbare", "K1", "intent", ref(), "", "")
	w.act("P2", "K2", "progress", pin(in, "note", "n"), ids["I"], ids["gK2"])
	w.act("PD", "D", "progress", pin(in), ids["I"], ids["gD"])
	w.act("Pbare", "K2", "progress", pin(bare), ids["I"], ids["gK2"])
	w.act("W2", "K2", "withdraw", pin(in), ids["I"], ids["gK2"])
	w.act("P1late", "K1", "progress", pin(in), ids["I"], ids["gK1"]) // after the withdrawal: activity, never a reopening
	attempt := func(tk *Task, intent string) *Attempt {
		for _, a := range tk.Attempts {
			if a.Intent == intent {
				return a
			}
		}
		t.Fatalf("no attempt %s\n%s", keylog.Short(intent), tk.Render())
		return nil
	}
	on := w.view(true)
	a := attempt(on, in)
	if a.Subject != IdentitySubject(ids["I"]) || len(a.Progress) != 2 || !slices.Contains(a.Progress, w.ids["P2"]) || a.Withdrawn != w.ids["W2"] {
		t.Fatalf("identity attempt: %+v\n%s", a, on.Render())
	}
	if b := attempt(on, bare); b.Subject != KeySubject(w.signer("K1")) || len(b.Progress) != 0 || b.Withdrawn != "" {
		t.Fatalf("bare attempt continued across subjects: %+v", b)
	}
	has(t, on.Render(), "for identity "+keylog.Short(ids["I"])+" on")
	off := w.view(false)
	if slices.ContainsFunc(off.Attempts, func(a *Attempt) bool { return a.Intent == in }) {
		t.Fatalf("an identity intent opened an attempt without the evaluator")
	}
	if b := attempt(off, bare); len(b.Progress) != 0 {
		t.Fatalf("bare attempt: %+v", b)
	}
}

// The rc/2 placement of the roles: a provisional contract has none (unread), and a reader whose contract reader
// does not read rc/2 reads no rc/2 contract. The rc/1 reading of the same contract fields is unchanged.
func TestRC2ContractPlacement(t *testing.T) {
	w, ids := taskIdentities(t)
	w.edition2("EP", w.roles(ids, "R", CountKey), obj("profile", ProvisionalProfile))
	tk := w.view(true)
	if b := tk.Bindings[w.ed("EP")]; b.Terms != nil || !strings.Contains(b.TermsWhy, "no rc/2 placement") {
		t.Fatalf("provisional rc/2 contract: %+v", b)
	}
	wantToken(t, tk, w.world, "EP", ReadyUnchecked, 3)
	if _, why, ok := (TaskContractV1{}).ReadRC2(contract2("beneficiary", w.signer("R")), &TaskRoles{Unit: CountKey, AnyIssuer: true}); ok ||
		!strings.Contains(why, "beneficiary is forbidden under rc/2") {
		t.Fatalf("role field in an rc/2 contract: %q", why)
	}
	if _, why, ok := (TaskContractV1{}).ReadRC2(contract2(), nil); ok || !strings.Contains(why, "task_roles") {
		t.Fatalf("rc/2 contract without roles: %q", why)
	}
}

// An rc/1 task-contract-v1 edition under counting_unit identity stays unknown with an evaluator too: its roles are
// keys in the contract, so no identity can be checked; the reason names the placement, not a missing profile.
func TestRC1IdentityUnitWithEvaluator(t *testing.T) {
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "counting_unit", "identity", "quorum", quorum(1, IndependenceNotRequired)))
	w.submit("S", "A", g, e, "X")
	off := readinessOf(t, taskV1View(t, w, g), w.ed(e))
	on := readinessOf(t, taskV1View(t, w, g, WithActorEligibility(&actorFake{})), w.ed(e))
	if off.Token != ReadyUnknown || !strings.Contains(strings.Join(off.Why, ";"), "no identity profile is registered") {
		t.Fatalf("without the evaluator: %s %v", off.Token, off.Why)
	}
	if on.Token != ReadyUnknown || !strings.Contains(strings.Join(on.Why, ";"), "the rc/1 placement") {
		t.Fatalf("with the evaluator: %s %v", on.Token, on.Why)
	}
}
