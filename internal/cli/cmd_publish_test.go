package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/run"
	"github.com/research-common/research-commons/internal/wire"
)

// forbidDialect is a test rule dialect: "FORBID <key>" fails when a scanned unit holds the JSON key, and is
// unchecked when a unit could not be scanned. No dialect ships; the publisher's pre-pin seam takes this one.
type forbidDialect struct{}

func (forbidDialect) Name() string { return "rc-test/1" }
func (forbidDialect) Compile(expr string) (resolve.Rule, error) {
	f := strings.Fields(expr)
	if len(f) != 2 || f[0] != "FORBID" {
		return nil, fmt.Errorf("keyword %q", expr)
	}
	return forbid{f[1]}, nil
}

type forbid struct{ key string }

func (r forbid) Eval(d *resolve.Domain) (resolve.Outcome, string, []string) {
	units, ok := d.Content("")
	if !ok {
		return resolve.RuleUnchecked, "content not held", nil
	}
	for _, u := range units {
		if u.Unscanned != "" {
			return resolve.RuleUnchecked, u.Name + " unscanned (" + u.Unscanned + ")", nil
		}
		if bytes.Contains(u.Data, []byte(`"`+r.key+`"`)) {
			return resolve.RuleFail, "forbidden key " + r.key + " in " + u.Name, nil
		}
	}
	return resolve.RuleOK, "", nil
}

func withDialect(t *testing.T) {
	ruleDialects = []resolve.Dialect{forbidDialect{}}
	t.Cleanup(func() { ruleDialects = nil })
}

func withClock(t *testing.T, at time.Time) {
	Now = func() time.Time { return at }
	t.Cleanup(func() { Now = time.Now })
}

// pubWorld is a store and a key file for publishing.
type pubWorld struct {
	*world
	dir, key, signer string
}

func newPubWorld(t *testing.T) *pubWorld {
	w := newWorld(t)
	dir := t.TempDir()
	p, s := newKeyFile(t, dir, wire.AlgEd25519)
	return &pubWorld{world: w, dir: dir, key: p, signer: s}
}

func (p *pubWorld) file(name, data string) string {
	f := filepath.Join(p.dir, name)
	os.WriteFile(f, []byte(data), 0o644)
	return f
}

func (p *pubWorld) publish(args ...string) result {
	return runIn(p.root, nil, append([]string{"publish", "--key", p.key, "--json"}, args...)...)
}

// edition publishes a collection whose one edition carries rules, signed by K9 through the fixture world.
func (p *pubWorld) collection(rules ...string) (string, string) {
	g := p.sign("G", "K9", "genesis", obj("type", "collection", "name", "c", "controllers", []string{p.signer9()}, "rule", obj("any_one", true)))
	rs := canon.Array{}
	for _, r := range rules {
		rs = append(rs, obj("dialect", "rc-test/1", "expr", r))
	}
	body := obj("resource", g, "predecessors", []string{g}, "contents", obj("rules", rs))
	p.sign("E", "K9", "edition", body)
	return g, resolve.EditionID(body)
}

func (p *pubWorld) signer9() string { return p.key9().Signer() }
func (p *pubWorld) key9() wire.Key  { return p.world.key("K9") }

func outObj(t *testing.T, r result) *canon.Object { t.Helper(); return jsonOf(t, r) }

func statementsOf(o *canon.Object) []*canon.Object {
	var out []*canon.Object
	for _, x := range o.Members["statements"].(canon.Array) {
		out = append(out, x.(*canon.Object))
	}
	return out
}

func idsOf(o *canon.Object) []string {
	var out []string
	for _, s := range statementsOf(o) {
		out = append(out, string(s.Members["statement"].(canon.String)))
	}
	return out
}

// TestPublishAuthored: authored + holds with the blob as one unit; the log continues (seq, prev); the statement
// resolves through show and verify; describes and retracts from options; a draft of another kind.
func TestPublishAuthored(t *testing.T) {
	p := newPubWorld(t)
	c := p.file("data.json", `{"rows":3}`)
	r := p.publish("--kind", "authored", "--content", c, "--licence", "CC0-1.0", "--description", "three rows")
	if r.code != 0 {
		t.Fatalf("publish: %d %s", r.code, r.stdout)
	}
	o := outObj(t, r)
	if o.Members["committed"] != canon.Bool(true) {
		t.Fatal("not committed")
	}
	sts := statementsOf(o)
	if len(sts) != 2 || sts[0].Members["kind"] != canon.String("authored") || sts[1].Members["kind"] != canon.String("holds") ||
		sts[0].Members["seq"] != canon.Int(0) || sts[1].Members["seq"] != canon.Int(1) || sts[1].Members["prev"] != sts[0].Members["statement"] {
		t.Fatalf("unit: %s", r.stdout)
	}
	d := run.Digest([]byte(`{"rows":3}`))
	show := p.run("show", d, "--json")
	if !strings.Contains(show.stdout, `"authorship":"sole author"`) || !strings.Contains(show.stdout, p.signer) || !strings.Contains(show.stdout, `"bytes":"held here"`) {
		t.Fatalf("show after publish: %s", show.stdout)
	}
	if v := p.run("verify", d, "--json"); v.code != 0 {
		t.Fatalf("verify: %d %s", v.code, v.stdout)
	}
	// the next publish continues the log
	a := idsOf(o)[0]
	r = p.publish("--kind", "describes", "--about", d, "--note", "checked")
	if r.code != 0 || statementsOf(outObj(t, r))[0].Members["seq"] != canon.Int(2) {
		t.Fatalf("describes: %d %s", r.code, r.stdout)
	}
	r = p.publish("--kind", "retracts", "--of", a, "--reason", "superseded")
	if r.code != 0 {
		t.Fatalf("retracts: %d %s", r.code, r.stdout)
	}
	if !strings.Contains(p.run("show", d, "--json").stdout, `"retracted"`) {
		t.Fatal("retracted label missing")
	}
	// a draft of a kind without bytes
	draft := p.file("d.json", `{"kind":"refutes","body":{"of":"`+a+`","evidence":"`+d+`"}}`)
	if r := p.publish("--draft", draft); r.code != 0 {
		t.Fatalf("draft: %d %s", r.code, r.stdout)
	}
	// a withheld artifact: authored only
	r = p.publish("--kind", "authored", "--content", p.file("w", "withheld"), "--no-holds")
	if r.code != 0 || len(statementsOf(outObj(t, r))) != 1 {
		t.Fatalf("no-holds: %d %s", r.code, r.stdout)
	}
}

// TestPublishInputsExitTwo: every bad input exits 2 before any work and leaves the store unchanged.
func TestPublishInputsExitTwo(t *testing.T) {
	p := newPubWorld(t)
	c := p.file("c", "bytes")
	before := snapshot(t, p.root)
	for _, args := range [][]string{
		{},
		{"--kind", "authored"},
		{"--kind", "authored", "--content", filepath.Join(p.dir, "missing")},
		{"--kind", "observed", "--content", c},
		{"--kind", "holds", "--content", c, "--licence", "x"},
		{"--kind", "describes"},
		{"--kind", "retracts", "--of", "zz"},
		{"--kind", "authored", "--content", c, "--availability", "{"},
		{"--kind", "authored", "--content", c, "--ts", "yesterday"},
		{"--kind", "authored", "--content", c, "--intended-for", "x/y"},
		{"--draft", p.file("e1", `{"kind":"authored","body":{},"seq":4}`)},
		{"--draft", p.file("e2", `{"kind":"x_custom","body":{}}`)},
		{"--draft", p.file("e3", `{"kind":"authored"`)},
		{"--draft", p.file("e4", `{"kind":"genesis","body":{"type":"task"}}`)},
		{"--draft", p.file("e5", `{"kind":"holds","body":{}}`), "--note", "x"},
		{"--kind", "authored", "--draft", p.file("e6", `{"kind":"holds","body":{}}`)},
	} {
		r := p.publish(args...)
		if r.code != 2 {
			t.Fatalf("%v: exit %d %s", args, r.code, r.stdout)
		}
		if outObj(t, r).Members["committed"] != canon.Bool(false) {
			t.Fatalf("%v: committed", args)
		}
		if snapshot(t, p.root) != before {
			t.Fatalf("%v: store changed", args)
		}
	}
	// a draft whose body fails §5 is refused at signing (exit 2, nothing appended)
	r := p.publish("--draft", p.file("e7", `{"kind":"retracts","body":{"of":"not-an-id"}}`))
	if r.code != 2 || snapshot(t, p.root) != before {
		t.Fatalf("schema: %d %s", r.code, r.stdout)
	}
}

// TestPublishDryRun: prints the statements and side effects, commits nothing, needs a key.
func TestPublishDryRun(t *testing.T) {
	p := newPubWorld(t)
	before := snapshot(t, p.root)
	r := p.publish("--kind", "authored", "--content", p.file("c", "dry"), "--dry-run")
	o := outObj(t, r)
	if r.code != 0 || o.Members["committed"] != canon.Bool(false) || o.Members["dry_run"] != canon.Bool(true) ||
		!strings.Contains(r.stdout, "install blob "+run.Digest([]byte("dry"))) || len(statementsOf(o)) != 2 {
		t.Fatalf("dry run: %d %s", r.code, r.stdout)
	}
	if _, ok := statementsOf(o)[0].Members["body"]; !ok {
		t.Fatal("dry run does not show the body")
	}
	if snapshot(t, p.root) != before {
		t.Fatal("dry run changed the store")
	}
}

// TestPublishFutureTS: C-core-105 through the writer. One hour ahead is refused (class reader policy, scope
// this statement), nothing appended; 299 s ahead is accepted.
func TestPublishFutureTS(t *testing.T) {
	conformance.Covers(t, "C-core-105")
	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	withClock(t, at)
	p := newPubWorld(t)
	c := p.file("c", "ts")
	before := snapshot(t, p.root)
	r := p.publish("--kind", "authored", "--content", c, "--ts", at.Add(time.Hour).Format(time.RFC3339))
	o := outObj(t, r)
	if r.code != 2 || o.Members["class"] != canon.String("reader policy") || o.Members["scope"] != canon.String("this statement") ||
		!strings.Contains(r.stdout, "300 s") {
		t.Fatalf("one hour ahead: %d %s", r.code, r.stdout)
	}
	if snapshot(t, p.root) != before {
		t.Fatal("refused ts appended something")
	}
	if r := p.publish("--kind", "authored", "--content", c, "--ts", at.Add(299*time.Second).Format(time.RFC3339)); r.code != 0 {
		t.Fatalf("299 s ahead: %d %s", r.code, r.stdout)
	}
	// wire.Write is the second line of defence (a ts that passed Prepare and then the clock moved back)
	if _, err := wire.Write(wire.Draft{Kind: "retracts", TS: at.Add(time.Hour).Format(time.RFC3339), Body: obj("of", strings.Repeat("ab", 32))}, testKey("x"), at); err == nil {
		t.Fatal("wire.Write accepted a ts an hour ahead")
	}
}

// TestPublishPrePin: C-core-95a, C-core-96 and the publish half of C-core-95.
func TestPublishPrePin(t *testing.T) {
	conformance.Covers(t, "C-core-95a", "C-core-96")
	conformance.Partial(t, "C-core-95", "publish records intended_for with outcome unchecked for a unit the reader could not scan (the size limit; the forbidden key unreadable) and a reader re-applying the rule does not admit it; no archive scanner exists in the CLI, so the unscanned unit is a whole blob over the scan limit, not an archive member in an unsupported compression")
	withDialect(t)
	p := newPubWorld(t)
	g, e := p.collection("FORBID secret")
	secret := p.file("s.json", `{"secret":"***"}`)
	fine := p.file("f.json", `{"fine":1}`)

	// C-core-96: the rule fails the bytes: refused (reader policy, this statement), nothing pinned or appended
	before := snapshot(t, p.root)
	r := p.publish("--kind", "authored", "--content", secret, "--intended-for", g+"/"+e)
	o := outObj(t, r)
	if r.code != 1 || o.Members["class"] != canon.String("reader policy") || o.Members["scope"] != canon.String("this statement") ||
		o.Members["committed"] != canon.Bool(false) || !strings.Contains(r.stdout, "forbidden key secret") || !strings.Contains(r.stdout, e[:12]) {
		t.Fatalf("C-core-96: %d %s", r.code, r.stdout)
	}
	if snapshot(t, p.root) != before {
		t.Fatal("C-core-96: the refused publish pinned or appended something")
	}
	if strings.Contains(r.stdout, "--force") {
		t.Fatal("suggests --force")
	}

	// C-core-95a: the edition is not held here: refused, names the edition to fetch, nothing pinned
	q := newPubWorld(t)
	r = q.publish("--kind", "authored", "--content", fine, "--intended-for", g+"/"+e)
	if r.code != 3 || !strings.Contains(r.stdout, "fetch resource "+g) || !strings.Contains(r.stdout, e) {
		t.Fatalf("C-core-95a: %d %s", r.code, r.stdout)
	}
	if entries, _ := os.ReadDir(filepath.Join(q.root, "statements")); len(entries) != 0 {
		t.Fatal("C-core-95a: something appended")
	}
	// control: the same publish where the edition is held records the outcome of the check that ran
	r = p.publish("--kind", "authored", "--content", fine, "--intended-for", g+"/"+e)
	if r.code != 0 || !strings.Contains(r.stdout, `"intended_for":{"edition":"`+e) || !strings.Contains(r.stdout, `"state":"ok"`) {
		t.Fatalf("control: %d %s", r.code, r.stdout)
	}
	id := idsOf(outObj(t, r))[0]
	if !strings.Contains(p.run("show", id, "--json").stdout, `"outcome":"ok"`) {
		t.Fatal("the statement does not record outcome ok")
	}

	// C-core-95 (publish half): a unit the reader cannot scan: unchecked recorded, never ok; re-applied, not admitted
	big := p.file("big.json", `{"secret":1,"pad":"`+strings.Repeat("x", maxScan)+`"}`)
	r = p.publish("--kind", "authored", "--content", big, "--intended-for", g+"/"+e)
	if r.code != 0 || !strings.Contains(r.stdout, `"state":"unchecked"`) || !strings.Contains(r.stdout, "unscanned (size limit") {
		t.Fatalf("C-core-95: %d %s", r.code, r.stdout[:min(len(r.stdout), 2000)])
	}
	id = idsOf(outObj(t, r))[0]
	if !strings.Contains(p.run("show", id, "--json").stdout, `"outcome":"unchecked"`) {
		t.Fatal("C-core-95: unchecked not recorded")
	}
	v, _ := loadView(p.s, nil, resolve.WithDialect(forbidDialect{}), resolve.WithContent(prepinContent{st: p.s}))
	if rec, ok := v.r.CheckRecorded(id); !ok || rec.Named == resolve.RuleOK || rec.Endorsed {
		t.Fatalf("C-core-95: re-applied: %+v", rec)
	}

	// no dialect configured (production): the rule cannot be evaluated: unchecked, never ok
	ruleDialects = nil
	r = p.publish("--kind", "authored", "--content", p.file("f2", `{"fine":2}`), "--intended-for", g+"/"+e)
	if r.code != 0 || !strings.Contains(r.stdout, `"state":"unchecked"`) {
		t.Fatalf("no dialect: %d %s", r.code, r.stdout)
	}
}

// TestPublishFork: a FORK in the signer's log is refused until --prev names a line; a --prev that is not a
// tip makes a fork and says so; nothing is ever rebased.
func TestPublishFork(t *testing.T) {
	p := newPubWorld(t)
	r := p.publish("--kind", "describes", "--about", dig("a"), "--note", "one")
	first := idsOf(outObj(t, r))[0]
	r = p.publish("--kind", "describes", "--about", dig("a"), "--note", "two")
	second := idsOf(outObj(t, r))[0]
	// --prev at a non-tip: a fork, flagged
	r = p.publish("--kind", "describes", "--about", dig("a"), "--note", "three", "--prev", first)
	o := outObj(t, r)
	if r.code != 0 || o.Members["line"] != canon.String("FORK") || statementsOf(o)[0].Members["seq"] != canon.Int(1) {
		t.Fatalf("fork by --prev: %d %s", r.code, r.stdout)
	}
	third := idsOf(o)[0]
	// now the log has two tips: refused, naming both, nothing appended
	before := snapshot(t, p.root)
	r = p.publish("--kind", "describes", "--about", dig("a"), "--note", "four")
	if r.code != 3 || !strings.Contains(r.stdout, second[:12]) || !strings.Contains(r.stdout, third[:12]) || !strings.Contains(r.stdout, "--prev") {
		t.Fatalf("fork refused: %d %s", r.code, r.stdout)
	}
	if snapshot(t, p.root) != before {
		t.Fatal("refused fork appended something")
	}
	if r := p.publish("--kind", "describes", "--about", dig("a"), "--note", "four", "--prev", second); r.code != 0 {
		t.Fatalf("explicit prev: %d %s", r.code, r.stdout)
	}
	if r := p.publish("--kind", "describes", "--about", dig("a"), "--prev", strings.Repeat("cd", 32)); r.code != 3 {
		t.Fatalf("prev not held: %d", r.code)
	}
}

// TestPublishCommittedPendingInstall: C-core-138. A failure after the commit point: the error names what
// failed, what is known, that it is committed, and the narrowest next step; never --force; once the cause is
// fixed, opening the store replays the record and the committed statement resolves.
func TestPublishCommittedPendingInstall(t *testing.T) {
	conformance.Covers(t, "C-core-138")
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions; the fault cannot be injected")
	}
	p := newPubWorld(t)
	dir := filepath.Join(p.root, "statements", strings.ReplaceAll(p.signer, ":", "-"))
	os.MkdirAll(dir, 0o755)
	os.Chmod(dir, 0o500) // the install step (3) fails after the record (2) is written
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	c := p.file("c", "crash")
	r := p.publish("--kind", "authored", "--content", c)
	o := outObj(t, r)
	if r.code != 3 || o.Members["committed"] != canon.Bool(true) || o.Members["type"] != canon.String(ProblemTypeBase+"committed-pending-install") {
		t.Fatalf("pending install: %d %s", r.code, r.stdout)
	}
	for _, want := range []string{"commit point", "journal record", "replays", "commons status", "do not publish again"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("message lacks %q: %s", want, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "force") {
		t.Fatal("suggests --force")
	}
	pend, _ := os.ReadDir(filepath.Join(p.root, "journal", "pending"))
	if len(pend) != 1 {
		t.Fatalf("pending records: %d", len(pend))
	}
	os.Chmod(dir, 0o755)
	if s := p.run("status", "--json"); s.code != 0 || !strings.Contains(s.stdout, "replayed") {
		t.Fatalf("status after fix: %d %s", s.code, s.stdout)
	}
	if v := p.run("show", run.Digest([]byte("crash")), "--json"); !strings.Contains(v.stdout, `"authorship":"sole author"`) {
		t.Fatalf("the committed statement does not resolve: %s", v.stdout)
	}
}

// TestPublishTask: C-exch-06. A task with no quorum predicate: publish says "settled by review, not by
// counting" and the task display repeats it; a quorum is reported as a count; an unreadable contract is
// readiness unchecked; a new edition continues the task.
func TestPublishTask(t *testing.T) {
	conformance.Covers(t, "C-exch-06")
	p := newPubWorld(t)
	ct := p.file("c.json", `{"profile":"`+resolve.ProvisionalProfile+`","beneficiary":"`+p.signer+`","any_issuer":true}`)
	r := runIn(p.root, nil, "publish", "task", "--key", p.key, "--name", "label the readings", "--contract", ct, "--json")
	if r.code != 0 || !strings.Contains(r.stdout, `"state":"settled by review, not by counting"`) {
		t.Fatalf("publish task: %d %s", r.code, r.stdout)
	}
	o := outObj(t, r)
	task := string(o.Members["task"].(canon.String))
	if len(statementsOf(o)) != 2 {
		t.Fatal("genesis + first edition are one unit")
	}
	// the display half: the resolver's task view over the same store repeats it
	tk, ok := resolve.New(mustLogs(t, p), resolve.WithContractReader(resolve.ProvisionalContract{})).Task(task)
	if !ok || !strings.Contains(tk.Render(), "settled by review, not by counting") {
		t.Fatalf("task display: %v", ok)
	}
	// a new edition with a quorum: a count
	cq := p.file("q.json", `{"profile":"`+resolve.ProvisionalProfile+`","beneficiary":"`+p.signer+`","any_issuer":true,"quorum":{"k":2,"independence":"not-required"}}`)
	r = runIn(p.root, nil, "publish", "task", "--key", p.key, "--task", task, "--contract", cq, "--json")
	if r.code != 0 || !strings.Contains(r.stdout, `"quorum":2`) || !strings.Contains(r.stdout, "distinct signing keys") {
		t.Fatalf("quorum: %d %s", r.code, r.stdout)
	}
	// a contract this reader cannot read: readiness unchecked, never a guess
	cu := p.file("u.json", `{"profile":"some-other-profile"}`)
	r = runIn(p.root, nil, "publish", "task", "--key", p.key, "--task", task, "--contract", cu, "--json")
	if r.code != 0 || !strings.Contains(r.stdout, "readiness unchecked") || !strings.Contains(r.stdout, `"state":"unchecked"`) {
		t.Fatalf("unread contract: %d %s", r.code, r.stdout)
	}
	// another key cannot extend the task: refused before anything is appended
	q := filepath.Join(p.dir, "other.key")
	runIn(p.dir, nil, "key", "new", "--out", q)
	before := snapshot(t, p.root)
	r = runIn(p.root, nil, "publish", "task", "--key", q, "--task", task, "--contract", ct, "--json")
	if r.code != 3 || snapshot(t, p.root) != before {
		t.Fatalf("non-controller: %d %s", r.code, r.stdout)
	}
}

func mustLogs(t *testing.T, p *pubWorld) *keylog.Store {
	v, err := loadView(p.s, nil)
	if err != nil {
		t.Fatal(err)
	}
	return v.logs
}

// TestPublishDisclosureFlags: C-exec-05 (CLI half). publish accepts a flag for every disclosure run --publish
// accepts, and each lands in the signed statement.
func TestPublishDisclosureFlags(t *testing.T) {
	conformance.Partial(t, "C-exec-05", "publish's disclosure flags equal run.Disclosure and each lands in the statement; run --publish is not a CLI command yet, so the second half (each flag passed to run --publish) is the planner's test in internal/run")
	var fields []string
	for _, d := range publishDisclosures {
		fields = append(fields, d.Field)
	}
	if !slices.Equal(fields, run.Disclosure) {
		t.Fatalf("publish disclosures %v != run.Disclosure %v", fields, run.Disclosure)
	}
	p := newPubWorld(t)
	vals := map[string]string{"attribution": "A. N. Other", "availability": `{"obtainable":true,"redistribution":"permitted"}`,
		"comparator": dig("cmp"), "description": "d", "extends": dig("ext"), "fulfills": `{"edition":"` + strings.Repeat("ef", 32) + `","resource":"` + strings.Repeat("ab", 32) + `"}`,
		"licence": "CC0-1.0", "licence_texts": `{"CC0-1.0":"` + dig("lt") + `"}`, "pre_registration": "exploratory", "replication": "bytes",
		"sampling": `{"n":10,"unit":"rows"}`, "shelf_life_days": "30", "supersedes": dig("old")}
	args := []string{"--kind", "authored", "--content", p.file("c", "disclosed"), "--dry-run"}
	for _, d := range publishDisclosures {
		if v, ok := vals[d.Field]; ok {
			args = append(args, "--"+flagOf(d.Field), v)
		}
	}
	r := p.publish(args...)
	if r.code != 0 {
		t.Fatalf("%d %s", r.code, r.stdout)
	}
	body := statementsOf(outObj(t, r))[0].Members["body"].(*canon.Object)
	for k := range vals {
		if _, ok := body.Members[k]; !ok {
			t.Errorf("disclosure %s missing from the statement", k)
		}
	}
}
