package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

// The identity reader through the commands: signed rc/2 statements (the published vectors, and lines signed here
// as the profile's builders sign them) pulled into a store, then read by show, verify and explain. The writer stays
// rc/1, so every rc/2 line arrives by pull or by a direct store commit, both through the production reader.

func licBody(x, l string) *canon.Object {
	return obj("content", canon.Value(content(x)), "type", "dataset", "licence", l)
}

func amendingBody(x, l string, targets ...string) *canon.Object {
	return withMember(licBody(x, l), wire.IdentityCrit, obj("amends", targets))
}

// vectorChain is the published signed vectors' ed25519 chain: positive lines by short name, file order.
func vectorChain(t *testing.T, chain string) (map[string]conformance.IdentityPositive, []conformance.IdentityNegative) {
	t.Helper()
	v, err := conformance.LoadSignedIdentityVectors()
	if err != nil {
		t.Fatal(err)
	}
	pos := map[string]conformance.IdentityPositive{}
	for _, p := range v.Positive {
		if p.Chain == chain {
			pos[strings.TrimPrefix(p.Name, chain+"-")] = p
		}
	}
	var neg []conformance.IdentityNegative
	for _, n := range v.Negative {
		if n.Chain == chain {
			neg = append(neg, n)
		}
	}
	return pos, neg
}

// commitLines commits exact lines into a fresh source store.
func commitLines(t *testing.T, lines ...string) *world {
	t.Helper()
	w := newWorld(t)
	for _, l := range lines {
		if _, err := w.s.Commit("publish", [][]byte{[]byte(l)}, nil); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

// showJSON is `show <id> --json`, exit 0.
func showJSON(t *testing.T, w *world, id string) *canon.Object {
	t.Helper()
	r := w.run("show", id, "--json")
	if r.code != ExitOK {
		t.Fatalf("show %s: %d\n%s%s", id[:12], r.code, r.stdout, r.stderr)
	}
	return jsonOf(t, r)
}

func member(o *canon.Object, path ...string) canon.Value {
	var v canon.Value = o
	for _, k := range path {
		x, ok := v.(*canon.Object)
		if !ok {
			return nil
		}
		v = x.Members[k]
	}
	return v
}

// TestIdentityReaderVectorsThroughPull: the published grant-covered rc/2 `authored` (both algorithms), pulled into a
// store with its inception, grant and the worker's first line, is read by the production reader: `show` prints its
// actor eligible for the identity it names, `counted`, and the evaluator context (version, evidence digest,
// receipt); `verify` of its content exits 0 with one sole author, the identity; the cut at last_good keeps it and
// denies the amending act, the null cut denies both, and the root's rc/1 revoke_key retires the identity: each
// answer bound to I and named.
func TestIdentityReaderVectorsThroughPull(t *testing.T) {
	conformance.Partial(t, "C-id-02", "end to end through pull, show and verify on the published vectors, both algorithms: actor eligible, counted, the content's sole author the identity; the basis is the evaluator's (identity package); no writer signs rc/2 yet")
	conformance.Partial(t, "C-id-11", "end to end through pull and show on the published vectors: the cut at last_good keeps the named act and denies its descendant, the null cut denies both (cut_excluded); siblings and merges are checked at the adapter")
	conformance.Partial(t, "C-id-17", "end to end through pull and show: the root's rc/1 revoke_key placed on I's lineage retires I (root_retired) for every act; the rival-lineage and unplaceable halves are the adapter's")
	for _, chain := range []string{"ed", "eip"} {
		t.Run(chain, func(t *testing.T) {
			pos, _ := vectorChain(t, chain)
			order := []string{"worker-genesis", "inception", "grant", "authored", "authored-amends", "cut-last-good", "cut-null", "revoke-key"}
			auth, amends := pos["authored"].ID, pos["authored-amends"].ID
			ident := pos["inception"].ID
			steps := []struct {
				upto         string
				auth, amends string
				code         string
			}{
				{"authored-amends", "eligible", "eligible", ""},
				{"cut-last-good", "eligible", "denied", "cut_excluded"},
				{"cut-null", "denied", "denied", "cut_excluded"},
				{"revoke-key", "denied", "denied", "root_retired"},
			}
			for _, s := range steps {
				var lines []string
				for _, n := range order[:indexOf(order, s.upto)+1] {
					lines = append(lines, pos[n].Line)
				}
				d := commitLines(t, lines...).pullInto()
				for _, x := range []struct{ id, want string }{{auth, s.auth}, {amends, s.amends}} {
					o := showJSON(t, d, x.id)
					if member(o, "actor", "identity") != canon.String(ident) || member(o, "actor", "state") != canon.String(x.want) {
						t.Fatalf("up to %s, %s: actor %s, want %s", s.upto, x.id[:12], canon.Encode(member(o, "actor")), x.want)
					}
					counted := "counted"
					if x.want != "eligible" {
						counted = "not counted"
						if !strings.Contains(string(canon.Encode(member(o, "actor", "reasons"))), s.code) {
							t.Fatalf("up to %s, %s: reasons lack %s: %s", s.upto, x.id[:12], s.code, canon.Encode(member(o, "actor")))
						}
					}
					if member(o, "counted") != canon.String(counted) {
						t.Fatalf("up to %s, %s: counted %v, want %s", s.upto, x.id[:12], member(o, "counted"), counted)
					}
					ev, ok := member(o, "identity_evaluator").(*canon.Object)
					if !ok || ev.Members["version"] == nil || ev.Members["evidence_digest"] == nil || !strings.HasPrefix(string(ev.Members["receipt"].(canon.String)), "sha256:") {
						t.Fatalf("no evaluator context: %s", canon.Encode(member(o, "identity_evaluator")))
					}
				}
				if s.upto == "authored-amends" {
					digest := string(member(showJSON(t, d, auth), "body", "content", "digest").(canon.String))
					r := d.run("verify", digest, "--json")
					if r.code != ExitOK || member(jsonOf(t, r), "authorship") != canon.String("sole author") {
						t.Fatalf("verify: %d\n%s", r.code, r.stdout)
					}
					if ex := d.run("explain", digest, "--json"); !strings.Contains(ex.stdout, `"identity":"`+ident+`"`) {
						t.Fatalf("explain does not name the identity as the claimant:\n%s", ex.stdout)
					}
				}
			}
		})
	}
}

func indexOf(s []string, x string) int {
	for i, v := range s {
		if v == x {
			return i
		}
	}
	return -1
}

// TestIdentityReaderNegativeVectorsThroughPull: every published negative vector delivered to `pull` beside its
// chain's good lines: a refused vector is refused intrinsic with the reason it states (bad signature: a tampered
// or stripped actor, a v1 preimage, a relabelled major, a non-canonical ed25519 encoding) and never written; a read
// one is admitted with the status it states (an rc/1 actor is not read; an rc/2 revoke_key is `invalid`, labelled,
// and counts toward nothing). The store keeps the rc/2 answer of the good lines whatever arrives beside them.
func TestIdentityReaderNegativeVectorsThroughPull(t *testing.T) {
	conformance.Partial(t, "C-id-36", "production reader: every published negative vector through pull (refused intrinsic or read with its stated status); the unchanged rc/1 reader's half stays in internal/wire and internal/resolve")
	conformance.Partial(t, "C-id-41", "through pull: a tampered or stripped actor is a bad signature, an rc/2 raw key event is admitted `invalid` and counts toward nothing; the marker/crit pairings are the wire reader's (internal/wire)")
	for _, chain := range []string{"ed", "eip"} {
		pos, neg := vectorChain(t, chain)
		for _, n := range neg {
			t.Run(n.Name, func(t *testing.T) {
				src := commitLines(t, pos["worker-genesis"].Line, pos["inception"].Line, pos["grant"].Line)
				pkg := src.pkgDir()
				st, _ := wire.Read([]byte(n.Delivered))
				signer := n.Signer
				if st != nil {
					signer = st.Signer
				}
				id := "0000000000000000000000000000000000000000000000000000000000000000"
				if rs, err := wire.ReadStored([]byte(n.Delivered)); err == nil {
					id = rs.ID
				} else if st != nil && st.ID != "" {
					id = st.ID
				}
				rel := stmtPath(signer, id)
				os.MkdirAll(filepath.Dir(filepath.Join(pkg, rel)), 0o755)
				if err := os.WriteFile(filepath.Join(pkg, rel), []byte(n.Delivered), 0o644); err != nil {
					t.Fatal(err)
				}
				d := newWorld(t)
				r := d.run("pull", pkg, "--json")
				rep := jsonOf(t, r)
				row := objectRow(t, rep, rel)
				switch n.Result {
				case "refused":
					if r.code != 1 || row == nil || row.Members["class"] != canon.String(n.Class) || row.Members["reason"] != canon.String(n.Reason) {
						t.Fatalf("want refused %s/%s: exit %d %s", n.Class, n.Reason, r.code, canon.Encode(row))
					}
					if _, err := os.Stat(filepath.Join(d.root, rel)); err == nil {
						t.Fatal("a refused vector was written")
					}
				case "read":
					if r.code != ExitOK {
						t.Fatalf("want read: exit %d\n%s", r.code, r.stdout)
					}
					o := showJSON(t, d, id)
					if o.Members["status"] != canon.String(n.Status) {
						t.Fatalf("status %v, want %s", o.Members["status"], n.Status)
					}
					if member(o, "actor") != nil {
						t.Fatalf("an actor read on a line that carries none the reader reads: %s", canon.Encode(member(o, "actor")))
					}
					if n.Status == "invalid" {
						if o.Members["counted"] != canon.String("not counted") {
							t.Fatalf("an invalid line counted: %s", r.stdout)
						}
						if row == nil || !strings.Contains(string(canon.Encode(row)), `"invalid"`) {
							t.Fatalf("the pull report does not label the invalid line: %s", canon.Encode(row))
						}
					}
				default:
					t.Fatalf("outcome %q", n.Result)
				}
			})
		}
	}
}

// TestIdentityReaderAmendmentsThroughCommands: the amendment scenarios over signed rc/2 evidence, read through the
// production reader and the commands (no fake evaluator, no test-only resolver): two delegates of I with
// amend:true; concurrent cross-key amendments of one claim leave the licence contested (verify 3) and an amendment
// naming both reconciles it (verify 0); an authorized amendment naming a missing target makes I's licence unknown
// (verify 3) while the claim stays I's; an amendment naming another principal's claim applies to nothing and is
// not a claim of I; an outsider's self-signed actor naming I with an invented grant changes nothing.
func TestIdentityReaderAmendmentsThroughCommands(t *testing.T) {
	conformance.Covers(t, "C-id-21", "C-id-22", "C-id-44", "C-id-45")
	ghost := strings.Repeat("e", 64)
	build := func() (*world, map[string][2]string, string) {
		w := newWorld(t)
		w.worker("K1")
		w.worker("K2")
		w.worker("S")
		i, a := w.identityOf("I", "IR", canon.Bool(true), "K1", "K2")
		return w, a, i
	}
	licence := func(d *world) (string, *canon.Object, int) {
		t.Helper()
		r := d.run("verify", dig("X"), "--json")
		o := jsonOf(t, r)
		st, _ := member(o, "disclosures", "licence", "state").(canon.String)
		return string(st), o, r.code
	}

	// C-id-21 / C-id-45: K2 amends K1's claim of I (amend:true is identity-wide, across keys and grants)
	w, a, i := build()
	w.signRC2("A0", "K1", "authored", licBody("X", "MIT"), a["K1"])
	w.signRC2("A1", "K1", "authored", amendingBody("X", "CC0-1.0", w.ids["A0"]), a["K1"])
	w.signRC2("B1", "K2", "authored", amendingBody("X", "Apache-2.0", w.ids["A0"]), a["K2"])
	if st, o, code := licence(w.pullInto()); st != "contested" || code != ExitCouldNot {
		t.Fatalf("concurrent cross-key amendments: %s %d\n%s", st, code, canon.Encode(o))
	}
	w.signRC2("C1", "K2", "authored", amendingBody("X", "CC-BY-4.0", w.ids["A1"], w.ids["B1"]), a["K2"])
	d := w.pullInto()
	st, o, code := licence(d)
	if st != "default" || code != ExitOK || member(o, "authorship") != canon.String("sole author") {
		t.Fatalf("reconciled: %s %d\n%s", st, code, canon.Encode(o))
	}
	if ex := d.run("explain", dig("X"), "--json"); !strings.Contains(ex.stdout, `"identity":"`+i+`"`) || !strings.Contains(ex.stdout, "CC-BY-4.0") {
		t.Fatalf("explain: %s", ex.stdout)
	}

	// C-id-22 / C-id-44: an authorized amendment naming a missing target makes I's view unknown, exit 3
	w, a, _ = build()
	w.signRC2("A0", "K1", "authored", licBody("X", "MIT"), a["K1"])
	w.signRC2("B1", "K2", "authored", amendingBody("X", "CC0-1.0", w.ids["A0"], ghost), a["K2"])
	if st, o, code := licence(w.pullInto()); st != "unknown" || code != ExitCouldNot {
		t.Fatalf("missing target: %s %d\n%s", st, code, canon.Encode(o))
	}

	// C-id-22: another principal's target (S's bare-key claim): the amendment applies to nothing, is not I's claim
	w, a, _ = build()
	w.signRC2("A0", "K1", "authored", licBody("X", "MIT"), a["K1"])
	w.authored("S1", "S", "X", "licence", "GPL-3.0")
	w.signRC2("B1", "K2", "authored", amendingBody("X", "CC0-1.0", w.ids["S1"]), a["K2"])
	d = w.pullInto()
	if ex := d.run("explain", dig("X")); !strings.Contains(ex.stdout, "amends nothing") {
		t.Fatalf("wrong principal: %s", ex.stdout)
	}

	// C-id-44: an outsider S signs an actor naming I with an invented grant: I's answer is unchanged
	w, a, i = build()
	w.signRC2("A0", "K1", "authored", licBody("X", "MIT"), a["K1"])
	before := w.pullInto().run("verify", dig("X"), "--json")
	z := w.signRC2("Z", "S", "authored", amendingBody("X", "WTFPL", w.ids["A0"]), [2]string{i, ghost})
	d = w.pullInto()
	after := d.run("verify", dig("X"), "--json")
	strip := func(s string) string { return s[:strings.Index(s, `"identity_evaluator"`)] }
	if before.code != ExitOK || after.code != ExitOK || strip(before.stdout) != strip(after.stdout) {
		t.Fatalf("an outsider changed I's answer:\n%s\nvs\n%s", before.stdout, after.stdout)
	}
	o = showJSON(t, d, z)
	if member(o, "actor", "state") == canon.String("eligible") || o.Members["counted"] != canon.String("not counted") {
		t.Fatalf("outsider: %s", canon.Encode(o))
	}
}

// TestIdentityReaderCapIsUnknown: C-id-39 through the commands. When admission fails as a whole (more authenticated
// statements than identity.MaxAdmitLines: no partial snapshot), every identity question reads `unknown` naming the
// failure: verify of I's content exits 3, show prints the actor unknown with the cap's reason and the statement not
// counted, never its key's; a bare-key claim in the same store keeps its answer. The admission failure itself is
// signed past the cap in internal/identity (TestAdmitCaps); here the reader's evaluator is the one it builds then.
func TestIdentityReaderCapIsUnknown(t *testing.T) {
	conformance.Covers(t, "C-id-39")
	w := newWorld(t)
	w.worker("K1")
	_, a := w.identityOf("I", "IR", canon.Bool(true), "K1")
	id := w.signRC2("A0", "K1", "authored", licBody("X", "MIT"), a["K1"])
	w.authored("B0", "B", "Y", "licence", "MIT")
	d := w.pullInto()
	if r := d.run("verify", dig("X")); r.code != ExitOK {
		t.Fatalf("control: %d\n%s", r.code, r.stdout)
	}
	capErr := errors.New("identity: more than 100000 distinct authenticated statements; no partial snapshot")
	old := newEvaluator
	t.Cleanup(func() { newEvaluator = old })
	newEvaluator = func(lines [][]byte) policy.ActorEligibility {
		if old(lines) == nil {
			return nil
		}
		return identity.Unavailable{Err: capErr}
	}
	r := d.run("verify", dig("X"), "--json")
	if r.code != ExitCouldNot || !strings.Contains(r.stdout, "no partial snapshot") {
		t.Fatalf("verify over the cap: %d\n%s", r.code, r.stdout)
	}
	o := showJSON(t, d, id)
	if member(o, "actor", "state") != canon.String("unknown") || o.Members["counted"] != canon.String("not counted") ||
		!strings.Contains(string(canon.Encode(o)), "model_limit") {
		t.Fatalf("show over the cap: %s", canon.Encode(o))
	}
	if ex := d.run("explain", dig("X")); !strings.Contains(ex.stdout, "whether it acts for it is not established") {
		t.Fatalf("explain over the cap: %s", ex.stdout)
	}
	if r := d.run("verify", dig("Y")); r.code != ExitOK {
		t.Fatalf("a bare-key claim moved: %d\n%s", r.code, r.stdout)
	}
}

// TestIdentityReaderTrustFloor: the pull gate's trust floor asks the production evaluator over the store and the
// package. An `{identity: I}` admission entry admits I's grant-covered act the package brings with its inception and
// grant, and refuses (below the floor) the same worker key's bare rc/1 statement and an outsider's act naming I.
func TestIdentityReaderTrustFloor(t *testing.T) {
	conformance.Partial(t, "C-id-02", "the pull trust floor over the production evaluator: an {identity: I} admission entry admits I's grant-covered act and refuses the worker's bare line")
	w := newWorld(t)
	w.worker("K1")
	w.worker("S")
	i, a := w.identityOf("I", "IR", canon.Bool(true), "K1")
	act := w.signRC2("A0", "K1", "authored", licBody("X", "MIT"), a["K1"])
	bare := w.authored("K1:bare", "K1", "Y", "licence", "MIT")
	out := w.signRC2("Z", "S", "authored", licBody("X", "WTFPL"), [2]string{i, strings.Repeat("e", 64)})
	pf := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(pf, []byte(`{"version":"reader-policy-v1","selections":[],"trust":[{"principal":{"identity":"`+i+`"},"purposes":["admission"],"targets":{"any_content":true}}]}`), 0o644)
	pkg := t.TempDir()
	copyData(t, w.root, pkg)
	r := newWorld(t).run("pull", pkg, "--policy", pf, "--below-floor", "refuse", "--json")
	rep := jsonOf(t, r)
	verdict := func(signer, id string) string {
		row := objectRow(t, rep, stmtPath(signer, id))
		if row == nil {
			return "admitted"
		}
		v, _ := row.Members["verdict"].(canon.String)
		return string(v)
	}
	if v := verdict(w.signer("K1"), act); v == "refused" {
		t.Fatalf("I's act refused:\n%s", r.stdout)
	}
	if v := verdict(w.signer("K1"), bare); v != "refused" {
		t.Fatalf("the worker's bare line: %s\n%s", v, r.stdout)
	}
	if v := verdict(w.signer("S"), out); v != "refused" {
		t.Fatalf("the outsider's act: %s\n%s", v, r.stdout)
	}
}

// TestIdentityReaderStoreRefusesBadRC2: a store commits nothing the production reader refuses: an rc/2 line with
// a flipped signature byte is refused before the commit point (bad signature: no journal record, no file), as an
// rc/1 one is, and fsck stays clean.
func TestIdentityReaderStoreRefusesBadRC2(t *testing.T) {
	conformance.Partial(t, "C-id-36", "the store's commit path under the production reader: a bad rc/2 signature is refused, never retained as an unverified other-major line")
	w := newWorld(t)
	w.worker("K1")
	_, a := w.identityOf("I", "IR", canon.Bool(true), "K1")
	line, _ := w.rc2Line("K1", "authored", licBody("X", "MIT"), a["K1"])
	i := strings.Index(string(line), `"sig":"`) + len(`"sig":"`) + 4
	bad := append([]byte(nil), line...)
	if bad[i] == '0' {
		bad[i] = '1'
	} else {
		bad[i] = '0'
	}
	before := snapshot(t, w.root)
	if out, err := w.s.Commit("publish", [][]byte{bad}, nil); err == nil || out.Committed || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("a bad rc/2 signature reached the commit point: committed %v, %v", out.Committed, err)
	}
	if snapshot(t, w.root) != before {
		t.Fatal("refusing the line changed the store (a journal record or a statement file was written)")
	}
	if _, err := wire.Read(bad); err != nil {
		t.Fatalf("control: the rc/1-only reader retains it (%v)", err)
	}
	if r := w.run("fsck", "--json"); r.code != ExitOK || !strings.Contains(r.stdout, `"clean":true`) {
		t.Fatalf("fsck: %d %s", r.code, r.stdout)
	}
}
