package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

// xzSecretBytes is `{"secret":1}` in xz: the forbidden key is inside, invisible to a reader that treats the
// blob as opaque bytes.
var xzSecretBytes = []byte("\xfd7zXZ\x00\x00\x01i\"\xde6\x02\x00!\x01\x1c\x00\x00\x00\x10\xcfX\xcc\x01\x00\x0b{\"secret\":1}\x00\x8f\x9c\xa1A\x00\x01 \x0c\xa2\xdd\xb4\xbc\x90B\x99\r\x01\x00\x00\x00\x00\x01YZ")

// TestSweepPullPublishRuleEvidenceNeverPasses: P-09 through the shipped commands. A statement records intended_for
// outcome ok over content the receiver reads. In each row the evidence the rule needs is substituted, and neither
// `pull --dry-run` (the gate's labelled row) nor `publish --intended-for` (the pre-pin check) computes ok:
//   - shipped reader, no dialect registered: every rule is unchecked ("unsupported dialect")
//   - content neither in the package nor in the store: unchecked
//   - content in a compression the scanner cannot read (xz): unchecked
//
// Controls (dialect registered, readable bytes) compute ok for a clean blob and fail for a forbidden one.
func TestSweepPullPublishRuleEvidenceNeverPasses(t *testing.T) {
	good, bad := []byte(`{"fine":1}`), []byte(`{"secret":1}`)
	missing := []byte(`{"never":"installed"}`)
	src := newPubWorld(t)
	g, e := src.collection("FORBID secret")
	claim := func() *canon.Object { return obj("resource", g, "edition", e, "edition_applied", e, "outcome", "ok") }
	for n, b := range map[string][]byte{"good": good, "bad": bad, "xz": xzSecretBytes} {
		src.blob(n, b)
		src.authored("A"+n, "K1", string(b), "intended_for", claim())
	}
	src.authored("Amissing", "K1", string(missing), "intended_for", claim()) // blob never installed
	blobs, stmts := dataObjects(t, src.root)
	objs := [][2]string{{"rc-store", ""}}
	for _, o := range append(blobs, stmts...) {
		objs = append(objs, [2]string{o, ""})
	}
	pkg := tarPackage(t, src.root, objs, false)
	rows := func(dialect bool) map[string]string {
		if dialect {
			withDialect(t)
		} else {
			ruleDialects = nil
		}
		r := newWorld(t).run("pull", pkg, "--dry-run", "--json")
		if r.code != 0 {
			t.Fatalf("dialect=%v: exit %d\n%s", dialect, r.code, r.stdout)
		}
		out := map[string]string{}
		arr, _ := jsonOf(t, r).Members["objects"].(canon.Array)
		for _, row := range arr {
			ro := row.(*canon.Object)
			if id, ok := ro.Members["id"].(canon.String); ok {
				out[string(id)] = string(canon.Encode(ro))
			}
		}
		return out
	}
	// shipped: no dialect at all, so no statement's rule is ever computed ok, whatever the bytes
	for name, row := range rows(false) {
		_ = name
		if strings.Contains(row, "intended_for") && (strings.Contains(row, ": ok;") || strings.Contains(row, ": fail;")) {
			t.Errorf("no dialect: a computed outcome in %s", row)
		}
	}
	shipped := rows(false)
	for _, n := range []string{"Agood", "Abad", "Axz", "Amissing"} {
		if row := shipped[src.ids[n]]; !strings.Contains(row, ": unchecked;") {
			t.Errorf("no dialect, %s: %s", n, row)
		}
	}
	// dialect registered: the substituted-evidence rows stay unchecked; the controls decide
	with := rows(true)
	for n, want := range map[string]string{"Agood": ": ok;", "Abad": ": fail;", "Axz": ": unchecked;", "Amissing": ": unchecked;"} {
		row := with[src.ids[n]]
		if !strings.Contains(row, want) {
			t.Errorf("dialect, %s: want %q in %s", n, want, row)
		}
		if (n == "Axz" || n == "Amissing") && (strings.Contains(row, ": ok;") || strings.Contains(row, ": fail;")) {
			t.Errorf("dialect, %s: substituted evidence computed an outcome: %s", n, row)
		}
	}

	// the pre-pin check at publish: the same substitutions record unchecked, never ok
	p := newPubWorld(t)
	pg, pe := p.collection("FORBID secret")
	xz := p.file("x.xz", string(xzSecretBytes))
	ruleDialects = nil
	for name, f := range map[string]string{"no dialect, clean bytes": p.file("g", string(good)), "no dialect, xz bytes": xz} {
		r := p.publish("--kind", "authored", "--content", f, "--intended-for", pg+"/"+pe)
		if r.code != 0 || !strings.Contains(r.stdout, `"state":"unchecked"`) || strings.Contains(r.stdout, `"state":"ok"`) {
			t.Errorf("%s: %d %s", name, r.code, r.stdout)
		}
	}
	withDialect(t)
	if r := p.publish("--kind", "authored", "--content", xz, "--intended-for", pg+"/"+pe); r.code != 0 || !strings.Contains(r.stdout, `"state":"unchecked"`) || strings.Contains(r.stdout, `"state":"ok"`) {
		t.Errorf("dialect, xz bytes: %d %s", r.code, r.stdout)
	}
	if r := p.publish("--kind", "authored", "--content", p.file("g2", string(good)), "--intended-for", pg+"/"+pe); r.code != 0 || !strings.Contains(r.stdout, `"state":"ok"`) {
		t.Errorf("control: %d %s", r.code, r.stdout)
	}
}
