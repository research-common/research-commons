package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// stmtPath is where a package carries the statement of signer under id.
func stmtPath(signer, id string) string {
	return filepath.Join("statements", strings.ReplaceAll(signer, ":", "-"), id)
}

// refusedRow is the one refused object of a pull report.
func refusedRow(t *testing.T, r result) *canon.Object {
	t.Helper()
	var row *canon.Object
	for _, x := range jsonOf(t, r).Members["objects"].(canon.Array) {
		if o := x.(*canon.Object); o.Members["verdict"] == canon.String("refused") {
			if row != nil {
				t.Fatalf("two refused objects: %s", r.stdout)
			}
			row = o
		}
	}
	if row == nil {
		t.Fatalf("nothing refused (exit %d): %s", r.code, r.stdout)
	}
	return row
}

// TestPullFlippedFieldsRefused: C-core-09. A statement carrying provenance, a licence, an unknown extension and a
// type is delivered to `pull` with one byte flipped in each value of its canonical body in turn (the nested
// provenance members too), and in the envelope's kind. A control delivers it untouched: admitted. Every flip is
// refused in the intrinsic class naming `bad signature` or `malformed statement`; a `bad signature` detail is
// the signature check's own ("does not recover"), which proves the line parsed and reached it (the digest the
// gate parsed is the statement id the refusal row carries); the reader's store is byte-identical afterwards and
// no surface shows the mutated value as anyone's word.
func TestPullFlippedFieldsRefused(t *testing.T) {
	conformance.Covers(t, "C-core-09")
	src := newWorld(t)
	src.blob("x", []byte("x"))
	src.blob("wf", []byte("wf"))
	src.blob("in", []byte("in"))
	id := src.authored("A:x", "K2", "x", "licence", "CC-BY-4.0", "x_ext", "vvvv", "prov", []string{"wf", "in"})
	rel := stmtPath(src.signer("K2"), id)
	pkg := t.TempDir()
	copyData(t, src.root, pkg)
	line := mustRead(t, filepath.Join(pkg, rel))

	if r := newWorld(t).run("pull", pkg, "--json"); r.code != 0 {
		t.Fatalf("control: the untouched statement is not admitted: %d %s", r.code, r.stdout)
	}
	// each value of the body, as it is spelled in the line
	fields := map[string]string{"licence": `"CC-BY-4.0"`, "x_ext": `"vvvv"`, "type": `"dataset"`, "kind": `"authored"`,
		"provenance.workflow": `"` + dig("wf") + `"`, "provenance.inputs[0]": `"` + dig("in") + `"`, "content.digest": `"` + dig("x") + `"`}
	for name, v := range fields {
		t.Run(name, func(t *testing.T) {
			i := strings.Index(string(line), v)
			if i < 0 {
				t.Fatalf("%s not found in the line", v)
			}
			m := append([]byte(nil), line...)
			m[i+2] ^= 0x01 // a byte inside the value, not its quote
			if string(m) == string(line) {
				t.Fatal("no mutation")
			}
			mp := t.TempDir()
			copyData(t, src.root, mp)
			os.WriteFile(filepath.Join(mp, rel), m, 0o644)
			dst := newWorld(t)
			r := dst.run("pull", mp, "--json")
			row := refusedRow(t, r)
			reason, _ := row.Members["reason"].(canon.String)
			detail, _ := row.Members["detail"].(canon.String)
			if r.code != 1 || row.Members["class"] != canon.String("intrinsic") || (reason != "bad signature" && reason != "malformed statement") {
				t.Fatalf("%s flipped: exit %d class %v reason %v\n%s", name, r.code, row.Members["class"], reason, r.stdout)
			}
			if reason == "bad signature" && !strings.Contains(string(detail), "does not recover") {
				t.Fatalf("a bad signature that is not the signature check's: %s", detail)
			}
			if row.Members["id"] != canon.String(id) {
				t.Fatalf("the refusal row does not carry the delivered statement id: %s", canon.Encode(row))
			}
			for _, ref := range []string{id, dig("x")} {
				for _, c := range []string{"show", "verify", "explain"} {
					if o := dst.run(c, ref, "--json"); strings.Contains(o.stdout, "CC-BY-4.0") || strings.Contains(o.stdout, "vvvv") || strings.Contains(o.stdout, string(m[strings.Index(string(m), `"sig"`):][:20])) {
						t.Fatalf("%s %s shows the mutated statement as the signer's word:\n%s", c, ref[:12], o.stdout)
					}
				}
			}
			if a := dst.run("list", "--json").stdout; strings.Contains(a, "authorship: sole") || strings.Contains(a, `"sole author"`) {
				t.Fatalf("a refused statement became an authorship claim:\n%s", a)
			}
			ents, _ := os.ReadDir(filepath.Join(dst.root, "statements"))
			if len(ents) != 0 {
				t.Fatalf("a refused statement was written: %v", ents)
			}
		})
	}
}

// TestPullParserRefusals: C-core-12. Statements handed to `pull` with a duplicate key, NaN, Infinity, a
// non-integer, exponent, negative-zero, leading-zero and out-of-range number, a lone surrogate, invalid UTF-8, a
// byte-order mark, a raw control character, trailing data, nesting past the documented depth, and a valid line
// in a non-canonical byte form. Each line is well under the size limit, so it reaches the parser: the refusal
// names the parser's own rule (malformed statement and its detail; depth limit for nesting, operational;
// `not canonical` for the valid line), and the reader's state is byte-identical afterwards: no line enters
// any log and every surface answers as before.
func TestPullParserRefusals(t *testing.T) {
	conformance.Covers(t, "C-core-12")
	src := newWorld(t)
	src.blob("x", []byte("x"))
	good := src.authored("A:x", "K2", "x", "licence", "CC0-1.0")
	rel := stmtPath(src.signer("K2"), good)
	goodLine := mustRead(t, filepath.Join(src.root, rel))
	deep := strings.Repeat(`{"a":`, 17) + "1" + strings.Repeat("}", 17)
	for _, c := range []struct {
		name, line, class, reason, detail string
	}{
		{"duplicate key", `{"licence":"a","licence":"b"}`, "intrinsic", "malformed statement", `duplicate key "licence"`},
		{"NaN", `{"seq":NaN}`, "intrinsic", "malformed statement", "non-finite"},
		{"Infinity", `{"seq":Infinity}`, "intrinsic", "malformed statement", "non-finite"},
		{"non-integer", `{"seq":1.0}`, "intrinsic", "malformed statement", "non-integer"},
		{"exponent", `{"seq":1e3}`, "intrinsic", "malformed statement", "non-integer"},
		{"negative zero", `{"seq":-0}`, "intrinsic", "malformed statement", "negative zero"},
		{"leading zero", `{"seq":01}`, "intrinsic", "malformed statement", "leading zero"},
		{"out of range", `{"seq":9007199254740992}`, "intrinsic", "malformed statement", "out of range"},
		{"lone surrogate", `{"licence":"\ud800"}`, "intrinsic", "malformed statement", "lone surrogate"},
		{"invalid UTF-8", "{\"licence\":\"\xff\"}", "intrinsic", "malformed statement", "invalid UTF-8"},
		{"byte order mark", "\xef\xbb\xbf{}", "intrinsic", "malformed statement", "byte order mark"},
		{"raw control character", "{\"licence\":\"x\ny\"}", "intrinsic", "malformed statement", "raw control character"},
		{"trailing data", `{"seq":1}x`, "intrinsic", "malformed statement", "trailing data"},
		{"nesting past the depth limit", deep, "operational", "depth limit", "depth limit 16"},
		{"valid line, other bytes", string(noncanonical(t, goodLine)), "intrinsic", "not canonical", "canonical"},
		{"valid line, escaped Unicode", strings.Replace(string(goodLine), `"licence":"CC0-1.0"`, `"licence":"\u0043C0-1.0"`, 1), "intrinsic", "not canonical", "canonical"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if len(c.line) > 4096 {
				t.Fatal("the line is not small: the size limit could be what refuses it")
			}
			pkg := t.TempDir()
			os.WriteFile(filepath.Join(pkg, "rc-store"), mustRead(t, filepath.Join(src.root, "rc-store")), 0o644)
			p := filepath.Join(pkg, rel)
			os.MkdirAll(filepath.Dir(p), 0o755)
			os.WriteFile(p, []byte(c.line), 0o644)
			dst := newWorld(t)
			refs := []string{good, dig("x")}
			beforeRoot, beforeView := snapshot(t, dst.root), viewDigest(surfaces(t, dst.root, refs))
			r := dst.run("pull", pkg, "--json")
			row := refusedRow(t, r)
			detail, _ := row.Members["detail"].(canon.String)
			if r.code != 1 || row.Members["class"] != canon.String(c.class) || row.Members["reason"] != canon.String(c.reason) || !strings.Contains(string(detail), c.detail) {
				t.Fatalf("exit %d: %s", r.code, canon.Encode(row))
			}
			if snapshot(t, dst.root) != beforeRoot || viewDigest(surfaces(t, dst.root, refs)) != beforeView {
				t.Fatal("a refused line changed the reader's state")
			}
		})
	}
}
