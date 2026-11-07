package cli

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write(b)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return z.Bytes()
}

// TestPullReadsContent: pull gives edition rules the package's blob bytes, as `hub check` does. A statement recording
// intended_for outcome ok over a tar.gz whose member holds the forbidden key is re-applied at pull as `fail`
// (the old behaviour was `unchecked`: content not held); over a clean tar.gz it is `ok`; over a blob the package does not
// carry and the store does not hold, `unchecked`. The same package pulled by two readers differs only in what each holds.
func TestPullReadsContent(t *testing.T) {
	withDialect(t)
	src := newPubWorld(t)
	g, e := src.collection("FORBID secret")
	bad := gzipBytes(t, tarOf(t, [2]string{"a.json", `{"ok":1}`}, [2]string{"b.json", `{"secret":1}`}))
	good := gzipBytes(t, tarOf(t, [2]string{"a.json", `{"ok":1}`}, [2]string{"b.json", `{"fine":1}`}))
	missing := gzipBytes(t, tarOf(t, [2]string{"c.json", `{"secret":2}`}))
	claim := func() *canon.Object { return obj("resource", g, "edition", e, "edition_applied", e, "outcome", "ok") }
	src.blob("bad", bad)
	src.blob("good", good)
	src.authored("Abad", "K1", string(bad), "intended_for", claim())
	src.authored("Agood", "K1", string(good), "intended_for", claim())
	src.authored("Amissing", "K1", string(missing), "intended_for", claim()) // its blob is never installed in src

	blobs, stmts := dataObjects(t, src.root)
	objs := [][2]string{{"rc-store", ""}}
	for _, o := range append(blobs, stmts...) {
		objs = append(objs, [2]string{o, ""})
	}
	for _, gz := range []bool{false, true} {
		pkg := tarPackage(t, src.root, objs, gz)
		dst := newWorld(t)
		r := dst.run("pull", pkg, "--dry-run", "--json")
		if r.code != 0 {
			t.Fatalf("gz=%v: exit %d\n%s", gz, r.code, r.stdout)
		}
		rows := map[string]string{}
		objsOut, _ := jsonOf(t, r).Members["objects"].(canon.Array)
		for _, row := range objsOut {
			ro := row.(*canon.Object)
			id, _ := ro.Members["id"].(canon.String)
			rows[string(id)] = string(canon.Encode(ro))
		}
		for _, name := range []string{"Abad", "Agood", "Amissing"} {
			if rows[src.ids[name]] == "" {
				t.Fatalf("gz=%v: no labelled row for %s: %v", gz, name, r.stdout)
			}
		}
		if got := rows[src.ids["Abad"]]; !strings.Contains(got, ": fail;") {
			t.Fatalf("gz=%v: forbidden key inside the pulled tar.gz was not found by the rule:\n%s", gz, got)
		}
		if got := rows[src.ids["Agood"]]; !strings.Contains(got, ": ok;") || strings.Contains(got, ": fail;") {
			t.Fatalf("gz=%v: clean tar.gz: %s", gz, got)
		}
		if got := rows[src.ids["Amissing"]]; !strings.Contains(got, ": unchecked;") {
			t.Fatalf("gz=%v: blob neither carried nor held: %s", gz, got)
		}
	}

	// a blob the store already holds is read from the store when the package does not carry it
	var rest [][2]string
	for _, o := range objs {
		if !strings.HasSuffix(o[0], strings.TrimPrefix(dig(string(bad)), "sha256:")) {
			rest = append(rest, o)
		}
	}
	dst := newWorld(t)
	dst.blob("bad", bad)
	r := dst.run("pull", tarPackage(t, src.root, rest, false), "--dry-run", "--json")
	if !strings.Contains(r.stdout, ": fail;") {
		t.Fatalf("held blob not read: exit %d\n%s", r.code, r.stdout)
	}
}
