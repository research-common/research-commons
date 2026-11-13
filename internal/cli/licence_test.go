package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// TestLicenceSurfaces: C-core-67 through the commands. (a) no licence field, (b) an expression the reader cannot
// parse and (c) `LicenseRef-X AND CC-BY-4.0` with LicenseRef-X cited by location only, over show, list, verify and
// explain. (a) and (b) read licence `unknown` (never open); (c) shows the expression with LicenseRef-X as `cited
// (location only, unverified)`, and the held-text and no-source citations read as their own states. No default
// licence text is written into a statement, and the grade and exit are those of the same blob with a plain licence.
func TestLicenceSurfaces(t *testing.T) {
	conformance.Covers(t, "C-core-67")
	w := newWorld(t)
	type row struct {
		name  string
		kv    []any
		state string
		cite  []string // the citations expected beside the refs, in order
	}
	w.blob("textheld", []byte("the licence text"))
	for _, b := range []string{"a", "b", "c", "d", "e", "plain"} {
		w.blob(b, []byte(b))
	}
	rows := []row{
		{"a", nil, "unknown", nil},
		{"b", []any{"licence", "not spdx"}, "unknown", nil},
		{"c", []any{"licence", "LicenseRef-X AND CC-BY-4.0", "licence_texts", obj("LicenseRef-X", "https://example.org/x-terms")}, "default", []string{"cited (location only, unverified)"}},
		{"d", []any{"licence", "LicenseRef-X OR LicenseRef-Y", "licence_texts", obj("LicenseRef-X", dig("the licence text"), "LicenseRef-Y", dig("nowhere"))}, "default", []string{"cited (text held)", "cited (text not held)"}},
		{"e", []any{"licence", "LicenseRef-Z"}, "default", []string{"cited (no source)"}},
		{"plain", []any{"licence", "CC-BY-4.0"}, "default", nil},
	}
	for _, r := range rows {
		w.authored("A:"+r.name, "K1", r.name, r.kv...)
	}
	// no default text is written: the statement for (a) has no licence member, and (b) carries the bytes as written
	if _, has := bodyOf(t, w, "A:a").Get("licence"); has {
		t.Fatal("a licence was written into a statement that declared none")
	}
	if v, _ := bodyOf(t, w, "A:b").Get("licence"); v != canon.String("not spdx") {
		t.Fatalf("the unparsable expression was rewritten: %v", v)
	}
	plain := w.run("verify", dig("plain"), "--json")
	for _, r := range rows {
		d := dig(r.name)
		surfaces := map[string]*canon.Object{}
		for _, cmd := range []string{"show", "verify", "explain"} {
			surfaces[cmd] = jsonOf(t, w.run(cmd, d, "--json"))
		}
		for _, b := range jsonOf(t, w.run("list", "--json")).Members["blobs"].(canon.Array) {
			if bo := b.(*canon.Object); bo.Members["digest"] == canon.String(d) {
				surfaces["list"] = bo
			}
		}
		if len(surfaces) != 4 {
			t.Fatalf("%s: %d surfaces", r.name, len(surfaces))
		}
		var first string
		for cmd, o := range surfaces {
			l := disclosureOf(t, o, "licence")
			if l.Members["state"] != canon.String(r.state) {
				t.Fatalf("%s %s: licence state %s, want %s", r.name, cmd, canon.Encode(l), r.state)
			}
			if r.state == "unknown" && l.Members["value"] != nil && r.name == "a" {
				t.Fatalf("%s %s: a value for a missing licence: %s", r.name, cmd, canon.Encode(l))
			}
			if e := string(canon.Encode(l)); first == "" {
				first = e
			} else if e != first {
				t.Fatalf("%s: surfaces disagree on the licence:\n%s\n%s", r.name, first, e)
			}
			var got []string
			if rs, ok := l.Members["refs"].(canon.Array); ok {
				for _, x := range rs {
					got = append(got, string(x.(*canon.Object).Members["citation"].(canon.String)))
				}
			}
			if strings.Join(got, "|") != strings.Join(r.cite, "|") {
				t.Fatalf("%s %s: citations %v, want %v", r.name, cmd, got, r.cite)
			}
		}
		h := w.run("show", d).stdout
		lic := h[strings.Index(h, "  licence:\n"):]
		lic = lic[:strings.Index(lic, "  pre registration:")]
		switch r.name {
		case "a":
			if !strings.Contains(lic, "state: unknown") || strings.Contains(lic, "value") || strings.Contains(lic, "parse") {
				t.Fatalf("a: human surface:\n%s", lic)
			}
		case "b":
			if !strings.Contains(lic, "state: unknown") || !strings.Contains(lic, "parse: not an SPDX license expression") {
				t.Fatalf("b: human surface:\n%s", lic)
			}
		case "c":
			if !strings.Contains(lic, "state: default") || !strings.Contains(lic, "LicenseRef-X AND CC-BY-4.0") || !strings.Contains(lic, "cited (location only, unverified)") ||
				!strings.Contains(lic, "identifiers not checked against the SPDX License List") {
				t.Fatalf("c: human surface:\n%s", lic)
			}
		}
		// grade and exit are unchanged by any of it
		v := jsonOf(t, w.run("verify", d, "--json"))
		if v.Members["grade"] != jsonOf(t, plain).Members["grade"] || v.Members["exit"] != jsonOf(t, plain).Members["exit"] {
			t.Fatalf("%s: licence moved the grade or exit: %s vs %s", r.name, canon.Encode(v), canon.Encode(jsonOf(t, plain)))
		}
	}
}

// bodyOf is the body of a statement the world signed, as `show` prints it.
func bodyOf(t *testing.T, w *world, name string) *canon.Object {
	t.Helper()
	b, ok := jsonOf(t, w.run("show", w.ids[name], "--json")).Members["body"].(*canon.Object)
	if !ok {
		t.Fatalf("no body for %s", name)
	}
	return b
}
