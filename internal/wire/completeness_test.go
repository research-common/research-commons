package wire

import (
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
)

// TestSchemaCompleteness: edition.contents.completeness (wire §5) is the scope of a completeness claim: a class
// with a time position (source, phenomenon, method), a source and a window, with an optional timescale. It is malformed beside any selection but "completeness" and
// without one of its required members; each refusal names body.contents.completeness (or the window time at
// fault), so the mutation reached this check. Controls: the full scope beside selection "completeness" is
// admitted, so is a completeness selection with no scope (shown declared, its check unchecked), and a TAI window
// carries no Z.
func TestSchemaCompleteness(t *testing.T) {
	win := func(from, to string) *canon.Object { return body("from", from, "to", to) }
	scope := func(kv ...any) *canon.Object {
		o := body("class", "source", "source", "https://api.example/readings", "window", win("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"))
		for i := 0; i < len(kv); i += 2 {
			k := kv[i].(string)
			o = setField(o, k, body(k, kv[i+1]).Members[k])
		}
		return o
	}
	ed := func(kv ...any) *canon.Object { return setField(minimal("edition"), "contents", body(kv...)) }
	for _, c := range []struct {
		name, detail string
		b            *canon.Object
	}{
		{"no selection", "body.contents.completeness", ed("completeness", scope())},
		{"curated", "body.contents.completeness", ed("selection", "curated", "completeness", scope())},
		{"rule-based", "body.contents.completeness", ed("selection", "rule-based", "completeness", scope())},
		{"class none-yet", "body.contents.completeness.class", ed("selection", "completeness", "completeness",
			body("class", "none-yet", "source", "x", "window", win("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")))},
		{"class exact-bytes (no time position)", "body.contents.completeness.class", ed("selection", "completeness", "completeness",
			body("class", "exact-bytes", "source", "bip122:x", "window", win("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")))},
		{"no source", "body.contents.completeness.source", ed("selection", "completeness", "completeness",
			body("class", "source", "window", win("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")))},
		{"no window", "body.contents.completeness.window", ed("selection", "completeness", "completeness",
			body("class", "source", "source", "x"))},
		{"window offset", "offset other than Z", ed("selection", "completeness", "completeness",
			scope("window", win("2026-01-01T00:00:00+00:00", "2026-02-01T00:00:00Z")))},
		{"Z in TAI", "Z asserts UTC", ed("selection", "completeness", "completeness",
			scope("timescale", "TAI"))},
		{"timescale unknown", "FITS", ed("selection", "completeness", "completeness", scope("timescale", "GMT"))},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := readBody(t, "edition", c.b)
			refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, c.detail)
		})
	}
	for name, b := range map[string]*canon.Object{
		"scoped":   ed("selection", "completeness", "completeness", scope()),
		"unscoped": ed("selection", "completeness"),
		"TAI":      ed("selection", "completeness", "completeness", scope("timescale", "TAI", "window", win("2026-01-01T00:00:37", "2026-02-01T00:00:37"))),
	} {
		st, err := readBody(t, "edition", b)
		if err != nil || st.Status != Valid {
			t.Fatalf("%s: got %v, want admitted", name, err)
		}
	}
}
