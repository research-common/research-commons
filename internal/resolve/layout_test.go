package resolve

import (
	"strconv"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
)

// Fixtures shaped like a settlement-data response that carries the run per record (synthetic, not real data).
const (
	respAllRF   = `{"data":[{"settlementDate":"2025-01-01","settlementPeriod":1,"settlementRunType":"RF","quantity":12.5},{"settlementDate":"2025-01-01","settlementPeriod":2,"settlementRunType":"RF","quantity":-0.75}]}`
	respMixed   = `{"data":[{"settlementPeriod":1,"settlementRunType":"R1","quantity":1.5},{"settlementPeriod":2,"settlementRunType":"RF","quantity":2}]}`
	respAllR1   = `{"data":[{"settlementPeriod":1,"settlementRunType":"R1","quantity":1.5},{"settlementPeriod":2,"settlementRunType":"R1","quantity":2}]}`
	respMissing = `{"data":[{"settlementPeriod":1,"settlementRunType":"RF"},{"settlementPeriod":2}]}`
	respCSV     = "settlementDate,settlementPeriod,settlementRunType\n2025-01-01,1,RF\n"
	// one record carries a label the profile does not have (II), beside two it places
	respOneUnknown = `{"data":[{"settlementPeriod":1,"settlementRunType":"RF"},{"settlementPeriod":2,"settlementRunType":"II"},{"settlementPeriod":3,"settlementRunType":"R1"}]}`
)

func layoutBytes(records, state string) []byte {
	return canon.Encode(obj("layout", ResponseLayoutTag, "records", records, "state", state))
}

func mustLayout(t *testing.T, b []byte) *ResponseLayout {
	t.Helper()
	l, err := ParseResponseLayout(b)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// TestParsePointer: RFC 6901 syntax, unescaping ~1 before ~0 (§4), and the reader caps.
func TestParsePointer(t *testing.T) {
	for in, want := range map[string][]string{
		"":         nil,
		"/":        {""},
		"/a/0":     {"a", "0"},
		"/a~1b":    {"a/b"},
		"/m~0n":    {"m~n"},
		"/~01":     {"~1"},
		"/a//b":    {"a", "", "b"},
		"/ünïcode": {"ünïcode"},
	} {
		got, err := ParsePointer(in)
		if err != nil || strings.Join(got, "|") != strings.Join(want, "|") || len(got) != len(want) {
			t.Errorf("ParsePointer(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for in, why := range map[string]string{
		"a":                             `does not start with "/"`,
		"/a~":                           `"~0" or "~1"`,
		"/a~2":                          `"~0" or "~1"`,
		strings.Repeat("/a", 17):        "depth limit",
		"/" + strings.Repeat("x", 1024): "longer than",
	} {
		if _, err := ParsePointer(in); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("ParsePointer(%.20q): %v, want %q", in, err, why)
		}
	}
}

// TestParseResponseLayout: closed members, canonical bytes, pointers syntactically RFC 6901; the control parses.
func TestParseResponseLayout(t *testing.T) {
	l := mustLayout(t, layoutBytes("/data", "/settlementRunType"))
	if !l.HasRecords || strings.Join(l.Records, "/") != "data" || strings.Join(l.State, "/") != "settlementRunType" {
		t.Fatalf("parsed %+v", l)
	}
	one := mustLayout(t, canon.Encode(obj("layout", ResponseLayoutTag, "state", "/meta/run")))
	if one.HasRecords {
		t.Fatal("a layout without records reads one state")
	}
	for name, c := range map[string]struct {
		b   []byte
		why string
	}{
		"not canonical":     {[]byte(`{"state":"/a", "layout":"rc-response-layout/1"}`), "canonical"},
		"undefined member":  {canon.Encode(obj("layout", ResponseLayoutTag, "state", "/a", "format", "csv")), `undefined member "format"`},
		"x_ member":         {canon.Encode(obj("layout", ResponseLayoutTag, "state", "/a", "x_note", "n")), `undefined member "x_note"`},
		"other tag":         {canon.Encode(obj("layout", "rc-response-layout/2", "state", "/a")), "layout is not"},
		"no state":          {canon.Encode(obj("layout", ResponseLayoutTag, "records", "/a")), `missing required member "state"`},
		"bad pointer":       {layoutBytes("data", "/a"), "records is not an RFC 6901 JSON pointer"},
		"bad escape":        {layoutBytes("/data", "/a~x"), "state is not an RFC 6901 JSON pointer"},
		"pointer not str":   {canon.Encode(obj("layout", ResponseLayoutTag, "state", 3)), "state is not a string"},
		"too deep together": {layoutBytes(strings.Repeat("/a", 9), strings.Repeat("/b", 8)), "past the depth limit"},
	} {
		if _, err := ParseResponseLayout(c.b); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v, want %q", name, err, c.why)
		}
	}
}

// settlementRank is the order of profile P in these tests: SF < R1 < R2 < RF < DF.
func settlementRank(l string) (int, bool) {
	i := map[string]int{"SF": 0, "R1": 1, "R2": 2, "RF": 3, "DF": 4}
	r, ok := i[l]
	return r, ok
}

// TestReadState: every record carries a label the profile places → the least record under the profile's order,
// the spread disclosed when records differ; anything else → "" naming the record and why, with no partial order
// over unknown labels. Pure: a function of the bytes, the layout and the order only, so the answer repeats.
func TestReadState(t *testing.T) {
	l := mustLayout(t, layoutBytes("/data", "/settlementRunType"))
	for _, c := range []struct{ name, resp, state, spread, why string }{
		{"all RF (fractions and negatives elsewhere)", respAllRF, "RF", "", ""},
		{"all R1", respAllR1, "R1", "", ""},
		{"mixed R1, RF: the least record", respMixed, "R1", "records at R1..RF, read as R1", ""},
		{"mixed, least last in array order", `{"data":[{"settlementRunType":"DF"},{"settlementRunType":"RF"},{"settlementRunType":"R2"}]}`, "R2", "records at R2..DF, read as R2", ""},
		{"mixed, least in the middle", `{"data":[{"settlementRunType":"RF"},{"settlementRunType":"SF"},{"settlementRunType":"RF"}]}`, "SF", "records at SF..RF, read as SF", ""},
		{"field missing", respMissing, "", "", `record 1: state pointer "/settlementRunType": no member "settlementRunType"`},
		{"not JSON", respCSV, "", "", "the response is not I-JSON"},
		{"duplicate key", `{"data":[{"settlementRunType":"RF","settlementRunType":"R1"}]}`, "", "", "duplicate key"},
		{"value not a string", `{"data":[{"settlementRunType":3}]}`, "", "", "names a number, not a string"},
		{"value not a string beside placed labels", `{"data":[{"settlementRunType":"R1"},{"settlementRunType":null}]}`, "", "", "record 1: state pointer \"/settlementRunType\" names a null, not a string"},
		{"empty string", `{"data":[{"settlementRunType":""}]}`, "", "", "names an empty string"},
		{"empty string beside placed labels", `{"data":[{"settlementRunType":"RF"},{"settlementRunType":""}]}`, "", "", "record 1: state pointer \"/settlementRunType\" names an empty string"},
		{"one label outside the profile", `{"data":[{"settlementRunType":"R1"},{"settlementRunType":"II"},{"settlementRunType":"RF"}]}`, "", "",
			`record 1 reads "II", which is not in the source profile's labels: not comparable`},
		{"every label outside the profile", `{"data":[{"settlementRunType":"II"},{"settlementRunType":"II"}]}`, "", "", `record 0 reads "II", which is not in`},
		{"records not an array", `{"data":{"settlementRunType":"RF"}}`, "", "", "names a object, not an array"},
		{"records missing", `{"rows":[]}`, "", "", `records pointer "/data": no member "data"`},
		{"no records", `{"data":[]}`, "", "", "the record array is empty"},
		{"record not an object", `{"data":["RF"]}`, "", "", "steps into a string"},
	} {
		for i := 0; i < 2; i++ {
			r := ReadState([]byte(c.resp), l, settlementRank, 0)
			if r.State != c.state || r.Spread() != c.spread || !strings.Contains(r.Why, c.why) || (c.why == "") != (r.Why == "") {
				t.Errorf("%s: %q, %q, %q; want %q, %q, %q", c.name, r.State, r.Spread(), r.Why, c.state, c.spread, c.why)
			}
		}
	}
	// the order is the profile's, passed in: the same bytes under the reverse order read at the other end, and
	// with no order nothing is read
	rev := func(s string) (int, bool) { r, ok := settlementRank(s); return -r, ok }
	if r := ReadState([]byte(respMixed), l, rev, 0); r.State != "RF" || r.Spread() != "records at RF..R1, read as RF" {
		t.Errorf("reverse order: %+v", r)
	}
	if r := ReadState([]byte(respAllRF), l, nil, 0); r.State != "" || !strings.Contains(r.Why, "no source profile order") {
		t.Errorf("no order: %+v", r)
	}
	// a single-position layout reads one pointer into the response
	one := mustLayout(t, canon.Encode(obj("layout", ResponseLayoutTag, "state", "/meta/run")))
	if r := ReadState([]byte(`{"meta":{"run":"SF"},"data":[1.5]}`), one, settlementRank, 0); r.State != "SF" || r.Why != "" || r.Spread() != "" {
		t.Errorf("single position: %+v", r)
	}
	if r := ReadState([]byte(`{"meta":{"run":"II"}}`), one, settlementRank, 0); r.State != "" || !strings.Contains(r.Why, `the response reads "II", which is not in`) {
		t.Errorf("single position, label outside the profile: %+v", r)
	}
	// an index pointer into an array, and the escaped form
	idx := mustLayout(t, layoutBytes("/a~1b", "/0"))
	if r := ReadState([]byte(`{"a/b":[["RF",1],["RF",2]]}`), idx, settlementRank, 0); r.State != "RF" || r.Why != "" {
		t.Errorf("index pointer: %+v", r)
	}
	if r := ReadState([]byte(`{"a/b":[["RF"],[]]}`), idx, settlementRank, 0); !strings.Contains(r.Why, "past the end") {
		t.Errorf("index past the end: %+v", r)
	}
}

// Root-array fixtures: a streaming endpoint answers with a bare JSON array of records (synthetic, not real data).
const (
	respRootMixed = `[{"settlementPeriod":1,"settlementRunType":"RF","quantity":1.5},{"settlementPeriod":2,"settlementRunType":"R2","quantity":-2}]`
	respRootAllRF = `[{"settlementPeriod":1,"settlementRunType":"RF"},{"settlementPeriod":2,"settlementRunType":"RF"}]`
)

// TestReadStateRootArray: `records` "" is the RFC 6901 pointer to the whole response, so a bare JSON array at the
// root is the record array. It is distinct from `records` absent (one state, read with `state` from the root): the
// same bare array under the absent form steps into an array with a member name and is unchecked.
func TestReadStateRootArray(t *testing.T) {
	root := mustLayout(t, layoutBytes("", "/settlementRunType"))
	if !root.HasRecords || root.Records != nil || root.RecordsText != "" {
		t.Fatalf("records \"\": %+v", root)
	}
	absent := mustLayout(t, canon.Encode(obj("layout", ResponseLayoutTag, "state", "/settlementRunType")))
	if absent.HasRecords {
		t.Fatalf("records absent read as present: %+v", absent)
	}
	if root.Digest == absent.Digest {
		t.Fatal("the two forms share a digest")
	}
	for _, c := range []struct {
		name          string
		l             *ResponseLayout
		resp          string
		state, spread string
		why           string
	}{
		{"root array, all RF", root, respRootAllRF, "RF", "", ""},
		{"root array, mixed: least", root, respRootMixed, "R2", "records at R2..RF, read as R2", ""},
		{"root array, empty", root, `[]`, "", "", "the record array is empty"},
		{"root is an object", root, respAllRF, "", "", `records pointer "" names a object, not an array`},
		{"records absent over a root array", absent, respRootAllRF, "", "", `the response: state pointer "/settlementRunType": reference token 0 "settlementRunType" is not an array index`},
	} {
		r := ReadState([]byte(c.resp), c.l, settlementRank, 0)
		if r.State != c.state || r.Spread() != c.spread || !strings.Contains(r.Why, c.why) || (c.why == "") != (r.Why == "") {
			t.Errorf("%s: %+v; want %q %q %q", c.name, r, c.state, c.spread, c.why)
		}
	}
}

// TestReadStateLimits: the step budget and the size cap bind (each read unchecked naming the limit); the control
// with the default budget reads the same bytes.
func TestReadStateLimits(t *testing.T) {
	l := mustLayout(t, layoutBytes("/data", "/settlementRunType"))
	var b strings.Builder
	b.WriteString(`{"data":[`)
	for i := 0; i < 1000; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"settlementRunType":"RF"}`)
	}
	b.WriteString(`]}`)
	if r := ReadState([]byte(b.String()), l, settlementRank, 500); r.State != "" || r.Why != LayoutStepLimit {
		t.Fatalf("budget 500: %+v", r)
	}
	if r := ReadState([]byte(b.String()), l, settlementRank, 0); r.State != "RF" || r.Why != "" {
		t.Fatalf("control (default budget): %+v", r)
	}
	big := make([]byte, MaxResponseBytes+1)
	if r := ReadState(big, l, settlementRank, 0); !strings.Contains(r.Why, "larger than") {
		t.Fatalf("size cap: %+v", r)
	}
}

// layoutWorld is a reader holding profile P (SF < R1 < R2 < RF < DF) citing layout L in its documents, response
// bytes resp under dig("resp:"+endpoint), and one source observation `run >= RF` citing P at asserted state.
type layoutWorld struct {
	w     *world
	id    string
	p     *SourceProfile
	l     *ResponseLayout
	blobs map[string][]byte
}

func newLayoutWorld(t *testing.T, asserted, resp string, layout []byte, kv ...any) *layoutWorld {
	t.Helper()
	lw := &layoutWorld{w: newWorld(t), blobs: map[string][]byte{}}
	if layout != nil {
		lw.l = mustLayout(t, layout)
		lw.blobs[lw.l.Digest] = layout
	}
	docs := []string{timetable}
	if lw.l != nil {
		docs = append(docs, lw.l.Digest)
	}
	lw.p = mustProfile(t, canon.Encode(obj("profile", SourceProfileTag, "source", "https://api.example/settlement", "dialect", DialectOrderedLabel,
		"labels", []string{"SF", "R1", "R2", "RF", "DF"}, "documents", docs)))
	lw.p.AttachLayouts(func(d string) ([]byte, error) { return lw.blobs[d], nil })
	ref := apiRef("https://api.example/settlement")
	if resp != "" {
		lw.blobs[str(ref, "response_digest")] = []byte(resp)
	}
	body := []any{"content", canon.Value(contentOf("S1")), "class", "source", "referent", canon.Value(ref),
		"capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted")), "finality", canon.Value(profileRun(lw.p.Digest, asserted))}
	for i := 0; i < len(kv); i += 2 { // kv replaces a body member (content with a media type)
		for j := 0; j < len(body); j += 2 {
			if body[j] == kv[i] {
				body[j+1] = kv[i+1]
			}
		}
	}
	lw.id = lw.w.sign("O1", "A", "observed", obj(body...))
	return lw
}

func (lw *layoutWorld) rules() ProfileRules {
	return NewProfileRules(lw.p).WithBytes(func(d string, max int64) ([]byte, string) {
		b, ok := lw.blobs[d]
		if !ok {
			return nil, "not held"
		}
		return b, ""
	}, 0)
}

// TestObservationResponseLayout: the observation view under a profile that cites a response layout (claims-model
// note §5.3.1a, "Response layouts"). (a) every record carries a label in the profile: the least record's state,
// read from the held bytes, governs, the referent reads `final (as held)` or provisional at the read state, records
// that differ are disclosed as a spread, and an asserted state that differs from the read one is shown beside it as
// a disclosed disagreement; (b) a record's label is outside the profile, the field is missing, the bytes are not
// JSON or not held: the layout read is unchecked naming why and the asserted state reads exactly as without a
// layout (`final (as captured, not re-checked)` at best, never upgraded); (c) no layout: alpha behaviour, unchanged.
func TestObservationResponseLayout(t *testing.T) {
	conformance.Covers(t, "C-core-104g")
	lay := layoutBytes("/data", "/settlementRunType")
	for _, c := range []struct {
		name, asserted, resp string
		layout               []byte
		kv                   []any
		ref, layoutLine      string
		noLayout             bool
	}{
		{"(a) agree RF, asserted RF", "RF", respAllRF, lay, nil, RefFinalHeld, "state RF read from the held response", false},
		{"(a) agree RF, asserted R1 (disclosed)", "R1", respAllRF, lay, nil, RefFinalHeld, "the observer asserted R1 at capture (disclosed, does not govern)", false},
		{"(a) agree R1, asserted RF (disclosed, not final)", "RF", respAllR1, lay, nil, "provisional (R1; final at RF)", "the observer asserted RF at capture (disclosed, does not govern)", false},
		{"(a) mixed R1, RF, asserted RF: the least record", "RF", respMixed, lay, nil, "provisional (R1; final at RF)",
			"state R1 read from the held response (records at R1..RF, read as R1); the observer asserted RF at capture (disclosed, does not govern)", false},
		{"(a) mixed R1, RF, asserted R1: agrees with the least", "R1", respMixed, lay, nil, "provisional (R1; final at RF)",
			"state R1 read from the held response (records at R1..RF, read as R1)", false},
		{"(a) mixed RF, DF, asserted RF: final as held at the least", "RF", `{"data":[{"settlementRunType":"DF"},{"settlementRunType":"RF"}]}`, lay, nil, RefFinalHeld,
			"state RF read from the held response (records at RF..DF, read as RF)", false},
		{"(a) mixed RF, DF, asserted DF: disclosed against the least", "DF", `{"data":[{"settlementRunType":"DF"},{"settlementRunType":"RF"}]}`, lay, nil, RefFinalHeld,
			"(records at RF..DF, read as RF); the observer asserted DF at capture (disclosed, does not govern)", false},
		{"(b) one record outside the profile", "RF", respOneUnknown, lay, nil, RefFinalCaptured, `unchecked (record 1 reads "II", which is not in the source profile's labels`, false},
		{"(b) one record outside the profile, asserted R1 not upgraded", "R1", respOneUnknown, lay, nil, "provisional (R1; final at RF)", `unchecked (record 1 reads "II"`, false},
		{"(b) field missing", "RF", respMissing, lay, nil, RefFinalCaptured, `unchecked (record 1: state pointer "/settlementRunType": no member`, false},
		{"(b) not JSON", "RF", respCSV, lay, nil, RefFinalCaptured, "unchecked (the response is not I-JSON", false},
		{"(b) declared non-JSON media type", "RF", respAllRF, lay, []any{"content", canon.Value(obj("digest", dig("S1"), "size", 2, "media_type", "text/csv"))},
			RefFinalCaptured, `unchecked (the capture's media type "text/csv" is not JSON`, false},
		{"(b) response not held", "RF", "", lay, nil, RefFinalCaptured, "not held)", false},
		{"(b) label outside the profile", "RF", `{"data":[{"settlementRunType":"II"}]}`, lay, nil, RefFinalCaptured, `record 0 reads "II", which is not in the source profile's labels`, false},
		{"(a) root array (records \"\"), mixed", "RF", respRootMixed, layoutBytes("", "/settlementRunType"), nil, "provisional (R2; final at RF)",
			"state R2 read from the held response (records at R2..RF, read as R2)", false},
		{"(c) no layout (control)", "RF", respAllR1, nil, nil, RefFinalCaptured, "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			lw := newLayoutWorld(t, c.asserted, c.resp, c.layout, c.kv...)
			o := obsView(t, lw.w, lw.id, WithFinalityRules(lw.rules()))
			wantRef(t, o, c.ref)
			if c.noLayout {
				if o.Layout != nil || strings.Contains(o.Render(), "response layout") {
					t.Fatalf("control: a layout read appeared\n%s", o.Render())
				}
			} else {
				if o.Layout == nil {
					t.Fatalf("no layout read\n%s", o.Render())
				}
				has(t, o.Layout.String(), c.layoutLine)
				has(t, o.Render(), "response layout")
			}
			if code, why := o.VerifyExit(); code != 0 {
				t.Fatalf("verify %d %v: a layout read is a disclosure, never an exit", code, why)
			}
		})
	}
	// never upgraded: an unchecked read leaves the referent exactly as the same profile without a layout reads it
	for _, asserted := range []string{"RF", "R1", "DF"} {
		with := newLayoutWorld(t, asserted, respOneUnknown, lay)
		without := newLayoutWorld(t, asserted, respOneUnknown, nil)
		a := obsView(t, with.w, with.id, WithFinalityRules(with.rules())).ReferentStatus
		b := obsView(t, without.w, without.id, WithFinalityRules(without.rules())).ReferentStatus
		if a != b {
			t.Fatalf("asserted %s: unchecked layout read gives %q, no layout gives %q", asserted, a, b)
		}
	}
}

// TestLayoutCitedUnusable: a cited document that claims to be a layout and is not one, or two layouts, leave the
// profile's layout unusable (named); a cited document that is not held or is not a layout at all is an ordinary
// document (no layout read, alpha behaviour).
func TestLayoutCitedUnusable(t *testing.T) {
	bad := canon.Encode(obj("layout", ResponseLayoutTag, "state", "no-slash"))
	l2 := layoutBytes("/data", "/run")
	for _, c := range []struct {
		name string
		docs map[string][]byte
		why  string
	}{
		{"invalid layout", map[string][]byte{dig(string(bad)): bad}, "is not a rc-response-layout/1 layout: state is not an RFC 6901"},
		{"two layouts", map[string][]byte{dig(string(layoutBytes("/data", "/settlementRunType"))): layoutBytes("/data", "/settlementRunType"), dig(string(l2)): l2},
			"cites 2 response layouts; none is picked"},
		{"held corrupt (the getter returns the held bytes)", map[string][]byte{dig(string(layoutBytes("/data", "/settlementRunType"))): layoutBytes("/data", "/other")},
			"is held corrupt (its bytes hash elsewhere), so whether it is the profile's rc-response-layout/1 layout cannot be read"},
		{"held corrupt beside a valid layout", map[string][]byte{dig(string(l2)): l2, dig("a document"): []byte("other bytes")}, "is held corrupt"},
		{"not held", map[string][]byte{dig("absent"): nil}, ""},
		{"not a layout", map[string][]byte{dig(`{"a":1}`): []byte(`{"a":1}`)}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			var docs []string
			for d := range c.docs {
				docs = append(docs, d)
			}
			p := mustProfile(t, canon.Encode(obj("profile", SourceProfileTag, "source", "s", "dialect", DialectOrderedLabel, "labels", []string{"R1", "RF"},
				"documents", sortedStrings(docs))))
			p.AttachLayouts(func(d string) ([]byte, error) { return c.docs[d], nil })
			b := NewProfileRules(p).For(p.Digest)
			lr := b.readLayout("run >= RF", obj("class", "source", "referent", obj("response_digest", dig("r"))), State{Run: "RF"})
			if c.why == "" {
				if lr != nil || p.HasLayout() {
					t.Fatalf("an ordinary document read as a layout: %v", lr)
				}
				return
			}
			if lr == nil || lr.State != "" || !strings.Contains(lr.Why, c.why) {
				t.Fatalf("got %+v, want unchecked %q", lr, c.why)
			}
		})
	}
}

// TestLayoutHeldCorruptNamed: a getter that checks the hash itself (a store) reports a corrupt held copy as
// ErrHeldCorrupt; the layout is then unusable naming that document, where before it was skipped silently. Control:
// the same getter reporting the document not held leaves the profile with no layout.
func TestLayoutHeldCorruptNamed(t *testing.T) {
	lb := layoutBytes("/data", "/settlementRunType")
	ld := dig(string(lb))
	for _, corrupt := range []bool{true, false} {
		p := mustProfile(t, canon.Encode(obj("profile", SourceProfileTag, "source", "s", "dialect", DialectOrderedLabel, "labels", []string{"R1", "RF"},
			"documents", []string{ld})))
		p.AttachLayouts(func(d string) ([]byte, error) {
			if corrupt {
				return nil, ErrHeldCorrupt
			}
			return nil, nil
		})
		lr := NewProfileRules(p).For(p.Digest).readLayout("run >= RF", obj("class", "source", "referent", obj("response_digest", dig("r"))), State{Run: "RF"})
		if !corrupt {
			if lr != nil || p.HasLayout() {
				t.Fatalf("not held read as a layout: %+v", lr)
			}
			continue
		}
		if lr == nil || lr.State != "" || !strings.Contains(lr.Why, "document "+keylog.Short(ld)+" is held corrupt") {
			t.Fatalf("corrupt: %+v", lr)
		}
	}
}

// TestLayoutLeastNeverUpgrades: seeded property. For any response whose records all carry labels in the profile,
// the read state meets `run >= L` exactly when every record does (the rule is monotone, so the least record is the
// one state the whole response can be relied on at), the read state is one of the records' labels, the spread is
// disclosed exactly when records differ, and the read does not depend on the records' order.
func TestLayoutLeastNeverUpgrades(t *testing.T) {
	l := mustLayout(t, layoutBytes("/data", "/settlementRunType"))
	labels := []string{"SF", "R1", "R2", "RF", "DF"}
	rng := uint64(0x5eed1113)
	next := func(n int) int {
		rng ^= rng << 13
		rng ^= rng >> 7
		rng ^= rng << 17
		return int(rng % uint64(n))
	}
	build := func(rs []string) []byte {
		var b strings.Builder
		b.WriteString(`{"data":[`)
		for i, r := range rs {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`{"settlementRunType":"` + r + `"}`)
		}
		b.WriteString(`]}`)
		return []byte(b.String())
	}
	for iter := 0; iter < 2000; iter++ {
		rs := make([]string, 1+next(8))
		for i := range rs {
			rs[i] = labels[next(len(labels))]
		}
		r := ReadState(build(rs), l, settlementRank, 0)
		if r.Why != "" {
			t.Fatalf("%v: %q", rs, r.Why)
		}
		ri, _ := settlementRank(r.State)
		distinct := map[string]bool{}
		for _, x := range rs {
			distinct[x] = true
		}
		if !distinct[r.State] {
			t.Fatalf("%v: read %q is no record's label", rs, r.State)
		}
		for li, L := range labels {
			all := true
			for _, x := range rs {
				xi, _ := settlementRank(x)
				all = all && xi >= li
			}
			if (ri >= li) != all {
				t.Fatalf("%v: read %s meets run >= %s is %v, every record meets it is %v", rs, r.State, L, ri >= li, all)
			}
		}
		if (r.Spread() != "") != (len(distinct) > 1) {
			t.Fatalf("%v: spread %q", rs, r.Spread())
		}
		sh := append([]string(nil), rs...)
		for i := len(sh) - 1; i > 0; i-- {
			j := next(i + 1)
			sh[i], sh[j] = sh[j], sh[i]
		}
		if r2 := ReadState(build(sh), l, settlementRank, 0); r2 != r {
			t.Fatalf("%v vs %v: %+v vs %+v (order changed the read)", rs, sh, r, r2)
		}
		// one record outside the profile, anywhere, and nothing is read
		bad := append([]string(nil), rs...)
		k := next(len(bad))
		bad[k] = "XX"
		if r3 := ReadState(build(bad), l, settlementRank, 0); r3.State != "" || !strings.Contains(r3.Why, "record "+strconv.Itoa(k)+` reads "XX"`) {
			t.Fatalf("%v: %+v", bad, r3)
		}
	}
}

func sortedStrings(ss []string) []string {
	out := append([]string(nil), ss...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// TestLayoutRevisionAndComparison: the state read from the bytes is the state a revision and a finality-aware
// comparison use. Two captures of one referent, both asserting RF, with different bytes: by their asserted states
// the pair contradicts (both final, different bytes); read from the bytes (R1 then RF) the first was revised before
// finality, and the comparison is not a contradiction. Control: no layout, the asserted states decide as before.
func TestLayoutRevisionAndComparison(t *testing.T) {
	lay := layoutBytes("/data", "/settlementRunType")
	for _, withLayout := range []bool{true, false} {
		var l []byte
		if withLayout {
			l = lay
		}
		lw := newLayoutWorld(t, "RF", respAllR1, l)
		// a second capture of the same referent, other bytes, other response digest held as all-RF
		ref2 := obj("endpoint", "https://api.example/settlement", "parameters", obj("period", "2026-09"), "response_digest", dig("resp2"))
		lw.blobs[dig("resp2")] = []byte(respAllRF)
		lw.w.observed("B", "O2", "S2", "source", ref2, "finality", profileRun(lw.p.Digest, "RF"), "at", "2026-10-17T00:00:00Z")
		o := obsView(t, lw.w, lw.id, WithFinalityRules(lw.rules()))
		if withLayout {
			wantRef(t, o, RefRevised)
			hasNot(t, o.Render(), "contradicts")
		} else {
			wantRef(t, o, RefFinalCaptured)
		}
	}
}

// TestSeriesBoundaryAsHeld: the series boundary when every segment's state is read from its held response is `as
// held`; one segment whose read is unchecked (asserted state used) makes the boundary the weaker `as captured, not
// re-checked`. Control: no layout, `as captured, not re-checked` as before.
func TestSeriesBoundaryAsHeld(t *testing.T) {
	conformance.Covers(t, "C-core-104h")
	lay := mustLayout(t, layoutBytes("/data", "/settlementRunType"))
	mk := func(withLayout bool, resps map[string]string) *Series {
		docs := []string{timetable}
		if withLayout {
			docs = append(docs, lay.Digest)
		}
		p := mustProfile(t, canon.Encode(obj("profile", SourceProfileTag, "source", "https://api.example/settlement", "dialect", DialectOrderedLabel,
			"labels", []string{"SF", "R1", "R2", "RF", "DF"}, "documents", docs)))
		p.AttachLayouts(func(d string) ([]byte, error) {
			if d == lay.Digest {
				return layoutBytes("/data", "/settlementRunType"), nil
			}
			return nil, nil
		})
		rules := NewProfileRules(p).WithBytes(func(d string, max int64) ([]byte, string) {
			for k, v := range resps {
				if dig("resp:"+k) == d {
					return []byte(v), ""
				}
			}
			return nil, "not held"
		}, 0)
		w := newWorld(t)
		g := w.sign("G", "A", "genesis", obj("type", "series", "name", "settlements", "controllers", w.controllers("A"), "rule", obj("any_one", true)))
		var ids []string
		for i, seg := range []string{"jan", "feb", "mar"} {
			ref := obj("endpoint", "https://api.example/settlement", "parameters", obj("period", seg), "response_digest", dig("resp:"+seg),
				"window", obj("from", "2025-0"+string(rune('1'+i))+"-01T00:00:00Z", "to", "2025-0"+string(rune('2'+i))+"-01T00:00:00Z"))
			ids = append(ids, w.observedRef("S"+seg, "O", seg, "source", ref, "finality", profileRun(p.Digest, "RF")))
		}
		w.editionWith("E1", "A", g, []string{g}, "members", segs(ids...), "frozen_before", obj("date", "2025-03-01"))
		s, ok := w.store(nil, WithSegments(ProfileSegments{Rules: rules})).Series(g, "")
		if !ok {
			t.Fatal("series not found")
		}
		return s
	}
	all := map[string]string{"jan": respAllRF, "feb": respAllRF, "mar": respAllR1}
	s := mk(true, all)
	has(t, s.Line(), "members final to 2025-03-01 as held (1 segment provisional)")
	hasNot(t, s.Line(), BoundaryAsCaptured)
	// mixed: one segment's response is not held, so its asserted RF is used: the weaker label
	mixed := map[string]string{"jan": respAllRF, "mar": respAllR1}
	s = mk(true, mixed)
	has(t, s.Line(), "members final to 2025-03-01 as captured, not re-checked (1 segment provisional)")
	has(t, s.Render(), "(as held)")
	// control: no layout: every asserted RF is final
	s = mk(false, all)
	has(t, s.Line(), "as captured, not re-checked")
	hasNot(t, s.Line(), "provisional")
}
