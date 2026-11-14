package resolve

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/reqlog"
)

// Batch response layouts (claims-model note §5.3.1a, "a batch reads at its least response"). Fixtures are synthetic
// settlement-shaped responses, never real data.

// batchRun is one settlement-shaped response whose records carry the runs given ("" omits the field).
func batchRun(period int, runs ...string) []byte {
	var rs []string
	for i, r := range runs {
		if r == "" {
			rs = append(rs, `{"settlementPeriod":`+itoa(i+1)+`}`)
			continue
		}
		rs = append(rs, `{"settlementPeriod":`+itoa(i+1)+`,"settlementRunType":"`+r+`"}`)
	}
	return []byte(`{"period":` + itoa(period) + `,"data":[` + strings.Join(rs, ",") + `]}`)
}

func itoa(i int) string { return canonInt(i) }

func canonInt(i int) string { return string(canon.Encode(canon.Int(i))) }

// batchLayoutWorld is a reader holding profile P (SF < R1 < R2 < RF < DF) citing layout L, and one batch source
// observation `run >= RF` citing P at asserted state, whose content is an archive of the responses and their log.
type batchLayoutWorld struct {
	w     *world
	id    string
	f     *batchFixture
	p     *SourceProfile
	blobs map[string][]byte
}

func newBatchLayoutWorld(t *testing.T, asserted string, cite bool, responses ...[]byte) *batchLayoutWorld {
	t.Helper()
	bw := &batchLayoutWorld{w: newWorld(t), blobs: map[string][]byte{}}
	lay := layoutBytes("/data", "/settlementRunType")
	l := mustLayout(t, lay)
	bw.blobs[l.Digest] = lay
	docs := []string{timetable}
	if cite {
		docs = append(docs, l.Digest)
	}
	bw.p = mustProfile(t, canon.Encode(obj("profile", SourceProfileTag, "source", "https://api.example/settlement", "dialect", DialectOrderedLabel,
		"labels", []string{"SF", "R1", "R2", "RF", "DF"}, "documents", docs)))
	bw.p.AttachLayouts(func(d string) ([]byte, error) { return bw.blobs[d], nil })
	f := &batchFixture{content: dig("batch-archive")}
	var es []reqlog.Entry
	for i, r := range responses {
		f.responses = append(f.responses, r)
		es = append(es, reqlog.Entry{Endpoint: batchEP, Parameters: obj("period", itoa(i+1)), Status: 200,
			Time: "2026-10-16T05:00:0" + itoa(i) + "Z", ResponseDigest: sha(r)})
	}
	f.log = reqlog.Encode(es)
	bw.f = f
	bw.id = bw.w.sign("B", "O", "observed", obj("content", obj("digest", f.content, "size", 1), "class", "source",
		"referent", obj("requests", batchReq(f, len(responses), "endpoint", batchEP)),
		"capture", obj("at", "2026-10-16T05:01:00Z", "evidence", "self-asserted"), "finality", profileRun(bw.p.Digest, asserted)))
	return bw
}

func (bw *batchLayoutWorld) rules() ProfileRules {
	return NewProfileRules(bw.p).WithBytes(func(d string, max int64) ([]byte, string) {
		b, ok := bw.blobs[d]
		if !ok {
			return nil, "not held"
		}
		return b, ""
	}, 0)
}

func (bw *batchLayoutWorld) view(t *testing.T, content ContentReader, extra ...Option) *Observation {
	t.Helper()
	return obsView(t, bw.w, bw.id, append([]Option{WithFinalityRules(bw.rules()), WithObservedContent(content)}, extra...)...)
}

// TestBatchResponseLayout: C-core-104i in the resolver. A batch capture whose rule resolves through a profile citing a
// response layout reads at the least state over every logged response's least record, the spread across responses
// disclosed; one logged response not held (or not readable by the layout), or a request-log check that is not `ok`,
// makes the whole read unchecked, naming the first offending entry by index and endpoint and counting the rest, and
// the referent reads exactly as with no layout (never a partial read, never upgraded). A log `fail` stays exit 1.
func TestBatchResponseLayout(t *testing.T) {
	conformance.Partial(t, "C-core-104i", "resolver half; through the commands in the cli package")
	allRF := [][]byte{batchRun(1, "RF", "RF"), batchRun(2, "RF"), batchRun(3, "DF", "RF")}
	mixed := [][]byte{batchRun(1, "RF", "RF"), batchRun(2, "R2", "RF"), batchRun(3, "DF")}
	for _, c := range []struct {
		name, asserted string
		resps          [][]byte
		ref, line      string
	}{
		{"every response final: final as held at the least", "RF", allRF, RefFinalHeld,
			"state RF read from the 3 held responses (records at RF..DF across 3 responses, read as RF)"},
		{"mixed across responses: the least record of the least response", "RF", mixed, "provisional (R2; final at RF)",
			"state R2 read from the 3 held responses (records at R2..DF across 3 responses, read as R2); the observer asserted RF at capture (disclosed, does not govern)"},
		{"one label everywhere: no spread", "RF", [][]byte{batchRun(1, "RF"), batchRun(2, "RF")}, RefFinalHeld,
			"state RF read from the 2 held responses"},
	} {
		t.Run(c.name, func(t *testing.T) {
			bw := newBatchLayoutWorld(t, c.asserted, true, c.resps...)
			o := bw.view(t, bw.f.reader())
			if o.RequestLog == nil || o.RequestLog.Outcome != RequestLogOK {
				t.Fatalf("request log: %+v", o.RequestLog)
			}
			wantRef(t, o, c.ref)
			if o.Layout == nil {
				t.Fatalf("no layout read\n%s", o.Render())
			}
			has(t, o.Layout.String(), c.line)
			if c.name == "one label everywhere: no spread" && strings.Contains(o.Layout.String(), "records at") {
				t.Fatalf("spread shown for one label: %s", o.Layout)
			}
			if code, why := o.VerifyExit(); code != 0 {
				t.Fatalf("verify %d %v: a layout read never moves an exit", code, why)
			}
		})
	}
	// the read does not depend on the order of the responses in the log: the least is the least
	rev := [][]byte{mixed[2], mixed[1], mixed[0]}
	bw := newBatchLayoutWorld(t, "RF", true, rev...)
	if o := bw.view(t, bw.f.reader()); o.ReferentStatus != "provisional (R2; final at RF)" || o.Layout.Spread != "records at R2..DF across 3 responses, read as R2" {
		t.Fatalf("reordered: %s %+v", o.ReferentStatus, o.Layout)
	}

	// any gap is unchecked: the asserted state reads exactly as with no layout cited (never a partial read)
	control := func(t *testing.T, asserted string, resps [][]byte, content func(*batchFixture) ContentReader) string {
		bw := newBatchLayoutWorld(t, asserted, false, resps...)
		o := bw.view(t, content(bw.f))
		if o.Layout != nil {
			t.Fatalf("control has a layout read: %s", o.Layout)
		}
		return o.ReferentStatus
	}
	// (1) one response not held in the content (the archive lost it): log fail, exit 1, layout unchecked naming it
	drop := func(i int) func(*batchFixture) ContentReader {
		return func(f *batchFixture) ContentReader {
			us := f.units()
			return tableContent{f.content: append(us[:1+i:1+i], us[2+i:]...)}
		}
	}
	bw = newBatchLayoutWorld(t, "RF", true, mixed...)
	o := bw.view(t, drop(1)(bw.f))
	if o.RequestLog.Outcome != RequestLogFail || o.Layout == nil || o.Layout.State != "" {
		t.Fatalf("unheld: %+v %+v", o.RequestLog, o.Layout)
	}
	has(t, o.Layout.String(), "unchecked (request log fail (entry 2, endpoint "+batchEP+": response")
	has(t, o.Layout.String(), "no response is read")
	if want := control(t, "RF", mixed, drop(1)); o.ReferentStatus != want || want != RefFinalCaptured {
		t.Fatalf("unheld: referent %q, no-layout control %q", o.ReferentStatus, want)
	}
	if code, why := o.VerifyExit(); code != 1 || !strings.Contains(strings.Join(why, ";"), "entry 2") {
		t.Fatalf("unheld: verify %d %v (a log fail stays exit 1)", code, why)
	}
	// (2) a response the layout cannot read (a record outside the profile, then a record without the field): the
	// log is ok, the read unchecked naming the first entry and counting the rest; asserted R1 is not upgraded
	bad := [][]byte{batchRun(1, "RF"), batchRun(2, "RF", "II"), batchRun(3, "RF", "")}
	for _, asserted := range []string{"RF", "R1"} {
		bw = newBatchLayoutWorld(t, asserted, true, bad...)
		o = bw.view(t, bw.f.reader())
		if o.RequestLog.Outcome != RequestLogOK || o.Layout == nil || o.Layout.State != "" {
			t.Fatalf("unreadable: %+v %+v", o.RequestLog, o.Layout)
		}
		has(t, o.Layout.String(), `unchecked (entry 2, endpoint `+batchEP+`: response `)
		has(t, o.Layout.String(), `unreadable: record 1 reads "II", which is not in the source profile's labels`)
		has(t, o.Layout.String(), "; 1 more of the 3 responses not read)")
		if want := control(t, asserted, bad, func(f *batchFixture) ContentReader { return f.reader() }); o.ReferentStatus != want {
			t.Fatalf("unreadable asserted %s: referent %q, control %q", asserted, o.ReferentStatus, want)
		}
		if code, why := o.VerifyExit(); code != 0 {
			t.Fatalf("unreadable: verify %d %v", code, why)
		}
	}
	// (3) content not held: the log is unchecked (exit 3), so is the read
	bw = newBatchLayoutWorld(t, "RF", true, mixed...)
	o = bw.view(t, tableContent{})
	if o.RequestLog.Outcome != RequestLogUnchecked || o.Layout == nil || o.Layout.State != "" || o.ReferentStatus != RefFinalCaptured {
		t.Fatalf("no content: %+v %+v %s", o.RequestLog, o.Layout, o.ReferentStatus)
	}
	has(t, o.Layout.String(), "unchecked (request log unchecked (content not held): no response is read)")
	if code, _ := o.VerifyExit(); code != 3 {
		t.Fatalf("no content: verify %d", code)
	}
}

// TestBatchResponseLayoutWholeContent: the log is the whole content (no archive): each logged response is read from
// the blobs the reader holds; one the reader does not hold leaves the log unchecked, and so the read.
func TestBatchResponseLayoutWholeContent(t *testing.T) {
	conformance.Partial(t, "C-core-104i", "resolver half, the log as the whole content")
	resps := [][]byte{batchRun(1, "RF"), batchRun(2, "R1", "RF")}
	bw := newBatchLayoutWorld(t, "RF", true, resps...)
	// a fresh reader, the log as the content
	bw.w = newWorld(t)
	bw.f.content = sha(bw.f.log)
	bw.id = bw.w.sign("W", "O", "observed", obj("content", obj("digest", bw.f.content, "size", 1), "class", "source",
		"referent", obj("requests", batchReq(bw.f, 2)),
		"capture", obj("at", "2026-10-16T05:01:00Z", "evidence", "self-asserted"), "finality", profileRun(bw.p.Digest, "RF")))
	whole := tableContent{bw.f.content: {{Name: "log", Data: bw.f.log}}}
	for _, r := range resps {
		bw.blobs[sha(r)] = r
	}
	held := heldSet{sha(resps[0]): true, sha(resps[1]): true}
	o := bw.view(t, whole, WithBlobIndex(held))
	if o.RequestLog.Outcome != RequestLogOK || o.ReferentStatus != "provisional (R1; final at RF)" {
		t.Fatalf("held: %+v %s\n%s", o.RequestLog, o.ReferentStatus, o.Render())
	}
	has(t, o.Layout.String(), "state R1 read from the 2 held responses (records at R1..RF across 2 responses, read as R1)")
	o = bw.view(t, whole, WithBlobIndex(heldSet{sha(resps[0]): true}))
	if o.RequestLog.Outcome != RequestLogUnchecked || o.Layout.State != "" || o.ReferentStatus != RefFinalCaptured {
		t.Fatalf("one not held: %+v %+v %s", o.RequestLog, o.Layout, o.ReferentStatus)
	}
}

// TestBatchLayoutCacheKey: the batch read is cached on the profile, the layout and the ordered list of response
// digests, so a capture whose one response differs reads afresh (the cache never serves another batch's read).
func TestBatchLayoutCacheKey(t *testing.T) {
	conformance.Partial(t, "C-core-104i", "the batch read's cache key")
	a := newBatchLayoutWorld(t, "RF", true, batchRun(1, "RF"), batchRun(2, "RF"))
	rules := a.rules()
	o := obsView(t, a.w, a.id, WithFinalityRules(rules), WithObservedContent(a.f.reader()))
	wantRef(t, o, RefFinalHeld)
	// a second batch, same profile and layout, one response changed to R1, read through the SAME rules (one cache)
	b := newBatchLayoutWorld(t, "RF", true, batchRun(1, "RF"), batchRun(2, "R1"))
	b.p = a.p
	b.id = b.w.sign("B", "O", "observed", obj("content", obj("digest", b.f.content, "size", 1), "class", "source",
		"referent", obj("requests", batchReq(b.f, 2, "endpoint", batchEP)),
		"capture", obj("at", "2026-10-16T05:01:00Z", "evidence", "self-asserted"), "finality", profileRun(a.p.Digest, "RF")))
	o = obsView(t, b.w, b.id, WithFinalityRules(rules), WithObservedContent(b.f.reader()))
	wantRef(t, o, "provisional (R1; final at RF)")
	has(t, o.Layout.String(), "records at R1..RF across 2 responses, read as R1")
	// and back: the first batch still reads from its own entry
	o = obsView(t, a.w, a.id, WithFinalityRules(rules), WithObservedContent(a.f.reader()))
	wantRef(t, o, RefFinalHeld)
	if k1, k2 := batchKey([]loggedResponse{{Digest: "a"}, {Digest: "b"}}), batchKey([]loggedResponse{{Digest: "b"}, {Digest: "a"}}); k1 == k2 {
		t.Fatal("the cache key ignores the responses' order")
	}
}
