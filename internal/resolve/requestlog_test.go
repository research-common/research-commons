package resolve

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/reqlog"
)

const batchEP = "https://api.example/v1/settlements"

// batchFixture is a capture of n requests: an archive-like content of n response units plus the log unit. mut
// changes the units after the log is written (the mutation under test).
type batchFixture struct {
	responses [][]byte
	log       []byte
	content   string // the content digest the statement names
}

func newBatch(n int) *batchFixture {
	f := &batchFixture{content: dig("batch-archive")}
	var es []reqlog.Entry
	for i := 0; i < n; i++ {
		resp := []byte(`{"period":"2026-0` + string(rune('1'+i)) + `"}`)
		f.responses = append(f.responses, resp)
		es = append(es, reqlog.Entry{Endpoint: batchEP, Parameters: obj("period", "2026-0"+string(rune('1'+i))), Status: 200,
			Time: "2026-10-16T05:00:0" + string(rune('0'+i)) + "Z", ResponseDigest: sha(resp)})
	}
	f.log = reqlog.Encode(es)
	return f
}


func (f *batchFixture) units() []ContentUnit {
	us := []ContentUnit{{Name: "capture.tar!/requests.jsonl", Data: f.log}}
	for i, r := range f.responses {
		us = append(us, ContentUnit{Name: "capture.tar!/r" + string(rune('1'+i)) + ".json", Data: r})
	}
	return us
}

func (f *batchFixture) reader() tableContent { return tableContent{f.content: f.units()} }

func (w *world) batchObserved(name, n string, f *batchFixture, req *canon.Object) string {
	return w.sign(name, n, "observed", obj("content", obj("digest", f.content, "size", 1), "class", "source",
		"referent", obj("requests", req), "capture", obj("at", "2026-10-16T05:01:00Z", "evidence", "self-asserted")))
}

func batchReq(f *batchFixture, count int, kv ...any) *canon.Object {
	return obj(append([]any{"digest", sha(f.log), "format", reqlog.Format, "count", count}, kv...)...)
}

// TestBatchRequestLog: C-core-31, the batch variant. The log is located by its digest inside the content, its
// count is checked, a request whose response bytes were mutated after logging is named by entry and endpoint,
// and a referent whose log digest matches nothing in the content reads `unpinned`. Controls: the intact capture
// is `ok` (exit 0), and the same mutation without the log check (content not held) is `unchecked`, so the
// content reader is what decides.
func TestBatchRequestLog(t *testing.T) {
	conformance.Partial(t, "C-core-31", "batch variant in the resolver; through the commands in the cli package")
	// intact: ok, every response held, exit 0
	f := newBatch(3)
	w := newWorld(t)
	id := w.batchObserved("B", "O", f, batchReq(f, 3, "endpoint", batchEP))
	o := obsView(t, w, id, WithObservedContent(f.reader()))
	if l := o.RequestLog; l == nil || l.Outcome != RequestLogOK || l.Held != 3 || l.Entries != 3 || l.Unit != "capture.tar!/requests.jsonl" {
		t.Fatalf("intact: %+v\n%s", l, o.Render())
	}
	if code, why := o.VerifyExit(); code != 0 {
		t.Fatalf("intact exit %d %v", code, why)
	}
	has(t, o.Render(), "responses held 3/3")
	// one response mutated after logging: named by index and endpoint, checked and wrong (exit 1)
	m := newBatch(3)
	m.responses[1] = []byte(`{"period":"2026-02","tampered":true}`)
	w2 := newWorld(t)
	id2 := w2.batchObserved("B", "O", m, batchReq(m, 3))
	o2 := obsView(t, w2, id2, WithObservedContent(m.reader()))
	l := o2.RequestLog
	if l == nil || l.Outcome != RequestLogFail || l.Held != 2 || len(l.Problems) != 1 || !strings.HasPrefix(l.Problems[0], "entry 2, endpoint "+batchEP+": response") {
		t.Fatalf("mutated: %+v", l)
	}
	if code, why := o2.VerifyExit(); code != 1 || !strings.Contains(strings.Join(why, ";"), "entry 2") {
		t.Fatalf("mutated exit %d %v", code, why)
	}
	// the mutation reached the boundary: without content the same statement is unchecked, not fail
	o2n := obsView(t, w2, id2)
	if o2n.RequestLog.Outcome != RequestLogUnchecked || o2n.RequestLog.Why != "content not held" {
		t.Fatalf("no content: %+v", o2n.RequestLog)
	}
	if code, _ := o2n.VerifyExit(); code != 3 {
		t.Fatalf("no content exit %d", code)
	}
	// count pinned wrong: named
	w3 := newWorld(t)
	id3 := w3.batchObserved("B", "O", f, batchReq(f, 4))
	o3 := obsView(t, w3, id3, WithObservedContent(f.reader()))
	if o3.RequestLog.Outcome != RequestLogFail || !slices.Contains(o3.RequestLog.Problems, "count 4 pinned, the log lists 3") {
		t.Fatalf("count: %+v", o3.RequestLog)
	}
	// endpoint pinned for every request but one entry differs
	e := newBatch(2)
	es, _ := reqlog.Parse(e.log)
	es[1].Endpoint = "https://api.example/v1/other"
	e.log = reqlog.Encode(es)
	w4 := newWorld(t)
	id4 := w4.batchObserved("B", "O", e, batchReq(e, 2, "endpoint", batchEP))
	o4 := obsView(t, w4, id4, WithObservedContent(e.reader()))
	if o4.RequestLog.Outcome != RequestLogFail || !strings.Contains(strings.Join(o4.RequestLog.Problems, ";"), "entry 2: endpoint") {
		t.Fatalf("endpoint: %+v", o4.RequestLog)
	}
	// log digest matching nothing in the content: unpinned (exit 3), no agreement model
	w5 := newWorld(t)
	id5 := w5.batchObserved("B", "O", f, obj("digest", dig("another log"), "format", reqlog.Format, "count", 3))
	o5 := obsView(t, w5, id5, WithObservedContent(f.reader()))
	if o5.ReferentStatus != RefUnpinned || !slices.Contains(o5.Unpinned, "referent.requests.digest") || o5.RequestLog.Outcome != RequestLogUnpinned {
		t.Fatalf("unmatched: %s %v %+v", o5.ReferentStatus, o5.Unpinned, o5.RequestLog)
	}
	if code, _ := o5.VerifyExit(); code != 3 {
		t.Fatalf("unmatched exit %d", code)
	}
	has(t, o5.Render(), "matches nothing in the content")
	// ...but with a unit the scanner could not read, the log may be there: unchecked, never unpinned
	us := append(f.units()[1:], ContentUnit{Name: "capture.tar!/big.bin", Unscanned: "member_bytes=1"})
	o6 := obsView(t, w5, id5, WithObservedContent(tableContent{f.content: us}))
	if o6.RequestLog.Outcome != RequestLogUnchecked || o6.ReferentStatus == RefUnpinned {
		t.Fatalf("unscanned: %+v %s", o6.RequestLog, o6.ReferentStatus)
	}
	// a format this reader does not read: unchecked, naming it
	w7 := newWorld(t)
	id7 := w7.batchObserved("B", "O", f, obj("digest", sha(f.log), "format", "har-1.2", "count", 3))
	o7 := obsView(t, w7, id7, WithObservedContent(f.reader()))
	if o7.RequestLog.Outcome != RequestLogUnchecked || !strings.Contains(o7.RequestLog.Why, `"har-1.2"`) {
		t.Fatalf("format: %+v", o7.RequestLog)
	}
	// the edition-rule content reader serves the check too
	if o8 := obsView(t, w, id, WithContent(f.reader())); o8.RequestLog.Outcome != RequestLogOK {
		t.Fatalf("WithContent: %+v", o8.RequestLog)
	}
}

// TestBatchRequestLogWholeContent: the log is the whole content blob (no archive): responses are looked up among
// the blobs the reader holds; one not held is unchecked, never wrong.
func TestBatchRequestLogWholeContent(t *testing.T) {
	f := newBatch(2)
	f.content = sha(f.log)
	w := newWorld(t)
	id := w.batchObserved("B", "O", f, batchReq(f, 2))
	whole := tableContent{f.content: {{Name: "log", Data: f.log}}}
	o := obsView(t, w, id, WithObservedContent(whole))
	if o.RequestLog.Outcome != RequestLogUnchecked || o.RequestLog.Held != 0 {
		t.Fatalf("not held: %+v", o.RequestLog)
	}
	held := heldSet{sha(f.responses[0]): true, sha(f.responses[1]): true}
	o2 := obsView(t, w, id, WithObservedContent(whole), WithBlobIndex(held))
	if o2.RequestLog.Outcome != RequestLogOK || o2.RequestLog.Held != 2 {
		t.Fatalf("held: %+v", o2.RequestLog)
	}
}

type heldSet map[string]bool

func (h heldSet) Has(d string) bool { return h[d] }

// TestBatchRequestLogMalformed: a log that is not rc-request-log/1 is checked and wrong, named by line.
func TestBatchRequestLogMalformed(t *testing.T) {
	f := newBatch(2)
	f.log = append(f.log, []byte("{\"endpoint\":\"e\"}\n")...)
	w := newWorld(t)
	id := w.batchObserved("B", "O", f, batchReq(f, 3))
	o := obsView(t, w, id, WithObservedContent(f.reader()))
	if o.RequestLog.Outcome != RequestLogFail || !strings.Contains(o.RequestLog.Why, "line 3: missing parameters") {
		t.Fatalf("%+v", o.RequestLog)
	}
}
