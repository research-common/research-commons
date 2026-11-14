package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/reqlog"
)

// batchCapture is a tar capture of two responses and its rc-request-log/1 log. mutate replaces the second
// response's bytes inside the archive after the log was written.
func batchCapture(t *testing.T, mutate bool) (archive []byte, log []byte) {
	const ep = "https://api.example/v1/settlements"
	r1, r2 := `{"period":"2026-08"}`, `{"period":"2026-09"}`
	log = reqlog.Encode([]reqlog.Entry{
		{Endpoint: ep, Parameters: obj("period", "2026-08"), Status: 200, Time: "2026-10-16T05:00:00Z", ResponseDigest: dig(r1)},
		{Endpoint: ep, Parameters: obj("period", "2026-09"), Status: 200, Time: "2026-10-16T05:00:01Z", ResponseDigest: dig(r2)},
	})
	if mutate {
		r2 = `{"period":"2026-09","tampered":true}`
	}
	return tarOf(t, [2]string{"requests.jsonl", string(log)}, [2]string{"r1.json", r1}, [2]string{"r2.json", r2}), log
}

func (w *world) batch(name string, archive []byte, logDigest string, count int) string {
	d := w.blob(name, archive)
	return w.sign(name, "O", "observed", obj("content", obj("digest", d, "size", len(archive)), "class", "source",
		"referent", obj("requests", obj("digest", logDigest, "format", reqlog.Format, "count", count, "endpoint", "https://api.example/v1/settlements")),
		"capture", obj("at", "2026-10-16T05:01:00Z", "evidence", "self-asserted")))
}

// TestBatchRequestLogCommands: C-core-31, the batch variant through the commands. `show` and `explain` of a
// batch observation print the log's check (where it was found, entries, endpoints, responses held n/N); a
// response mutated after logging is named by entry and endpoint and `verify` exits 1; a log digest that matches
// nothing in the content reads `unpinned` (exit 3). Control: the intact capture verifies (exit 0).
func TestBatchRequestLogCommands(t *testing.T) {
	conformance.Partial(t, "C-core-31", "batch variant through the commands; the single-request and phenomenon halves are TestSingleRequestReferentCommands")
	w := newWorld(t)
	good, log := batchCapture(t, false)
	ok := w.batch("OK", good, dig(string(log)), 2)
	r := w.run("verify", ok, "--json")
	if r.code != 0 || !strings.Contains(r.stdout, `"responses_held":2`) || !strings.Contains(r.stdout, `"found_at"`) {
		t.Fatalf("intact: exit %d\n%s", r.code, r.stdout)
	}
	for _, cmd := range []string{"show", "explain"} {
		r = w.run(cmd, ok)
		if r.code != 0 || !strings.Contains(r.stdout, "request_log") && !strings.Contains(r.stdout, "request log") {
			t.Fatalf("%s: exit %d\n%s", cmd, r.code, r.stdout)
		}
		if !strings.Contains(r.stdout, "requests.jsonl") {
			t.Fatalf("%s does not say where the log is:\n%s", cmd, r.stdout)
		}
	}
	bad, _ := batchCapture(t, true)
	mut := w.batch("MUT", bad, dig(string(log)), 2)
	r = w.run("verify", mut, "--json")
	if r.code != 1 || !strings.Contains(r.stdout, "entry 2, endpoint https://api.example/v1/settlements") || !strings.Contains(r.stdout, `"responses_held":1`) {
		t.Fatalf("mutated: exit %d\n%s", r.code, r.stdout)
	}
	r = w.run("explain", mut)
	if !strings.Contains(r.stdout, "entry 2") {
		t.Fatalf("explain mutated:\n%s", r.stdout)
	}
	none := w.batch("NONE", good, dig("a log the capture does not carry"), 2)
	r = w.run("verify", none, "--json")
	if r.code != 3 || !strings.Contains(r.stdout, `"unpinned"`) || !strings.Contains(r.stdout, "referent.requests.digest") {
		t.Fatalf("unmatched: exit %d\n%s", r.code, r.stdout)
	}
}
